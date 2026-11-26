use std::fs;
use std::net::{TcpStream, SocketAddr};
use std::io::{Write, Read};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use rand::thread_rng;
use crate::logger;
use crate::config::{ProxyType, ProxySettings, ProxyStrategy};

#[derive(Debug, Clone)]
pub struct Proxy {
    pub host:       String,
    pub port:       u16,
    pub ptype:      ProxyType,
    pub username:   Option<String>,
    pub password:   Option<String>,
    pub latency_ms: u64,
    pub alive:      bool,
    pub fail_count: u32,
}

impl Proxy {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() || s.starts_with('#') { return None; }

        let (ptype, rest) = if let Some(r) = s.strip_prefix("socks5://") {
            (ProxyType::Socks5, r)
        } else if let Some(r) = s.strip_prefix("socks4://") {
            (ProxyType::Socks4, r)
        } else if let Some(r) = s.strip_prefix("https://") {
            (ProxyType::Https, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (ProxyType::Http, r)
        } else {
            (ProxyType::Socks5, s)
        };

        let (auth, hostpart) = if rest.contains('@') {
            let idx = rest.rfind('@').unwrap();
            (Some(&rest[..idx]), &rest[idx + 1..])
        } else {
            (None, rest)
        };

        let (username, password) = match auth {
            Some(a) if a.contains(':') => {
                let i = a.find(':').unwrap();
                (Some(a[..i].to_string()), Some(a[i+1..].to_string()))
            }
            Some(a) => (Some(a.to_string()), None),
            None    => (None, None),
        };

        let parts: Vec<&str> = hostpart.splitn(2, ':').collect();
        if parts.len() != 2 { return None; }
        let port = parts[1].parse::<u16>().ok()?;

        Some(Self {
            host: parts[0].to_string(), port, ptype,
            username, password,
            latency_ms: 0, alive: true, fail_count: 0,
        })
    }

    pub fn addr(&self) -> String { format!("{}:{}", self.host, self.port) }

    
    pub fn tunnel(&self, target_host: &str, target_port: u16, timeout: Duration) -> Result<TcpStream, String> {
        match self.ptype {
            ProxyType::Socks5 | ProxyType::Https => self.socks5_tunnel(target_host, target_port, timeout),
            ProxyType::Socks4 => self.socks4_tunnel(target_host, target_port, timeout),
            ProxyType::Http   => self.http_connect_tunnel(target_host, target_port, timeout),
        }
    }

    fn socks5_tunnel(&self, host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
        let sa: SocketAddr = self.addr().parse().map_err(|e| format!("parse: {}", e))?;
        let mut s = TcpStream::connect_timeout(&sa, timeout)
            .map_err(|e| format!("connect: {}", e))?;
        s.set_read_timeout(Some(timeout)).ok();
        s.set_write_timeout(Some(timeout)).ok();

        let auth_method: u8 = if self.username.is_some() { 0x02 } else { 0x00 };
        s.write_all(&[0x05, 0x01, auth_method]).map_err(|e| e.to_string())?;

        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).map_err(|e| e.to_string())?;
        if resp[0] != 0x05 { return Err("not SOCKS5".into()); }
        if resp[1] == 0xFF  { return Err("no acceptable auth".into()); }

        if resp[1] == 0x02 {
            let user = self.username.as_deref().unwrap_or("").as_bytes();
            let pass = self.password.as_deref().unwrap_or("").as_bytes();
            let mut auth = vec![0x01u8, user.len() as u8];
            auth.extend_from_slice(user);
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass);
            s.write_all(&auth).map_err(|e| e.to_string())?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).map_err(|e| e.to_string())?;
            if ar[1] != 0x00 { return Err("auth rejected".into()); }
        }

        let hb = host.as_bytes();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
        req.extend_from_slice(hb);
        req.push((port >> 8) as u8);
        req.push(port as u8);
        s.write_all(&req).map_err(|e| e.to_string())?;

        let mut cr = [0u8; 10];
        s.read_exact(&mut cr).map_err(|e| e.to_string())?;
        if cr[1] != 0x00 { return Err(format!("SOCKS5 error: 0x{:02x}", cr[1])); }

        Ok(s)
    }

    fn socks4_tunnel(&self, host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
        use std::net::ToSocketAddrs;
        let sa: SocketAddr = self.addr().parse().map_err(|e| format!("parse: {}", e))?;
        let mut s = TcpStream::connect_timeout(&sa, timeout)
            .map_err(|e| format!("connect: {}", e))?;
        s.set_read_timeout(Some(timeout)).ok();

        let ip = format!("{}:{}", host, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.find(|x| x.is_ipv4()))
            .ok_or("DNS resolve failed")?;

        let octets = match ip.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => return Err("IPv6 not supported by SOCKS4".into()),
        };

        let mut req = vec![0x04, 0x01, (port >> 8) as u8, port as u8];
        req.extend_from_slice(&octets);
        req.push(0x00);
        s.write_all(&req).map_err(|e| e.to_string())?;

        let mut resp = [0u8; 8];
        s.read_exact(&mut resp).map_err(|e| e.to_string())?;
        if resp[1] != 0x5A { return Err(format!("SOCKS4 rejected: {}", resp[1])); }

        Ok(s)
    }

    fn http_connect_tunnel(&self, host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
        let sa: SocketAddr = self.addr().parse().map_err(|e| format!("parse: {}", e))?;
        let mut s = TcpStream::connect_timeout(&sa, timeout)
            .map_err(|e| format!("connect: {}", e))?;
        s.set_read_timeout(Some(timeout)).ok();

        let mut req = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n", host, port, host, port);
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            let encoded = base64_encode(format!("{}:{}", u, p).as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        req.push_str("Proxy-Connection: keep-alive\r\n\r\n");

        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;

        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf).map_err(|e| e.to_string())?;
        let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if !resp.contains("200") {
            return Err(format!("HTTP CONNECT rejected: {}", resp.lines().next().unwrap_or("")));
        }
        Ok(s)
    }

    pub fn check(&mut self, timeout: Duration) -> bool {
        let start = Instant::now();
        let addr = self.addr();
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            if TcpStream::connect_timeout(&sa, timeout).is_ok() {
                self.latency_ms = start.elapsed().as_millis() as u64;
                self.alive = true;
                self.fail_count = 0;
                return true;
            }
        }
        self.alive = false;
        self.fail_count += 1;
        false
    }

    pub fn mark_failed(&mut self) {
        self.fail_count += 1;
        if self.fail_count >= 5 { self.alive = false; }
    }
}

fn base64_encode(data: &[u8]) -> String {
    const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut r = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i+1 < data.len() { data[i+1] as usize } else { 0 };
        let b2 = if i+2 < data.len() { data[i+2] as usize } else { 0 };
        r.push(C[b0>>2] as char);
        r.push(C[((b0&3)<<4)|(b1>>4)] as char);
        r.push(if i+1<data.len() { C[((b1&15)<<2)|(b2>>6)] as char } else { '=' });
        r.push(if i+2<data.len() { C[b2&63] as char } else { '=' });
        i += 3;
    }
    r
}

pub struct ProxyPool {
    proxies:  Arc<RwLock<Vec<Proxy>>>,
    index:    Arc<AtomicUsize>,
    strategy: ProxyStrategy,
}

impl ProxyPool {
    pub fn from_settings(settings: &ProxySettings) -> Self {
        let proxies: Vec<Proxy> = settings.proxies
            .iter()
            .filter_map(|s| Proxy::parse(s))
            .collect();

        let total = proxies.len();
        logger::log_info(&format!("Proxy pool: {} loaded", total));

        Self {
            proxies:  Arc::new(RwLock::new(proxies)),
            index:    Arc::new(AtomicUsize::new(0)),
            strategy: settings.strategy.clone(),
        }
    }

    pub fn get(&self) -> Option<Proxy> {
        match self.strategy {
            ProxyStrategy::Random     => self.random(),
            ProxyStrategy::RoundRobin => self.round_robin(),
            ProxyStrategy::Fastest    => self.fastest(),
        }
    }

    fn random(&self) -> Option<Proxy> {
        let pool = self.proxies.read();
        let alive: Vec<&Proxy> = pool.iter().filter(|p| p.alive).collect();
        alive.choose(&mut thread_rng()).map(|p| (*p).clone())
    }

    fn round_robin(&self) -> Option<Proxy> {
        let pool = self.proxies.read();
        let alive: Vec<&Proxy> = pool.iter().filter(|p| p.alive).collect();
        if alive.is_empty() { return None; }
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % alive.len();
        Some(alive[idx].clone())
    }

    fn fastest(&self) -> Option<Proxy> {
        let pool = self.proxies.read();
        pool.iter()
            .filter(|p| p.alive && p.latency_ms > 0)
            .min_by_key(|p| p.latency_ms)
            .cloned()
    }

    pub fn mark_failed(&self, proxy: &Proxy) {
        let mut pool = self.proxies.write();
        if let Some(p) = pool.iter_mut().find(|p| p.host == proxy.host && p.port == proxy.port) {
            p.mark_failed();
        }
    }

    pub fn alive_count(&self) -> usize {
        self.proxies.read().iter().filter(|p| p.alive).count()
    }

    pub fn total(&self) -> usize {
        self.proxies.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    pub async fn health_check(&self, timeout_ms: u64, threads: usize) {
        logger::log_info(&format!("Health check: {} proxies...", self.total()));
        let pool_clone: Vec<Proxy> = self.proxies.read().clone();
        let total = pool_clone.len();
        let shared = Arc::new(RwLock::new(pool_clone));
        let alive_count = Arc::new(AtomicUsize::new(0));
        let chunk = (total / threads.max(1)).max(1);
        let mut handles = vec![];

        for start in (0..total).step_by(chunk) {
            let shared = shared.clone();
            let alive_count = alive_count.clone();
            let end = (start + chunk).min(total);
            let timeout = Duration::from_millis(timeout_ms);

            handles.push(tokio::spawn(async move {
                for i in start..end {
                    let mut p = { shared.read()[i].clone() };
                    if p.check(timeout) {
                        alive_count.fetch_add(1, Ordering::Relaxed);
                    }
                    shared.write()[i] = p;
                }
            }));
        }

        for h in handles { let _ = h.await; }

        let final_pool = shared.read().clone();
        *self.proxies.write() = final_pool;

        logger::log_success(&format!(
            "Health check done: {}/{} alive",
            alive_count.load(Ordering::Relaxed), total
        ));
    }

    pub fn print_stats(&self) {
        let pool = self.proxies.read();
        let total = pool.len();
        let alive = pool.iter().filter(|p| p.alive).count();
        let avg_lat = {
            let lats: Vec<u64> = pool.iter().filter(|p| p.latency_ms > 0).map(|p| p.latency_ms).collect();
            if lats.is_empty() { 0 } else { lats.iter().sum::<u64>() / lats.len() as u64 }
        };
        logger::log_info(&format!(
            "Proxy stats — Total: {} | Alive: {} | Avg latency: {}ms",
            total, alive, avg_lat
        ));
    }
}
