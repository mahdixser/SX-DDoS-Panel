use std::process::{Command, Child, Stdio};
use std::time::Duration;
use std::io::{Write, Read};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use parking_lot::Mutex;
use tokio::time::sleep;
use crate::logger;
use crate::config::TorSettings;

pub struct TorController {
    process:       Option<Child>,
    pub settings:  TorSettings,
    rotation_count: Arc<AtomicU64>,
    running:       Arc<AtomicBool>,
    ctrl_stream:   Arc<Mutex<Option<TcpStream>>>,
}

impl TorController {
    pub fn new(settings: TorSettings) -> Self {
        Self {
            process: None,
            settings,
            rotation_count: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            ctrl_stream: Arc::new(Mutex::new(None)),
        }
    }

    fn write_torrc(&self) -> Result<String, String> {
        let path = format!("{}/torrc", self.settings.data_dir);
        std::fs::create_dir_all(&self.settings.data_dir)
            .map_err(|e| format!("mkdir: {}", e))?;

        let mut cfg = format!(
            "SocksPort {}\n\
             ControlPort {}\n\
             DataDirectory {}\n\
             MaxCircuitDirtiness 10\n\
             NewCircuitPeriod 15\n\
             NumEntryGuards 1\n\
             Log notice stderr\n\
             SafeSocks 1\n\
             TestSocks 0\n\
             WarnUnsafeSocks 1\n",
            self.settings.socks_port,
            self.settings.control_port,
            self.settings.data_dir,
        );

        
        if self.settings.control_password.is_empty() {
            cfg.push_str(&format!("CookieAuthentication 1\nCookieAuthFile {}/control_auth_cookie\n",
                self.settings.data_dir));
        } else {
            cfg.push_str("CookieAuthentication 0\n");
            cfg.push_str(&format!("HashedControlPassword {}\n", self.settings.control_password));
        }

        if !self.settings.exit_countries.is_empty() {
            let nodes = self.settings.exit_countries.iter()
                .map(|c| format!("{{{}}}", c))
                .collect::<Vec<_>>()
                .join(",");
            cfg.push_str(&format!("ExitNodes {}\nStrictNodes 1\n", nodes));
        }

        std::fs::write(&path, &cfg).map_err(|e| format!("write torrc: {}", e))?;
        Ok(path)
    }

    pub async fn start(&mut self) -> bool {
        logger::log_info(&format!(
            "Starting Tor — SOCKS:{} Control:{}",
            self.settings.socks_port, self.settings.control_port
        ));

        let torrc = match self.write_torrc() {
            Ok(p) => p,
            Err(e) => { logger::log_error(&e); return false; }
        };

        match Command::new("tor")
            .args(["-f", &torrc])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => {
                self.process = Some(child);
                self.running.store(true, Ordering::Relaxed);
            }
            Err(e) => {
                logger::log_error(&format!("Cannot start tor: {} — install tor first", e));
                return false;
            }
        }

        
        for i in 0..30 {
            sleep(Duration::from_secs(1)).await;
            let addr = format!("127.0.0.1:{}", self.settings.socks_port);
            if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(1)).is_ok() {
                logger::log_success(&format!("Tor ready in {}s", i + 1));
                self.connect_control();
                return true;
            }
        }

        logger::log_error("Tor failed to start in 30s");
        self.stop();
        false
    }

    fn connect_control(&self) {
        let addr = format!("127.0.0.1:{}", self.settings.control_port);
        let Ok(sa) = addr.parse() else { return };

        let Ok(mut s) = TcpStream::connect_timeout(&sa, Duration::from_secs(3)) else {
            logger::log_warn("Cannot connect to Tor control port");
            return;
        };

        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        s.set_write_timeout(Some(Duration::from_secs(5))).ok();

        
        let auth_success = if self.settings.control_password.is_empty() {
            self.auth_cookie(&mut s)
        } else {
            self.auth_password(&mut s)
        };

        if auth_success {
            logger::log_success("Tor control port authenticated");
            *self.ctrl_stream.lock() = Some(s);
        } else {
            logger::log_warn("Tor control auth failed — identity rotation disabled");
        }
    }

    fn auth_cookie(&self, s: &mut TcpStream) -> bool {
        let cookie_path = format!("{}/control_auth_cookie", self.settings.data_dir);
        let cookie = match std::fs::read(&cookie_path) {
            Ok(b) => b,
            Err(_) => {
                
                return self.send_recv(s, "AUTHENTICATE \"\"\r\n").contains("250");
            }
        };
        let hex: String = cookie.iter().map(|b| format!("{:02x}", b)).collect();
        self.send_recv(s, &format!("AUTHENTICATE {}\r\n", hex)).contains("250")
    }

    fn auth_password(&self, s: &mut TcpStream) -> bool {
        let cmd = format!("AUTHENTICATE \"{}\"\r\n", self.settings.control_password);
        self.send_recv(s, &cmd).contains("250")
    }

    fn send_recv(&self, s: &mut TcpStream, cmd: &str) -> String {
        if s.write_all(cmd.as_bytes()).is_err() { return String::new(); }
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    pub fn rotate_identity(&self) -> bool {
        let mut guard = self.ctrl_stream.lock();

        if let Some(ref mut s) = *guard {
            let resp = self.send_recv(s, "SIGNAL NEWNYM\r\n");
            if resp.contains("250") {
                let n = self.rotation_count.fetch_add(1, Ordering::Relaxed) + 1;
                logger::log_info(&format!("Tor identity rotated [#{}]", n));
                return true;
            }
            
            logger::log_warn("Tor control stream broken");
            *guard = None;
        }

        drop(guard);
        self.connect_control();
        false
    }

    
    pub fn socks5_addr(&self) -> String {
        format!("127.0.0.1:{}", self.settings.socks_port)
    }

    pub fn rotation_count(&self) -> u64 {
        self.rotation_count.load(Ordering::Relaxed)
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stop(&mut self) {
        if let Some(ref mut child) = self.process {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.process = None;
        self.running.store(false, Ordering::Relaxed);
        *self.ctrl_stream.lock() = None;
        logger::log_info("Tor stopped");
    }

    pub async fn start_rotation_loop(controller: Arc<tokio::sync::Mutex<Self>>, running: Arc<AtomicBool>) {
        let interval = { controller.lock().await.settings.rotate_every_secs };
        logger::log_info(&format!("Tor rotation loop started — every {}s", interval));
        while running.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(interval)).await;
            if !running.load(Ordering::Relaxed) { break; }
            controller.lock().await.rotate_identity();
        }
    }
}

impl Drop for TorController {
    fn drop(&mut self) { self.stop(); }
}
