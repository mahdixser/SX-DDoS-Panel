use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyType {
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_connections:   usize,
    pub max_memory_mb:     usize,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms:   u64,
    pub write_timeout_ms:  u64,
    pub max_retries:       u8,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_connections:    10_000,
            max_memory_mb:      512,
            connect_timeout_ms: 3_000,
            read_timeout_ms:    5_000,
            write_timeout_ms:   5_000,
            max_retries:        2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorSettings {
    pub enabled:          bool,
    pub socks_port:       u16,
    pub control_port:     u16,
    pub control_password: String,
    pub rotate_every_secs: u64,
    pub exit_countries:   Vec<String>,
    pub data_dir:         String,
}

impl Default for TorSettings {
    fn default() -> Self {
        Self {
            enabled:           false,
            socks_port:        9050,
            control_port:      9051,
            control_password:  String::new(),
            rotate_every_secs: 30,
            exit_countries:    vec![],
            data_dir:          "/tmp/sx_tor".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub enabled:    bool,
    pub proxy_type: ProxyType,
    pub proxies:    Vec<String>,
    pub strategy:   ProxyStrategy,
    pub health_check: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyStrategy {
    Random,
    RoundRobin,
    Fastest,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            enabled:      false,
            proxy_type:   ProxyType::Socks5,
            proxies:      vec![],
            strategy:     ProxyStrategy::Random,
            health_check: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub target:          String,
    pub port:            u16,
    pub duration_secs:   u64,
    pub workers:         usize,
    pub methods:         Vec<String>,
    pub protocol:        String,
    pub use_ssl:         bool,
    pub proxy:           ProxySettings,
    pub tor:             TorSettings,
    pub limits:          ResourceLimits,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            target:        String::new(),
            port:          80,
            duration_secs: 60,
            workers:       100,
            methods:       vec![],
            protocol:      String::new(),
            use_ssl:       false,
            proxy:         ProxySettings::default(),
            tor:           TorSettings::default(),
            limits:        ResourceLimits::default(),
        }
    }
}

impl AttackConfig {
    pub fn summary(&self) -> String {
        format!(
            "Target={} Port={} Proto={} Methods=[{}] Duration={}s Workers={} Proxies={} Tor={}",
            self.target, self.port, self.protocol.to_uppercase(),
            self.methods.join("+"), self.duration_secs, self.workers,
            self.proxy.proxies.len(), self.tor.enabled,
        )
    }

    
    pub fn effective_workers(&self) -> usize {
        
        let mem_cap = (self.limits.max_memory_mb * 1024 * 1024) / (8 * 1024);
        let conn_cap = self.limits.max_connections / self.methods.len().max(1);
        self.workers.min(mem_cap).min(conn_cap).max(1)
    }
}
