<!-- Language Toggle -->
<div align="right">
  <a href="#english">🇬🇧 English</a> &nbsp;|&nbsp;
  <a href="#persian">🇮🇷 فارسی</a>
</div>

<br/>

<div align="center">
```
 ███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ ███████╗    ██████╗  █████╗ ███╗   ██╗███████╗██╗
 ██╔════╝╚██╗██╔╝    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║
 ███████╗ ╚███╔╝     ██║  ██║██║  ██║██║   ██║███████╗    ██████╔╝███████║██╔██╗ ██║█████╗  ██║
 ╚════██║ ██╔██╗     ██║  ██║██║  ██║██║   ██║╚════██║    ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║
 ███████║██╔╝ ██╗    ██████╔╝██████╔╝╚██████╔╝███████║    ██║     ██║  ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

  <h3>SX DDoS Panel v2.0 — BY SX TEAM</h3>

  ![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?style=flat-square&logo=rust)
  ![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
  ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
  ![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)
  ![Version](https://img.shields.io/badge/Version-2.0.0-red?style=flat-square)

  > **High-performance, async, multi-protocol stress testing panel built in Rust.**  
  > Designed for authorized red team operations and network resilience testing.

</div>

---

<a name="english"></a>

## 🇬🇧 English

### Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Protocols & Methods](#protocols--methods)
- [Requirements](#requirements)
- [Build — Linux](#build--linux)
- [Build — Windows](#build--windows)
- [Usage](#usage)
- [Architecture](#architecture)
- [Legal](#legal)

---

### Overview

SX DDoS Panel is a fully async, multi-protocol network stress testing tool built in Rust using Tokio. It supports Layer 2 through Layer 7 attack vectors, WAF/CDN bypass techniques, Tor integration, SOCKS4/5 and HTTP proxy chaining, and a rich interactive terminal UI.

All traffic generation is handled by dedicated async workers per protocol, with real-time statistics (PPS, MB/s, sent/error counters) streamed to the terminal.

---

### Features

- **18 protocols** across Layer 2–7
- **Async Tokio runtime** — zero blocking, maximum throughput
- **Raw socket support** — SYN/UDP/ICMP/GRE floods (requires `CAP_NET_RAW`)
- **WAF bypass** — header mutation, desync, cache poisoning, TLS fingerprint spoofing
- **CDN bypass** — origin IP probing, cookie bypass, real-IP headers
- **Tor integration** — automatic identity rotation via control port
- **Proxy support** — SOCKS4, SOCKS5, HTTP proxies with health checking and failover
- **Static binary** — compiled with `musl`, zero runtime dependencies
- **Interactive TUI** — protocol selector, method picker, live stats

---

### Protocols & Methods

#### Layer 4 — TCP
| # | Method | Description |
|---|--------|-------------|
| 1 | `syn` | SYN Flood — half-open connection exhaustion |
| 2 | `ack` | ACK Flood — bulk ACK storm |
| 3 | `rst` | RST Flood — connection reset storm |
| 4 | `fin` | FIN Flood — close storm |
| 5 | `syn_ack` | SYN-ACK Reflection |
| 6 | `push` | PUSH Flood — data push storm |
| 7 | `null` | NULL Flood — zero-flag packets |
| 8 | `xmas` | Xmas Tree — all-flag combination |
| 9 | `connection` | Connection Flood — full handshake socket exhaustion |
| 10 | `frag` | Fragmentation — split-stream DoS |
| 11 | `zero_window` | Zero-Window — recv buffer manipulation |
| 12 | `window_scale` | Window Scale — WSopt manipulation |
| 13 | `ttl` | TTL Variation — hop-limit evasion |
| 14 | `src_port` | Source Port Rotation — rate-limit bypass |
| 15 | `half_open` | Half-Open RST |
| 16 | `urgent` | Urgent Pointer — URG flag storm |
| 17 | `mss` | MSS Manipulation — min segment storm |
| 18 | `sockstress` | Sockstress — resource hold |
| 19 | `persist` | Persist Timer — 300s hold exploit |
| 20 | `mixed_flags` | Mixed Flags — combined flag fuzzing |

#### Layer 4 — UDP
| Method | Description |
|--------|-------------|
| `flood` | Raw UDP flood |
| `amplification` | Amplification via open resolvers |
| `fragmentation` | Fragmented UDP DoS |
| `random_payload` | Random-payload UDP storm |

#### Layer 7 — HTTP
| Method | Description |
|--------|-------------|
| `get` | GET flood with bypass headers |
| `post` | POST flood with random body |
| `slow` | Slowloris — slow header send |
| `slow_body` | Slow POST body drain |
| `h2` | HTTP/2 rapid-reset flood |
| `cache_bust` | Cache-busting GET storm |
| `waf_desync` | TE-CL/CL-TE desync |
| `range` | Range-request amplification |
| `method_fuzz` | HTTP method fuzzing |
| `fake_crawl` | Googlebot spoofed crawler flood |

#### Layer 3 — ICMP / ICMPv6
| Method | Description |
|--------|-------------|
| `echo` | Ping flood |
| `smurf` | Smurf amplification |
| `fraggle` | Fraggle (UDP variant) |
| `pod` | Ping of Death |
| `icmpv6_flood` | IPv6 ICMP control plane flood |

#### Layer 7 — DNS
| Method | Description |
|--------|-------------|
| `query` | Random-query flood |
| `amplification` | DNS amplification via open resolvers |
| `nxdomain` | NXDOMAIN exhaustion |
| `any` | ANY-record flood |

#### Amplification Protocols
`NTP` · `SSDP` · `SNMP` · `LDAP/CLDAP` · `COAP` · `TFTP` · `Memcached` · `Chargen` · `WSD` · `OpenVPN` · `Plex` · `ARK`

#### Other Protocols
`SIP` · `RTP` · `QUIC` · `DHCP` · `GRE` · `IP Frag/Land/Teardrop` · `ARP Flood/Poison`

---

### Requirements

| Dependency | Minimum Version | Notes |
|------------|----------------|-------|
| Rust | 1.75+ | via rustup |
| `musl-tools` | any | Linux static builds |
| `tor` | any | Optional, for Tor routing |
| `CAP_NET_RAW` | — | Required for L3/L4 raw floods |

---

### Build — Linux

#### 1. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

#### 2. Add musl target (for static binary)
```bash
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools -y          # Debian/Ubuntu
# sudo dnf install musl-gcc -y          # Fedora/RHEL
```

#### 3. Build — static release binary
```bash
git clone https://github.com/youruser/sx-ddos-panel.git
cd sx-ddos-panel

RUSTFLAGS="-C target-feature=+crt-static" \
cargo build --release --target x86_64-unknown-linux-musl
```

Binary output: `target/x86_64-unknown-linux-musl/release/sx`

#### 4. Grant raw socket capability (for L3/L4 floods)
```bash
sudo setcap cap_net_raw+ep ./target/x86_64-unknown-linux-musl/release/sx
```

> Without `CAP_NET_RAW`, only connection-based methods work (HTTP, TCP connection, etc.). Raw floods (SYN, UDP, ICMP) require the capability or running as root.

#### 5. Optional — Install system-wide
```bash
sudo cp target/x86_64-unknown-linux-musl/release/sx /usr/local/bin/sx
sudo setcap cap_net_raw+ep /usr/local/bin/sx
```

#### Quick build script
```bash
chmod +x build.sh
./build.sh
```

---

### Build — Windows

> **Note:** Raw socket support on Windows requires running as Administrator. L7/connection methods work without elevation.

#### 1. Install Rust
Download and run: https://win.rustup.rs/x86_64

Or via winget:
```powershell
winget install Rustlang.Rustup
```

#### 2. Add Windows target
```powershell
rustup target add x86_64-pc-windows-msvc
```

#### 3. Build
```powershell
git clone https://github.com/youruser/sx-ddos-panel.git
cd sx-ddos-panel

cargo build --release --target x86_64-pc-windows-msvc
```

Binary output: `target\x86_64-pc-windows-msvc\release\sx.exe`

#### 4. Run as Administrator (for raw sockets)
```powershell
# Right-click PowerShell → "Run as Administrator"
.\target\x86_64-pc-windows-msvc\release\sx.exe
```

#### Cross-compile from Linux → Windows
```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64 -y

CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
cargo build --release --target x86_64-pc-windows-gnu
```

---

### Usage

#### Launch interactive panel
```bash
./sx
```

#### Interactive flow
```
1. Select protocol (1–18)
2. Select method(s):
   - Single:  1
   - Multi:   1,3,7
   - Range:   1-5
   - All:     all
3. Enter target IP or domain
4. Set port, duration, worker count
5. (Optional) load proxy list file
6. (Optional) enable Tor routing
7. Confirm and launch
```

#### Proxy file format
```
SOCKS5://user:pass@1.2.3.4:1080
SOCKS4://1.2.3.4:1080
HTTP://1.2.3.4:8080
```

#### Example sessions

**HTTP GET flood, 500 workers, 60 seconds:**
```
Protocol: 3 (HTTP)
Method:   get
Target:   target.example.com
Port:     443
Duration: 60
Workers:  500
```

**TCP SYN flood with Tor (requires tor in PATH):**
```
Protocol: 1 (TCP)
Method:   syn
Target:   10.0.0.1
Port:     80
Duration: 120
Workers:  200
Tor:      Y
```

**DNS amplification:**
```
Protocol: 6 (DNS)
Method:   amplification
Target:   10.0.0.1
Port:     53
Duration: 60
Workers:  100
```

#### Live stats output
```
[STAT]  T+  12s | Sent:      48291 | Errors:      14 | PPS:    4024 | Avg: 3.21 MB/s
```

| Field | Description |
|-------|-------------|
| `Sent` | Total packets/requests sent |
| `Errors` | Failed sends |
| `PPS` | Packets per second (current) |
| `Avg MB/s` | Average throughput |

---

### Architecture

```
sx-ddos-panel/
├── src/
│   ├── main.rs          — Entry point, Tokio runtime init
│   ├── ui.rs            — Interactive TUI, protocol/method selector
│   ├── attack.rs        — WorkerCtx, stat counters, worker orchestration
│   ├── config.rs        — AttackConfig, ProxyType, ProxyStrategy structs
│   ├── logger.rs        — Colored terminal logger
│   ├── proxy.rs         — Proxy pool, SOCKS4/5/HTTP tunnel
│   ├── tor.rs           — Tor controller, identity rotation
│   ├── bypass.rs        — WAF/CDN/Rate-limit bypass, TLS fingerprint
│   └── protocols/
│       ├── mod.rs       — Protocol dispatch
│       ├── http.rs      — HTTP L7 floods
│       ├── tcp.rs       — TCP L4 raw floods
│       ├── udp.rs       — UDP L4 floods
│       └── other.rs     — ICMP, DNS, NTP, GRE, SIP, AMP, etc.
├── Cargo.toml
└── build.sh
```

---

### Legal

> **This tool is intended exclusively for:**
> - Authorized penetration testing
> - Testing infrastructure you own
> - Academic and educational research in controlled environments

> The authors(SX TEAM , XSERGOD) , accept no liability for misuse.

---
### Support

**If you encounter any bugs or issues in the code, or experience any difficulties using it, you can join the Discord server below and open a support ticket:**

- [SX TEAM Official Discord Server](https://discord.gg/JAzFv72trY)
---

<a name="persian"></a>

## 🇮🇷 فارسی

<div dir="rtl">

### فهرست مطالب
- [معرفی](#معرفی)
- [امکانات](#امکانات)
- [پروتوکل‌ها و متدها](#پروتوکل‌ها-و-متدها)
- [پیش‌نیازها](#پیش‌نیازها)
- [بیلد — لینوکس](#بیلد--لینوکس)
- [بیلد — ویندوز](#بیلد--ویندوز)
- [نحوه استفاده](#نحوه-استفاده)
- [قانونی](#قانونی)

---

### معرفی

SX DDoS Panel یک ابزار تست استرس شبکه کاملاً async و چندپروتوکلی است که با Rust و Tokio نوشته شده. از لایه ۲ تا لایه ۷ را پوشش می‌دهد و شامل تکنیک‌های bypass WAF/CDN، پشتیبانی از Tor، زنجیره پروکسی SOCKS4/5 و HTTP، و یک TUI تعاملی غنی است.

---

### امکانات

- **۱۸ پروتوکل** از لایه ۲ تا ۷
- **رانتایم Tokio async** — بدون بلاکینگ، حداکثر throughput
- **پشتیبانی raw socket** — SYN/UDP/ICMP/GRE flood (نیاز به `CAP_NET_RAW`)
- **bypass WAF** — mutation هدر، desync، cache poisoning، جعل TLS fingerprint
- **bypass CDN** — پروب IP مبدا، bypass کوکی، هدرهای real-IP
- **یکپارچه‌سازی Tor** — چرخش خودکار هویت از طریق control port
- **پشتیبانی پروکسی** — SOCKS4، SOCKS5، HTTP با health check و failover
- **باینری استاتیک** — کامپایل با `musl`، بدون وابستگی runtime
- **TUI تعاملی** — انتخاب پروتوکل، انتخاب متد، آمار لحظه‌ای

---

### پروتوکل‌ها و متدها

#### لایه ۴ — TCP
| # | متد | توضیح |
|---|-----|-------|
| 1 | `syn` | SYN Flood — اشباع اتصال نیمه‌باز |
| 2 | `ack` | ACK Flood — طوفان ACK انبوه |
| 3 | `rst` | RST Flood — طوفان ریست اتصال |
| 4 | `fin` | FIN Flood — طوفان بستن |
| 5 | `syn_ack` | انعکاس SYN-ACK |
| 6 | `push` | PUSH Flood — طوفان push داده |
| 7 | `null` | NULL Flood — پکت‌های zero-flag |
| 8 | `xmas` | Xmas Tree — ترکیب همه flag‌ها |
| 9 | `connection` | Connection Flood — اشباع socket با handshake کامل |
| 10 | `frag` | Fragmentation — DoS جریان تقسیم‌شده |
| 11 | `zero_window` | Zero-Window — دستکاری recv buffer |
| 12 | `window_scale` | Window Scale — دستکاری WSopt |
| 13 | `ttl` | TTL Variation — فرار از hop-limit |
| 14 | `src_port` | چرخش Source Port — bypass rate-limit |
| 15 | `half_open` | Half-Open RST |
| 16 | `urgent` | Urgent Pointer — طوفان URG |
| 17 | `mss` | دستکاری MSS — طوفان segment کوچک |
| 18 | `sockstress` | Sockstress — نگه‌داشتن منابع |
| 19 | `persist` | Persist Timer — اکسپلویت نگه‌داشتن ۳۰۰ ثانیه |
| 20 | `mixed_flags` | Mixed Flags — fuzzing flag ترکیبی |

#### لایه ۴ — UDP
| متد | توضیح |
|-----|-------|
| `flood` | UDP flood خام |
| `amplification` | تقویت از طریق resolver باز |
| `fragmentation` | UDP DoS تکه‌تکه |
| `random_payload` | طوفان UDP با payload تصادفی |

#### لایه ۷ — HTTP
| متد | توضیح |
|-----|-------|
| `get` | GET flood با هدرهای bypass |
| `post` | POST flood با body تصادفی |
| `slow` | Slowloris — ارسال آهسته هدر |
| `slow_body` | تخلیه body آهسته POST |
| `h2` | HTTP/2 rapid-reset flood |
| `cache_bust` | طوفان GET با cache-busting |
| `waf_desync` | desync TE-CL/CL-TE |
| `range` | تقویت درخواست Range |
| `method_fuzz` | fuzzing متد HTTP |
| `fake_crawl` | flood جعلی Googlebot |

#### لایه ۳ — ICMP / ICMPv6
| متد | توضیح |
|-----|-------|
| `echo` | Ping flood |
| `smurf` | تقویت Smurf |
| `fraggle` | Fraggle (نوع UDP) |
| `pod` | Ping of Death |
| `icmpv6_flood` | flood صفحه کنترل ICMP IPv6 |

#### لایه ۷ — DNS
| متد | توضیح |
|-----|-------|
| `query` | flood کوئری تصادفی |
| `amplification` | تقویت DNS از طریق resolver باز |
| `nxdomain` | اشباع NXDOMAIN |
| `any` | flood رکورد ANY |

#### پروتوکل‌های تقویت
`NTP` · `SSDP` · `SNMP` · `LDAP/CLDAP` · `COAP` · `TFTP` · `Memcached` · `Chargen` · `WSD` · `OpenVPN` · `Plex` · `ARK`

#### پروتوکل‌های دیگر
`SIP` · `RTP` · `QUIC` · `DHCP` · `GRE` · `IP Frag/Land/Teardrop` · `ARP Flood/Poison`

---

### پیش‌نیازها

| وابستگی | نسخه حداقل | توضیح |
|---------|-----------|-------|
| Rust | 1.75+ | از طریق rustup |
| `musl-tools` | هر نسخه | برای بیلد استاتیک لینوکس |
| `tor` | هر نسخه | اختیاری، برای مسیریابی Tor |
| `CAP_NET_RAW` | — | برای flood خام L3/L4 لازم است |

---

### بیلد — لینوکس

#### ۱. نصب Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

#### ۲. اضافه کردن target musl (برای باینری استاتیک)
```bash
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools -y          # Debian/Ubuntu
# sudo dnf install musl-gcc -y          # Fedora/RHEL
```

#### ۳. بیلد — باینری release استاتیک
```bash
git clone https://github.com/youruser/sx-ddos-panel.git
cd sx-ddos-panel

RUSTFLAGS="-C target-feature=+crt-static" \
cargo build --release --target x86_64-unknown-linux-musl
```

خروجی باینری: `target/x86_64-unknown-linux-musl/release/sx`

#### ۴. دادن capability raw socket (برای flood L3/L4)
```bash
sudo setcap cap_net_raw+ep ./target/x86_64-unknown-linux-musl/release/sx
```

> بدون `CAP_NET_RAW` فقط متدهای connection-based کار می‌کنند (HTTP، TCP connection و...). flood خام (SYN، UDP، ICMP) نیاز به capability یا اجرا به عنوان root دارد.

#### ۵. اختیاری — نصب system-wide
```bash
sudo cp target/x86_64-unknown-linux-musl/release/sx /usr/local/bin/sx
sudo setcap cap_net_raw+ep /usr/local/bin/sx
```

#### اسکریپت بیلد سریع
```bash
chmod +x build.sh
./build.sh
```

---

### بیلد — ویندوز

> **توجه:** پشتیبانی raw socket در ویندوز نیاز به اجرا به عنوان Administrator دارد. متدهای L7/connection بدون elevation کار می‌کنند.

#### ۱. نصب Rust
دانلود و اجرا: https://win.rustup.rs/x86_64

یا از طریق winget:
```powershell
winget install Rustlang.Rustup
```

#### ۲. اضافه کردن target ویندوز
```powershell
rustup target add x86_64-pc-windows-msvc
```

#### ۳. بیلد
```powershell
git clone https://github.com/youruser/sx-ddos-panel.git
cd sx-ddos-panel

cargo build --release --target x86_64-pc-windows-msvc
```

خروجی باینری: `target\x86_64-pc-windows-msvc\release\sx.exe`

#### ۴. اجرا به عنوان Administrator (برای raw socket)
```powershell
# کلیک راست روی PowerShell ← "Run as Administrator"
.\target\x86_64-pc-windows-msvc\release\sx.exe
```

#### Cross-compile از لینوکس به ویندوز
```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64 -y

CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
cargo build --release --target x86_64-pc-windows-gnu
```

---

### نحوه استفاده

#### راه‌اندازی پنل تعاملی
```bash
./sx
```

#### جریان تعاملی
```
۱. انتخاب پروتوکل (۱–۱۸)
۲. انتخاب متد(ها):
   - تکی:    1
   - چندتا:  1,3,7
   - محدوده: 1-5
   - همه:    all
۳. وارد کردن IP یا دامنه هدف
۴. تنظیم پورت، مدت زمان، تعداد worker
۵. (اختیاری) بارگذاری فایل پروکسی
۶. (اختیاری) فعال‌سازی مسیریابی Tor
۷. تأیید و شروع
```

#### فرمت فایل پروکسی
```
SOCKS5://user:pass@1.2.3.4:1080
SOCKS4://1.2.3.4:1080
HTTP://1.2.3.4:8080
```

#### نمونه session‌ها

**HTTP GET flood، ۵۰۰ worker، ۶۰ ثانیه:**
```
Protocol: 3 (HTTP)
Method:   get
Target:   target.example.com
Port:     443
Duration: 60
Workers:  500
```

**TCP SYN flood با Tor (نیاز به tor در PATH):**
```
Protocol: 1 (TCP)
Method:   syn
Target:   10.0.0.1
Port:     80
Duration: 120
Workers:  200
Tor:      Y
```

#### خروجی آمار لحظه‌ای
```
[STAT]  T+  12s | Sent:      48291 | Errors:      14 | PPS:    4024 | Avg: 3.21 MB/s
```

| فیلد | توضیح |
|------|-------|
| `Sent` | کل پکت/درخواست ارسال‌شده |
| `Errors` | ارسال‌های ناموفق |
| `PPS` | پکت در ثانیه (لحظه‌ای) |
| `Avg MB/s` | میانگین throughput |

---

### قانونی

> **این ابزار فقط برای موارد زیر در نظر گرفته شده است:**
> - تست نفوذ مجاز
> - تست زیرساختی که مالک آن هستید
> - تحقیق آکادمیک در محیط‌های کنترل‌شده
>
>
> نویسندگان(SX TEAM, XSEGOD) , هیچ مسئولیتی در قبال سوء استفاده نمی‌پذیرند.

</div>

---

### پشتیبانی 

**اگر باگ یا مشکلی در کد پیدا کردید یا مشکلی در استفاده از کد داشتید میتونید وارد سرور دیسکورد زیر شوید و یک تیکت باز کنید :**

- [SX TEAM Official Discord Channel](https://discord.gg/JAzFv72trY)

</div>

---

<div align="center">
  <sub>+-= Developed By SX TEAM & XSERGOD =-+</sub>
</div>
