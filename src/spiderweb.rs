use crate::ja4;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize)]
pub struct ChronoLine {
    pub flow_id: u64,
    pub ts: u64,
    pub proto: String,
    pub flags: String,
    pub src: String,
    pub dst: String,
    pub len: usize,
    pub entropy: f32,
    pub preview: Vec<u8>,
    pub ascii: String,
}

#[derive(Clone)]
pub struct CapturedFlow {
    pub id: u64,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub pkts: u32,
    pub bytes: usize,
    pub last_ts: u64,
    pub sni: Option<String>,
    pub ja4: Option<String>,
    pub dns_q: Option<String>,
    pub payload: Vec<u8>,
}

#[derive(Serialize)]
pub struct FlowSummary {
    pub id: u64,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub pkts: u32,
    pub bytes: usize,
    pub entropy: f32,
    pub sni: Option<String>,
    pub ja4: Option<String>,
    pub dns_q: Option<String>,
    pub snippet: String,
}

#[derive(Serialize)]
pub struct Reconstruction {
    pub id: u64,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub bytes: usize,
    pub entropy: f32,
    pub artifact_type: String,
    pub metadata: serde_json::Value,
    pub text_view: String,
    pub data_uri: Option<String>,
    pub hex_dump: String,
}

#[derive(Serialize)]
pub struct TalkerRow {
    pub ip: String,
    pub pkts: u64,
    pub bytes: u64,
    pub share_pct: f32,
}

#[derive(Serialize)]
pub struct ProtoRow {
    pub proto: String,
    pub pkts: u64,
    pub bytes: u64,
    pub share_pct: f32,
}

#[derive(Serialize)]
pub struct IptrafSnapshot {
    pub pps: f32,
    pub kbps: f32,
    pub total_pkts: u64,
    pub total_bytes: u64,
    pub active_flows: usize,
    pub protos: Vec<ProtoRow>,
    pub size_buckets: [u64; 5],
    pub top_talkers: Vec<TalkerRow>,
}

pub struct Spiderweb {
    next_id: u64,
    flows: HashMap<String, CapturedFlow>,
    order: VecDeque<String>,
    pub chrono: VecDeque<ChronoLine>,
    total_pkts: u64,
    total_bytes: u64,
    proto_stats: HashMap<String, (u64, u64)>,
    talker_stats: HashMap<String, (u64, u64)>,
    size_buckets: [u64; 5],
    rate_win: VecDeque<(u64, usize)>,
}

impl Spiderweb {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            flows: HashMap::new(),
            order: VecDeque::new(),
            chrono: VecDeque::with_capacity(240),
            total_pkts: 0,
            total_bytes: 0,
            proto_stats: HashMap::new(),
            talker_stats: HashMap::new(),
            size_buckets: [0; 5],
            rate_win: VecDeque::with_capacity(2048),
        }
    }

    pub fn ingest_eth(&mut self, frame: &[u8]) -> Option<(String, u32, u32, f32, ChronoLine)> {
        if frame.len() < 34 { return None; }
        let eth_type = u16::from_be_bytes([frame[12], frame[13]]);
        if eth_type != 0x0800 { return None; }

        let ip = &frame[14..];
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        if ihl < 20 || ip.len() < ihl + 8 { return None; }
        let proto_num = ip[9];
        let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let l4 = &ip[ihl..];

        let (src_port, dst_port, payload, is_syn, flags_str) = match proto_num {
            6 => {
                if l4.len() < 20 { return None; }
                let sp = u16::from_be_bytes([l4[0], l4[1]]);
                let dp = u16::from_be_bytes([l4[2], l4[3]]);
                let doff = ((l4[12] >> 4) as usize) * 4;
                let fl = l4[13];
                let syn = (fl & 0x02) != 0;
                if doff < 20 || l4.len() < doff { return None; }
                let mut fs = String::new();
                if (fl & 0x02) != 0 { fs.push('S'); }
                if (fl & 0x10) != 0 { fs.push('A'); }
                if (fl & 0x08) != 0 { fs.push('P'); }
                if (fl & 0x01) != 0 { fs.push('F'); }
                if (fl & 0x04) != 0 { fs.push('R'); }
                if fs.is_empty() { fs.push('-'); }
                (sp, dp, &l4[doff..], syn, fs)
            }
            17 => {
                if l4.len() < 8 { return None; }
                let sp = u16::from_be_bytes([l4[0], l4[1]]);
                let dp = u16::from_be_bytes([l4[2], l4[3]]);
                (sp, dp, &l4[8..], false, "UDP".to_string())
            }
            _ => return None,
        };

        if src_port == 8095 || dst_port == 8095 || src_port == 8096 || dst_port == 8096 {
            return None;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let (a, b) = if (src_ip, src_port) <= (dst_ip, dst_port) {
            (format!("{src_ip}:{src_port}"), format!("{dst_ip}:{dst_port}"))
        } else {
            (format!("{dst_ip}:{dst_port}"), format!("{src_ip}:{src_port}"))
        };
        let key = format!("{proto_num}:{a}<>{b}");

        let mut detected = if proto_num == 17 && (src_port == 53 || dst_port == 53) {
            "DNS".to_string()
        } else if proto_num == 6 {
            "TCP".to_string()
        } else {
            "UDP".to_string()
        };

        let mut sni_hit = None;
        let mut ja4_hit = None;
        let mut dns_hit = None;

        if !payload.is_empty() {
            if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") || payload.starts_with(b"PUT ")
                || payload.starts_with(b"HEAD ") || payload.starts_with(b"HTTP/")
            {
                detected = "HTTP".into();
            } else if payload.starts_with(b"SSH-") {
                detected = "SSH".into();
            } else if payload.len() > 44 && payload[0] == 0x16 && payload[5] == 0x01 {
                detected = "TLS".into();
                ja4_hit = ja4::parse_client_hello(payload);
                sni_hit = extract_tls_sni(payload);
            } else if detected == "DNS" && payload.len() > 12 {
                dns_hit = extract_dns_name(payload);
            } else if dst_port == 443 || src_port == 443 {
                detected = "TLS".into();
            }
        }

        // Update iptraf-ng real-time counters
        let flen = frame.len();
        self.total_pkts += 1;
        self.total_bytes += flen as u64;
        let ps = self.proto_stats.entry(detected.clone()).or_insert((0, 0));
        ps.0 += 1;
        ps.1 += flen as u64;

        let b_idx = match flen {
            0..=64 => 0,
            65..=256 => 1,
            257..=1024 => 2,
            1025..=1500 => 3,
            _ => 4,
        };
        self.size_buckets[b_idx] += 1;

        let talker_ip = if src_ip.is_private() || src_ip.is_loopback() { dst_ip } else { src_ip };
        let ts_entry = self.talker_stats.entry(talker_ip.to_string()).or_insert((0, 0));
        ts_entry.0 += 1;
        ts_entry.1 += flen as u64;

        self.rate_win.push_back((now, flen));
        while let Some(&(t, _)) = self.rate_win.front() {
            if now.saturating_sub(t) > 3000 { self.rate_win.pop_front(); } else { break; }
        }

        if !self.flows.contains_key(&key) {
            if self.order.len() >= 128 {
                if let Some(old) = self.order.pop_front() {
                    self.flows.remove(&old);
                }
            }
            let id = self.next_id;
            self.next_id += 1;
            self.order.push_back(key.clone());
            self.flows.insert(key.clone(), CapturedFlow {
                id, proto: detected.clone(),
                src_ip: src_ip.to_string(), src_port,
                dst_ip: dst_ip.to_string(), dst_port,
                pkts: 0, bytes: 0, last_ts: now,
                sni: None, ja4: None, dns_q: None,
                payload: Vec::new(),
            });
        }

        if let Some(f) = self.flows.get_mut(&key) {
            f.pkts += 1;
            f.bytes += payload.len().max(flen);
            f.last_ts = now;
            if detected != "TCP" && detected != "UDP" { f.proto = detected.clone(); }
            if sni_hit.is_some() { f.sni = sni_hit; }
            if ja4_hit.is_some() { f.ja4 = ja4_hit; }
            if dns_hit.is_some() { f.dns_q = dns_hit; }
            if !payload.is_empty() && f.payload.len() < 65536 {
                let take = (65536 - f.payload.len()).min(payload.len());
                f.payload.extend_from_slice(&payload[..take]);
            }
        }

        let ent = shannon(if payload.is_empty() { frame } else { payload });
        let ascii: String = payload.iter().take(28)
            .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
            .collect();
        let fid = self.flows.get(&key).map(|f| f.id).unwrap_or(0);
        let line = ChronoLine {
            flow_id: fid,
            ts: now,
            proto: detected.clone(),
            flags: flags_str,
            src: format!("{src_ip}:{src_port}"),
            dst: format!("{dst_ip}:{dst_port}"),
            len: flen,
            entropy: ent,
            preview: payload.iter().take(64).copied().collect(),
            ascii,
        };
        if self.chrono.len() >= 220 { self.chrono.pop_front(); }
        self.chrono.push_back(line.clone());

        let ip_u32 = u32::from_be_bytes(src_ip.octets());
        let x = (ip_u32 ^ (ip_u32 >> 16)) % 512;
        let y = (dst_port as u32) % 512;
        let amp = if is_syn { 2.0 } else if !payload.is_empty() { 1.45 } else { 1.0 };
        let summary = format!("WIRE {detected} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({flen}B)");
        Some((summary, x, y, amp, line))
    }

    pub fn iptraf_snapshot(&mut self) -> IptrafSnapshot {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        while let Some(&(t, _)) = self.rate_win.front() {
            if now.saturating_sub(t) > 3000 { self.rate_win.pop_front(); } else { break; }
        }
        let win_pkts = self.rate_win.len() as f32;
        let win_bytes: usize = self.rate_win.iter().map(|&(_, b)| b).sum();
        let pps = (win_pkts / 3.0 * 10.0).round() / 10.0;
        let kbps = ((win_bytes as f32 / 3.0 / 1024.0) * 10.0).round() / 10.0;

        let tb = self.total_bytes.max(1) as f32;
        let mut protos: Vec<ProtoRow> = self.proto_stats.iter().map(|(k, &(p, b))| ProtoRow {
            proto: k.clone(), pkts: p, bytes: b,
            share_pct: ((b as f32 / tb) * 1000.0).round() / 10.0,
        }).collect();
        protos.sort_by(|a, b| b.bytes.cmp(&a.bytes));

        let mut talkers: Vec<TalkerRow> = self.talker_stats.iter().map(|(ip, &(p, b))| TalkerRow {
            ip: ip.clone(), pkts: p, bytes: b,
            share_pct: ((b as f32 / tb) * 1000.0).round() / 10.0,
        }).collect();
        talkers.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        talkers.truncate(8);

        IptrafSnapshot {
            pps, kbps,
            total_pkts: self.total_pkts,
            total_bytes: self.total_bytes,
            active_flows: self.flows.len(),
            protos,
            size_buckets: self.size_buckets,
            top_talkers: talkers,
        }
    }

    pub fn list_flows(&self) -> Vec<FlowSummary> {
        let mut out: Vec<&CapturedFlow> = self.flows.values().collect();
        out.sort_by(|a, b| b.last_ts.cmp(&a.last_ts));
        out.into_iter().take(60).map(|f| {
            let snip: String = f.payload.iter().take(48)
                .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
                .collect();
            FlowSummary {
                id: f.id, proto: f.proto.clone(),
                src: format!("{}:{}", f.src_ip, f.src_port),
                dst: format!("{}:{}", f.dst_ip, f.dst_port),
                pkts: f.pkts, bytes: f.bytes,
                entropy: shannon(&f.payload),
                sni: f.sni.clone(), ja4: f.ja4.clone(), dns_q: f.dns_q.clone(),
                snippet: snip,
            }
        }).collect()
    }

    pub fn reconstruct(&self, id: u64) -> Option<Reconstruction> {
        let f = self.flows.values().find(|x| x.id == id)?;
        let data = &f.payload;
        let ent = shannon(data);
        let hex_dump = format_hex(data, 512);

        let mut artifact_type;
        let mut data_uri = None;
        let text_view;
        let mut meta = serde_json::json!({
            "pkts": f.pkts, "sni": f.sni, "ja4": f.ja4, "dns_query": f.dns_q
        });

        if f.proto == "HTTP" || data.starts_with(b"HTTP/") || data.starts_with(b"GET ") || data.starts_with(b"POST ") {
            artifact_type = "HTTP_EXCHANGE".into();
            if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let hdrs = String::from_utf8_lossy(&data[..pos]).to_string();
                let body = &data[pos + 4..];
                meta["headers"] = serde_json::json!(hdrs);
                if body.starts_with(b"\x89PNG") {
                    artifact_type = "RECONSTRUCTED_IMAGE_PNG".into();
                    data_uri = Some(format!("data:image/png;base64,{}", to_base64(body)));
                    text_view = format!("Reconstructed PNG image ({} bytes) from HTTP body.", body.len());
                } else if body.starts_with(b"\xff\xd8\xff") {
                    artifact_type = "RECONSTRUCTED_IMAGE_JPEG".into();
                    data_uri = Some(format!("data:image/jpeg;base64,{}", to_base64(body)));
                    text_view = format!("Reconstructed JPEG image ({} bytes) from HTTP body.", body.len());
                } else {
                    text_view = format!("{hdrs}\n\n--- BODY ({} bytes) ---\n{}", body.len(), String::from_utf8_lossy(&body[..body.len().min(4096)]));
                }
            } else {
                text_view = String::from_utf8_lossy(&data[..data.len().min(4096)]).to_string();
            }
        } else if f.proto == "TLS" {
            artifact_type = "TLS_ENCRYPTED_SESSION".into();
            text_view = format!(
                "Encrypted TLS stream ({} captured bytes, entropy {ent:.2} bits/byte).\nSNI Host: {}\nJA4 Fingerprint: {}\n\nPrintable cert/handshake strings:\n{}",
                data.len(),
                f.sni.as_deref().unwrap_or("(not in capture window)"),
                f.ja4.as_deref().unwrap_or("(mid-stream / no ClientHello)"),
                extract_strings(data)
            );
        } else if f.proto == "DNS" {
            artifact_type = "DNS_RECORD".into();
            text_view = format!("Decoded DNS Query: {}\nRaw printable strings:\n{}", f.dns_q.as_deref().unwrap_or("unknown"), extract_strings(data));
        } else {
            if let Some((kind, uri)) = carve_media(data) {
                artifact_type = kind.into();
                data_uri = Some(uri);
                text_view = format!("Carved live {kind} directly from raw stream ({} bytes).", data.len());
            } else if data.starts_with(b"RFB ") {
                artifact_type = "VNC_DESKTOP_STREAM".into();
                text_view = format!("Live VNC/RFB remote desktop session detected ({} bytes). Pipe to RFB framebuffer decoder to render pixels.", data.len());
            } else if data.len() >= 376 && data[0] == 0x47 && data[188] == 0x47 {
                artifact_type = "MPEG_TS_VIDEO_STREAM".into();
                text_view = format!("Live MPEG-TS video/TV stream detected (0x47 188B sync lock, {} bytes). Pipe to VA-API ffmpeg for instant keyframe decode.", data.len());
            } else {
            let strs = extract_strings(data);
            if !strs.is_empty() {
                artifact_type = "ASCII_TEXT_STREAM".into();
                text_view = strs;
            } else {
                artifact_type = "BINARY_OR_OBFUSCATED".into();
                text_view = format!("High-entropy or binary payload ({} bytes, H={ent:.2}). Inspect hex dump below.", data.len());
            }
            }
        }

        Some(Reconstruction {
            id: f.id, proto: f.proto.clone(),
            src: format!("{}:{}", f.src_ip, f.src_port),
            dst: format!("{}:{}", f.dst_ip, f.dst_port),
            bytes: data.len(), entropy: ent,
            artifact_type, metadata: meta, text_view, data_uri, hex_dump,
        })
    }
}

pub fn spawn_sniffer<F>(web: Arc<Mutex<Spiderweb>>, on_pkt: F) -> bool
where
    F: Fn(String, u32, u32, f32, ChronoLine) + Send + 'static,
{
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32) };
    if fd < 0 { return false; }
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 { continue; }
            let slice = &buf[..n as usize];
            let res = web.lock().ok().and_then(|mut w| w.ingest_eth(slice));
            if let Some((msg, x, y, amp, line)) = res {
                on_pkt(msg, x, y, amp, line);
            }
        }
    });
    true
}

fn shannon(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut cnt = [0u32; 256];
    for &b in data { cnt[b as usize] += 1; }
    let n = data.len() as f32;
    let mut h = 0.0f32;
    for c in cnt {
        if c > 0 { let p = c as f32 / n; h -= p * p.log2(); }
    }
    (h * 100.0).round() / 100.0
}

fn extract_strings(data: &[u8]) -> String {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data.iter().take(4096) {
        if (32..=126).contains(&b) { cur.push(b as char); }
        else {
            if cur.len() >= 4 { out.push(cur.clone()); }
            cur.clear();
        }
    }
    if cur.len() >= 4 { out.push(cur); }
    out.into_iter().take(32).collect::<Vec<_>>().join("\n")
}

fn extract_dns_name(buf: &[u8]) -> Option<String> {
    let mut i = 12;
    let mut parts = Vec::new();
    while i < buf.len() {
        let l = buf[i] as usize;
        if l == 0 { break; }
        if l > 63 || i + 1 + l > buf.len() { break; }
        parts.push(String::from_utf8_lossy(&buf[i + 1..i + 1 + l]).to_string());
        i += 1 + l;
    }
    if parts.is_empty() { None } else { Some(parts.join(".")) }
}

fn extract_tls_sni(buf: &[u8]) -> Option<String> {
    let mut i = 5 + 4 + 2 + 32;
    if i >= buf.len() { return None; }
    i += 1 + buf[i] as usize;
    if i + 2 > buf.len() { return None; }
    i += 2 + u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    if i >= buf.len() { return None; }
    i += 1 + buf[i] as usize;
    if i + 2 > buf.len() { return None; }
    let end = (i + 2 + u16::from_be_bytes([buf[i], buf[i + 1]]) as usize).min(buf.len());
    i += 2;
    while i + 4 <= end {
        let et = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let el = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + el > end { break; }
        if et == 0x0000 && el > 5 {
            let nl = u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize;
            if 5 + nl <= el {
                return Some(String::from_utf8_lossy(&buf[i + 5..i + 5 + nl]).to_string());
            }
        }
        i += el;
    }
    None
}

fn format_hex(data: &[u8], max_bytes: usize) -> String {
    let mut out = String::new();
    for (row, chunk) in data.iter().take(max_bytes).collect::<Vec<_>>().chunks(16).enumerate() {
        out.push_str(&format!("{:04x}: ", row * 16));
        for &b in chunk { out.push_str(&format!("{b:02x} ")); }
        for _ in chunk.len()..16 { out.push_str("   "); }
        out.push(' ');
        for &&b in chunk { out.push(if (32..=126).contains(&b) { b as char } else { '.' }); }
        out.push('\n');
    }
    out
}

fn to_base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for c in input.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = if c.len() > 1 { c[1] as u32 } else { 0 };
        let b2 = if c.len() > 2 { c[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn carve_media(data: &[u8]) -> Option<(&'static str, String)> {
    if let Some(i) = data.windows(8).position(|w| w == b"\x89PNG\r\n\x1a\n") {
        return Some(("CARVED_PNG_IMAGE", format!("data:image/png;base64,{}", to_base64(&data[i..]))));
    }
    if let Some(i) = data.windows(3).position(|w| w == b"\xff\xd8\xff") {
        return Some(("CARVED_JPEG_IMAGE", format!("data:image/jpeg;base64,{}", to_base64(&data[i..]))));
    }
    if let Some(i) = data.windows(6).position(|w| w == b"GIF89a" || w == b"GIF87a") {
        return Some(("CARVED_GIF_IMAGE", format!("data:image/gif;base64,{}", to_base64(&data[i..]))));
    }
    if let Some(i) = data.windows(12).position(|w| &w[0..4] == b"RIFF" && &w[8..12] == b"WEBP") {
        return Some(("CARVED_WEBP_IMAGE", format!("data:image/webp;base64,{}", to_base64(&data[i..]))));
    }
    None
}

fn carve_media_any(data: &[u8]) -> Option<(&'static str, String)> {
    if let Some(i) = data.windows(8).position(|w| w == b"\x89PNG\r\n\x1a\n") {
        return Some(("CARVED_PNG_IMAGE", format!("data:image/png;base64,{}", to_base64(&data[i..]))));
    }
    if let Some(i) = data.windows(3).position(|w| w == b"\xff\xd8\xff") {
        return Some(("CARVED_JPEG_IMAGE", format!("data:image/jpeg;base64,{}", to_base64(&data[i..]))));
    }
    if let Some(i) = data.windows(6).position(|w| w == b"GIF89a" || w == b"GIF87a") {
        return Some(("CARVED_GIF_IMAGE", format!("data:image/gif;base64,{}", to_base64(&data[i..]))));
    }
    if let Some(i) = data.windows(12).position(|w| &w[0..4] == b"RIFF" && &w[8..12] == b"WEBP") {
        return Some(("CARVED_WEBP_IMAGE", format!("data:image/webp;base64,{}", to_base64(&data[i..]))));
    }
    None
}

impl Spiderweb {
    pub fn reconstruct_with_tls(&self, flow_id: u64, tls: &crate::tls_decrypt::TlsKeyStore) -> Option<Reconstruction> {
        let f = self.flows.values().find(|fl| fl.id == flow_id)?;
        if let Some((cipher_info, plain)) = tls.try_decrypt_stream(&f.payload, &f.payload) {
            let (atype, duri, tview) = if let Some((kind, uri)) = carve_media_any(&plain) {
                (format!("TLS_DECRYPTED_{kind}"), Some(uri), format!("Decrypted {cipher_info} and carved live image ({} bytes).", plain.len()))
            } else {
                (format!("TLS_DECRYPTED_STREAM ({cipher_info})"), None, String::from_utf8_lossy(&plain).into_owned())
            };
            return Some(Reconstruction {
                id: f.id,
                proto: f.proto.clone(),
                src: format!("{}:{}", f.src_ip, f.src_port),
                dst: format!("{}:{}", f.dst_ip, f.dst_port),
                bytes: plain.len(),
                entropy: shannon(&plain),
                artifact_type: atype,
                metadata: serde_json::json!({}),
                text_view: tview,
                data_uri: duri,
                hex_dump: format_hex(&plain, 512),
            });
        }
        let mut art = self.reconstruct(flow_id)?;
        if art.data_uri.is_none() {
            if let Some((kind, uri)) = carve_media_any(&f.payload) {
                art.artifact_type = kind.into();
                art.data_uri = Some(uri);
            }
        }
        Some(art)
    }
}
