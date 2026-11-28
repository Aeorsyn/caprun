use std::collections::BTreeSet;

fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn short_hash(s: &str) -> String {
    let h = blake3::hash(s.as_bytes()).to_hex();
    h[..12].to_string()
}

/// Computes a JA4-compatible fingerprint from a TLS ClientHello record or handshake payload.
pub fn parse_client_hello(buf: &[u8]) -> Option<String> {
    if buf.len() < 44 { return None; }
    let mut i = if buf[0] == 0x16 { 5 } else { 0 };
    if i + 4 >= buf.len() || buf[i] != 0x01 { return None; } // HandshakeType::ClientHello
    i += 4; // type + 24-bit length
    if i + 34 > buf.len() { return None; }
    let mut ver = u16::from_be_bytes([buf[i], buf[i + 1]]);
    i += 2 + 32; // version + random
    if i >= buf.len() { return None; }
    let sid_len = buf[i] as usize;
    i += 1 + sid_len;
    if i + 2 > buf.len() { return None; }

    let cs_len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;
    if i + cs_len > buf.len() { return None; }
    let mut ciphers = BTreeSet::new();
    for chunk in buf[i..i + cs_len].chunks_exact(2) {
        let c = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !is_grease(c) { ciphers.insert(c); }
    }
    i += cs_len;
    if i >= buf.len() { return None; }
    let comp_len = buf[i] as usize;
    i += 1 + comp_len;

    let mut exts = BTreeSet::new();
    let mut has_sni = false;
    let mut alpn = "00".to_string();
    if i + 2 <= buf.len() {
        let ext_total = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
        i += 2;
        let end = (i + ext_total).min(buf.len());
        while i + 4 <= end {
            let et = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let el = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            i += 4;
            if i + el > end { break; }
            let edata = &buf[i..i + el];
            if !is_grease(et) {
                if et == 0x0000 { has_sni = true; }
                if et == 0x002b && el >= 3 {
                    for v in edata[1..].chunks_exact(2) {
                        let sv = u16::from_be_bytes([v[0], v[1]]);
                        if !is_grease(sv) && sv > ver { ver = sv; }
                    }
                }
                if et == 0x0010 && el >= 4 {
                    let al = edata[2] as usize;
                    if 3 + al <= el && al >= 2 {
                        let a = &edata[3..3 + al];
                        alpn = format!("{}{}", a[0] as char, a[al - 1] as char);
                    }
                }
                if et != 0x0000 && et != 0x0010 { exts.insert(et); }
            }
            i += el;
        }
    }

    let vstr = match ver { 0x0304 => "13", 0x0303 => "12", 0x0302 => "11", _ => "10" };
    let sni = if has_sni { 'd' } else { 'i' };
    let cs_str: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
    let ex_str: Vec<String> = exts.iter().map(|e| format!("{e:04x}")).collect();
    Some(format!(
        "t{vstr}{sni}{:02}{:02}{alpn}_{}_{}",
        ciphers.len().min(99),
        exts.len().min(99),
        short_hash(&cs_str.join(",")),
        short_hash(&ex_str.join(","))
    ))
}

pub fn cortex_coord(src_ip: u32, ja4: &str) -> (u32, u32) {
    let h = blake3::hash(format!("{src_ip}:{ja4}").as_bytes());
    let b = h.as_bytes();
    let x = (u16::from_le_bytes([b[0], b[1]]) as u32) % 512;
    let y = (u16::from_le_bytes([b[2], b[3]]) as u32) % 512;
    (x, y)
}
