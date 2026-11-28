use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};

#[derive(Default, Clone)]
pub struct TlsKeyStore {
    /// Maps 32-byte client_random (64-char lowercase hex) -> (label -> secret bytes)
    pub secrets: Arc<RwLock<HashMap<String, HashMap<String, Vec<u8>>>>>,
    pub keylog_path: Arc<RwLock<Option<String>>>,
}

impl TlsKeyStore {
    pub fn new() -> Self {
        let store = Self::default();
        if let Ok(path) = std::env::var("SSLKEYLOGFILE") {
            if !path.is_empty() {
                let _ = store.load_keylog_file(&path);
            }
        }
        store
    }

    pub fn load_keylog_text(&self, text: &str) -> usize {
        let mut added = 0;
        let mut map = self.secrets.write().unwrap();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 3 && parts[1].len() == 64 {
                if let Ok(sec) = hex_decode(parts[2]) {
                    let entry = map.entry(parts[1].to_lowercase()).or_default();
                    if entry.insert(parts[0].to_string(), sec).is_none() {
                        added += 1;
                    }
                }
            }
        }
        added
    }

    pub fn load_keylog_file(&self, path: &str) -> Result<usize, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        *self.keylog_path.write().unwrap() = Some(path.to_string());
        Ok(self.load_keylog_text(&content))
    }

    pub fn refresh_from_disk(&self) {
        let path = self.keylog_path.read().unwrap().clone();
        if let Some(p) = path {
            if let Ok(content) = fs::read_to_string(&p) {
                let _ = self.load_keylog_text(&content);
            }
        }
    }

    pub fn stats(&self) -> (usize, usize, Option<String>) {
        let map = self.secrets.read().unwrap();
        let sessions = map.len();
        let keys: usize = map.values().map(|v| v.len()).sum();
        let path = self.keylog_path.read().unwrap().clone();
        (sessions, keys, path)
    }

    /// Attempts to extract ClientHello random + ServerHello cipher suite and decrypt TLS 1.3 records.
    pub fn try_decrypt_stream(&self, client_bytes: &[u8], server_bytes: &[u8]) -> Option<(String, Vec<u8>)> {
        self.refresh_from_disk();
        let client_random = extract_handshake_random(client_bytes, 0x01)?;
        let cipher_suite = extract_server_cipher(server_bytes).unwrap_or(0x1301);

        let secrets_for_session = {
            let map = self.secrets.read().unwrap();
            map.get(&client_random)?.clone()
        };

        let mut plaintext = Vec::new();
        let mut records_decrypted = 0usize;

        if let Some(c_sec) = secrets_for_session.get("CLIENT_TRAFFIC_SECRET_0") {
            let dec = decrypt_direction_records(client_bytes, c_sec, cipher_suite);
            if !dec.is_empty() {
                plaintext.extend_from_slice(b"=== CLIENT -> SERVER (DECRYPTED TLS 1.3) ===\n");
                plaintext.extend_from_slice(&dec);
                plaintext.push(b'\n');
                records_decrypted += 1;
            }
        }
        if let Some(s_sec) = secrets_for_session.get("SERVER_TRAFFIC_SECRET_0") {
            let dec = decrypt_direction_records(server_bytes, s_sec, cipher_suite);
            if !dec.is_empty() {
                plaintext.extend_from_slice(b"=== SERVER -> CLIENT (DECRYPTED TLS 1.3) ===\n");
                plaintext.extend_from_slice(&dec);
                plaintext.push(b'\n');
                records_decrypted += 1;
            }
        }

        if records_decrypted > 0 {
            let cs_name = match cipher_suite {
                0x1301 => "TLS_AES_128_GCM_SHA256",
                0x1302 => "TLS_AES_256_GCM_SHA384",
                0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
                _ => "TLS_1_3_AEAD",
            };
            Some((format!("{cs_name} (client_random={}..)", &client_random[..12]), plaintext))
        } else {
            None
        }
    }
}

fn extract_handshake_random(stream: &[u8], hs_type: u8) -> Option<String> {
    let mut i = 0;
    while i + 9 <= stream.len() {
        if stream[i] == 0x16 && stream[i + 1] == 0x03 {
            let rec_len = u16::from_be_bytes([stream[i + 3], stream[i + 4]]) as usize;
            if i + 5 + rec_len <= stream.len() && stream[i + 5] == hs_type && rec_len >= 38 {
                // Handshake header: 1B type, 3B len, 2B legacy_version, 32B random
                let rnd = &stream[i + 11..i + 43];
                return Some(rnd.iter().map(|b| format!("{b:02x}")).collect());
            }
            i += 5 + rec_len;
        } else {
            i += 1;
        }
    }
    None
}

fn extract_server_cipher(stream: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i + 45 <= stream.len() {
        if stream[i] == 0x16 && stream[i + 1] == 0x03 && stream[i + 5] == 0x02 {
            let rec_len = u16::from_be_bytes([stream[i + 3], stream[i + 4]]) as usize;
            if i + 5 + rec_len > stream.len() {
                break;
            }
            let sid_len = stream[i + 43] as usize;
            let cs_off = i + 44 + sid_len;
            if cs_off + 2 <= i + 5 + rec_len {
                return Some(u16::from_be_bytes([stream[cs_off], stream[cs_off + 1]]));
            }
        }
        i += 1;
    }
    None
}

fn hkdf_expand_label_sha256(secret: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(4 + full_label.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0u8); // empty context

    let hk = Hkdf::<Sha256>::from_prk(secret).unwrap_or_else(|_| Hkdf::<Sha256>::new(None, secret));
    let mut okm = vec![0u8; out_len];
    let _ = hk.expand(&info, &mut okm);
    okm
}

fn hkdf_expand_label_sha384(secret: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(4 + full_label.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0u8);

    let hk = Hkdf::<Sha384>::from_prk(secret).unwrap_or_else(|_| Hkdf::<Sha384>::new(None, secret));
    let mut okm = vec![0u8; out_len];
    let _ = hk.expand(&info, &mut okm);
    okm
}

fn decrypt_direction_records(stream: &[u8], traffic_secret: &[u8], cipher_suite: u16) -> Vec<u8> {
    let (key_len, is_sha384) = match cipher_suite {
        0x1302 => (32, true),
        0x1303 => (32, false),
        _ => (16, false),
    };
    let key = if is_sha384 {
        hkdf_expand_label_sha384(traffic_secret, b"key", key_len)
    } else {
        hkdf_expand_label_sha256(traffic_secret, b"key", key_len)
    };
    let iv = if is_sha384 {
        hkdf_expand_label_sha384(traffic_secret, b"iv", 12)
    } else {
        hkdf_expand_label_sha256(traffic_secret, b"iv", 12)
    };

    let mut out = Vec::new();
    let mut seq: u64 = 0;
    let mut i = 0;
    while i + 5 <= stream.len() {
        let content_type = stream[i];
        let ver_maj = stream[i + 1];
        let rec_len = u16::from_be_bytes([stream[i + 3], stream[i + 4]]) as usize;
        if i + 5 + rec_len > stream.len() {
            break;
        }
        let header = &stream[i..i + 5];
        let payload = &stream[i + 5..i + 5 + rec_len];
        i += 5 + rec_len;

        if content_type != 0x17 || ver_maj != 0x03 || payload.len() <= 16 {
            continue;
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&iv[..12]);
        let seq_bytes = seq.to_be_bytes();
        for k in 0..8 {
            nonce_bytes[4 + k] ^= seq_bytes[k];
        }
        seq += 1;

        let aad_payload = Payload { msg: payload, aad: header };
        let plain_opt = match cipher_suite {
            0x1302 => Aes256Gcm::new_from_slice(&key)
                .ok()
                .and_then(|c| c.decrypt(AesNonce::from_slice(&nonce_bytes), aad_payload).ok()),
            0x1303 => ChaCha20Poly1305::new_from_slice(&key)
                .ok()
                .and_then(|c| c.decrypt(ChaChaNonce::from_slice(&nonce_bytes), aad_payload).ok()),
            _ => Aes128Gcm::new_from_slice(&key)
                .ok()
                .and_then(|c| c.decrypt(AesNonce::from_slice(&nonce_bytes), aad_payload).ok()),
        };

        if let Some(mut pt) = plain_opt {
            // Strip TLS 1.3 inner padding zeroes and trailing inner content-type byte
            while pt.last() == Some(&0) {
                pt.pop();
            }
            if let Some(inner_ct) = pt.pop() {
                if inner_ct == 0x17 {
                    out.extend_from_slice(&pt);
                }
            }
        }
    }
    out
}

/// Parses classic libpcap (.pcap) packet payloads into raw segments for offline decrypt/carving.
pub fn parse_pcap_payloads(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if bytes.len() < 24 {
        return Err("File too short for PCAP global header".into());
    }
    let le = match &bytes[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err("Unsupported PCAP magic (expected classic .pcap)".into()),
    };
    let read_u32 = |off: usize| -> u32 {
        let b = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let mut off = 24;
    let mut payloads = Vec::new();
    while off + 16 <= bytes.len() {
        let incl_len = read_u32(off + 8) as usize;
        off += 16;
        if off + incl_len > bytes.len() {
            break;
        }
        let pkt = &bytes[off..off + incl_len];
        off += incl_len;
        // Ethernet (14B) + IPv4 (20B) + TCP (20B) minimum
        if pkt.len() > 54 && pkt[12] == 0x08 && pkt[13] == 0x00 && pkt[23] == 6 {
            let ihl = ((pkt[14] & 0x0f) as usize) * 4;
            let tcp_off = 14 + ihl;
            if pkt.len() > tcp_off + 12 {
                let doff = ((pkt[tcp_off + 12] >> 4) as usize) * 4;
                let data_start = tcp_off + doff;
                if data_start < pkt.len() {
                    payloads.push(pkt[data_start..].to_vec());
                }
            }
        }
    }
    Ok(payloads)
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if clean.len() % 2 != 0 {
        return Err(());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
