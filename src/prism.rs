use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessLineage {
    pub pid: u32,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    pub parent_chain: Vec<String>,
    pub exe_sha256: String,
    pub anomalies: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpectralDna {
    pub flow_id: u64,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub samples: usize,
    pub mean_iat_ms: f64,
    pub jitter_cv: f64,
    pub dft_papr: f64,
    pub avg_pkt_bytes: f64,
    pub beacon_score: u8,
    pub classification: String,
    pub lineage: Option<ProcessLineage>,
    pub vulkan_broker_online: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShadowRule {
    pub id: u64,
    pub mode: String,   // "SHADOW" | "ARMED"
    pub action: String, // "XDP_DROP_TUPLE" | "FREEZE_PID" | "RATE_LIMIT" | "PCAP_RECORD"
    pub target_ip: String,
    pub target_port: u16,
    pub target_pid: Option<u32>,
    pub reason: String,
    pub shadow_hits: u64,
    pub armed_hits: u64,
    pub created_ts: u64,
}

#[derive(Default)]
struct FlowTelemetry {
    timestamps_ms: VecDeque<u64>,
    delta_bytes: VecDeque<usize>,
    last_pkts: u64,
    last_bytes: usize,
    src: String,
    dst: String,
    proto: String,
    src_port: u16,
    dst_port: u16,
}

#[derive(Clone, Default)]
pub struct PrismEngine {
    telemetry: Arc<RwLock<HashMap<u64, FlowTelemetry>>>,
    rules: Arc<RwLock<Vec<ShadowRule>>>,
    next_rule_id: Arc<RwLock<u64>>,
    hash_cache: Arc<RwLock<HashMap<String, String>>>,
}

impl PrismEngine {
    pub fn new() -> Self {
        Self {
            telemetry: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(Vec::new())),
            next_rule_id: Arc::new(RwLock::new(1)),
            hash_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Feeds flow snapshots from Spiderweb into Prism's sliding-window ring buffers
    /// and updates Shadow-Mode / Armed hit counters without touching existing packet paths.
    pub fn ingest_snapshots(&self, snaps: &[(u64, String, String, u16, String, u16, u64, usize)]) {
        let now_ms = now_epoch_ms();
        let mut tel = self.telemetry.write().unwrap();
        let mut rules = self.rules.write().unwrap();

        for (fid, proto, src_ip, src_port, dst_ip, dst_port, pkts, total_bytes) in snaps {
            let entry = tel.entry(*fid).or_insert_with(|| FlowTelemetry {
                src: format!("{src_ip}:{src_port}"),
                dst: format!("{dst_ip}:{dst_port}"),
                proto: proto.clone(),
                src_port: *src_port,
                dst_port: *dst_port,
                ..Default::default()
            });

            if *pkts > entry.last_pkts || *total_bytes > entry.last_bytes {
                let d_pkts = pkts.saturating_sub(entry.last_pkts).max(1);
                let d_bytes = total_bytes.saturating_sub(entry.last_bytes);
                entry.last_pkts = *pkts;
                entry.last_bytes = *total_bytes;

                if entry.timestamps_ms.len() >= 64 {
                    entry.timestamps_ms.pop_front();
                }
                if entry.delta_bytes.len() >= 64 {
                    entry.delta_bytes.pop_front();
                }
                entry.timestamps_ms.push_back(now_ms);
                entry.delta_bytes.push_back(d_bytes);

                // Evaluate Shadow-Mode & Armed rules against active traffic deltas
                for r in rules.iter_mut() {
                    let ip_match = r.target_ip == *dst_ip || r.target_ip == *src_ip;
                    let port_match = r.target_port == 0 || r.target_port == *dst_port || r.target_port == *src_port;
                    if ip_match && port_match {
                        if r.mode == "SHADOW" {
                            r.shadow_hits += d_pkts;
                        } else {
                            r.armed_hits += d_pkts;
                        }
                    }
                }
            }
        }
    }

    /// Computes full Process Lineage + Spectral Traffic DNA for a specific flow or port pair.
    pub fn inspect_flow(
        &self,
        flow_id: u64,
        proto: &str,
        src: &str,
        dst: &str,
    ) -> SpectralDna {
        let src_port = parse_port(src);
        let dst_port = parse_port(dst);
        let lineage = self.resolve_lineage_for_ports(proto, src_port, dst_port);

        let (samples, mean_iat_ms, jitter_cv, dft_papr, avg_pkt_bytes) = {
            let tel = self.telemetry.read().unwrap();
            if let Some(ft) = tel.get(&flow_id) {
                compute_spectral_metrics(&ft.timestamps_ms, &ft.delta_bytes)
            } else {
                (0, 0.0, 0.0, 0.0, 0.0)
            }
        };

        let mut score: f64 = 0.0;
        if samples >= 4 {
            // Metronomic or jittered C2 periodicity (low CV or strong DFT harmonic peak)
            if jitter_cv > 0.0 && jitter_cv < 0.35 {
                score += 40.0 * (1.0 - jitter_cv / 0.35);
            }
            if dft_papr > 2.2 {
                score += ((dft_papr - 2.0) * 18.0).min(35.0);
            }
            if avg_pkt_bytes > 12_000.0 {
                score += 20.0;
            }
        }
        if let Some(ref lin) = lineage {
            if !lin.anomalies.is_empty() {
                score += 35.0;
            }
        }
        let beacon_score = score.clamp(0.0, 100.0).round() as u8;

        let classification = if lineage.as_ref().map(|l| !l.anomalies.is_empty()).unwrap_or(false) {
            "SUSPICIOUS_LINEAGE".to_string()
        } else if beacon_score >= 65 {
            "PERIODIC_C2_BEACON".to_string()
        } else if beacon_score >= 35 && avg_pkt_bytes > 12_000.0 {
            "HIGH_VOLUME_EXFIL_BURST".to_string()
        } else if beacon_score >= 35 {
            "JITTERED_PERIODIC_FLOW".to_string()
        } else {
            "NORMAL_TRAFFIC".to_string()
        };

        let broker_sock = std::env::var("HOME")
            .map(|h| format!("{h}/.cas/vulkan.sock"))
            .unwrap_or_else(|_| "/tmp/vulkan.sock".into());
        let vulkan_broker_online = Path::new(&broker_sock).exists();

        SpectralDna {
            flow_id,
            src: src.to_string(),
            dst: dst.to_string(),
            proto: proto.to_string(),
            samples,
            mean_iat_ms,
            jitter_cv,
            dft_papr,
            avg_pkt_bytes,
            beacon_score,
            classification,
            lineage,
            vulkan_broker_online,
        }
    }

    pub fn add_shadow_rule(
        &self,
        action: String,
        target_ip: String,
        target_port: u16,
        target_pid: Option<u32>,
        reason: String,
    ) -> ShadowRule {
        let mut next = self.next_rule_id.write().unwrap();
        let id = *next;
        *next += 1;
        let rule = ShadowRule {
            id,
            mode: "SHADOW".into(),
            action,
            target_ip,
            target_port,
            target_pid,
            reason,
            shadow_hits: 0,
            armed_hits: 0,
            created_ts: now_epoch_ms() / 1000,
        };
        self.rules.write().unwrap().push(rule.clone());
        rule
    }

    pub fn list_rules(&self) -> Vec<ShadowRule> {
        self.rules.read().unwrap().clone()
    }

    pub fn set_rule_mode(&self, rule_id: u64, arm: bool) -> Result<ShadowRule, String> {
        let mut rules = self.rules.write().unwrap();
        let r = rules
            .iter_mut()
            .find(|x| x.id == rule_id)
            .ok_or_else(|| format!("Rule #{rule_id} not found"))?;

        if r.action == "FREEZE_PID" {
            if let Some(pid) = r.target_pid {
                let my_pid = std::process::id();
                if pid <= 1 || pid == my_pid {
                    return Err("Refused to signal PID 1 or caprun itself".into());
                }
                let sig = if arm { "-STOP" } else { "-CONT" };
                let _ = Command::new("kill").args([sig, &pid.to_string()]).status();
            }
        }
        r.mode = if arm { "ARMED".into() } else { "SHADOW".into() };
        Ok(r.clone())
    }

    pub fn summary_stats(&self) -> (usize, usize, usize) {
        let flows = self.telemetry.read().unwrap().len();
        let rules = self.rules.read().unwrap();
        let shadow = rules.iter().filter(|r| r.mode == "SHADOW").count();
        let armed = rules.iter().filter(|r| r.mode == "ARMED").count();
        (flows, shadow, armed)
    }

    fn resolve_lineage_for_ports(&self, proto: &str, p1: u16, p2: u16) -> Option<ProcessLineage> {
        let is_udp = proto.eq_ignore_ascii_case("UDP")
            || proto.eq_ignore_ascii_case("DNS")
            || proto.eq_ignore_ascii_case("QUIC");
        let tables: &[&str] = if is_udp {
            &["/proc/net/udp", "/proc/net/udp6"]
        } else {
            &["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"]
        };

        let mut target_inodes = Vec::new();
        for tbl in tables {
            if let Ok(txt) = fs::read_to_string(tbl) {
                for line in txt.lines().skip(1) {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() < 10 {
                        continue;
                    }
                    if let Some(hex_port) = cols[1].split(':').nth(1) {
                        if let Ok(lport) = u16::from_str_radix(hex_port, 16) {
                            if (p1 != 0 && lport == p1) || (p2 != 0 && lport == p2) {
                                if let Ok(inode) = cols[9].parse::<u64>() {
                                    if inode > 0 {
                                        target_inodes.push(inode);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if target_inodes.is_empty() {
            return None;
        }

        let entries = fs::read_dir("/proc").ok()?;
        for ent in entries.flatten() {
            let name = ent.file_name();
            let pid_str = name.to_string_lossy();
            let Ok(pid) = pid_str.parse::<u32>() else { continue };
            let fd_dir = format!("/proc/{pid}/fd");
            let Ok(fds) = fs::read_dir(&fd_dir) else { continue };
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    let s = link.to_string_lossy();
                    if let Some(rest) = s.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                        if let Ok(ino) = rest.parse::<u64>() {
                            if target_inodes.contains(&ino) {
                                return Some(self.build_lineage(pid));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn build_lineage(&self, pid: u32) -> ProcessLineage {
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "(unreadable)".into());
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .replace('\0', " ")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default();
        let (comm, mut cur_ppid) = read_comm_ppid(pid).unwrap_or_else(|| ("?".into(), 0));

        let mut parent_chain = vec![format!("{comm}({pid})")];
        for _ in 0..4 {
            if cur_ppid <= 1 {
                break;
            }
            if let Some((pcomm, next_ppid)) = read_comm_ppid(cur_ppid) {
                parent_chain.push(format!("{pcomm}({cur_ppid})"));
                cur_ppid = next_ppid;
            } else {
                break;
            }
        }

        let exe_sha256 = self.cached_sha256(&exe);
        let mut anomalies = Vec::new();
        if exe.starts_with("/tmp/") || exe.starts_with("/dev/shm/") || exe.starts_with("/var/tmp/") {
            anomalies.push(format!("ephemeral_exec_path:{exe}"));
        }
        if exe.contains("(deleted)") {
            anomalies.push("fileless_or_deleted_binary".into());
        }

        ProcessLineage {
            pid,
            comm,
            exe,
            cmdline,
            parent_chain,
            exe_sha256,
            anomalies,
        }
    }

    fn cached_sha256(&self, path: &str) -> String {
        if path.starts_with('(') || path.contains("(deleted)") {
            return "unavailable".into();
        }
        if let Some(hit) = self.hash_cache.read().unwrap().get(path) {
            return hit.clone();
        }
        let digest = match fs::metadata(path) {
            Ok(meta) if meta.len() <= 32 * 1024 * 1024 => fs::read(path)
                .map(|bytes| {
                    let h = Sha256::digest(&bytes);
                    h.iter().map(|b| format!("{b:02x}")).collect::<String>()
                })
                .unwrap_or_else(|_| "unreadable".into()),
            _ => "skipped_large_or_unreadable".into(),
        };
        self.hash_cache.write().unwrap().insert(path.to_string(), digest.clone());
        digest
    }
}

fn read_comm_ppid(pid: u32) -> Option<(String, u32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let lparen = stat.find('(')?;
    let rparen = stat.rfind(')')?;
    let comm = stat[lparen + 1..rparen].to_string();
    let rest: Vec<&str> = stat[rparen + 2..].split_whitespace().collect();
    let ppid = rest.get(1)?.parse::<u32>().ok()?;
    Some((comm, ppid))
}

fn compute_spectral_metrics(ts: &VecDeque<u64>, sizes: &VecDeque<usize>) -> (usize, f64, f64, f64, f64) {
    let n = ts.len();
    let avg_pkt_bytes = if sizes.is_empty() {
        0.0
    } else {
        sizes.iter().sum::<usize>() as f64 / sizes.len() as f64
    };
    if n < 3 {
        return (n, 0.0, 0.0, 0.0, avg_pkt_bytes);
    }

    let mut iats = Vec::with_capacity(n - 1);
    for i in 1..n {
        iats.push(ts[i].saturating_sub(ts[i - 1]) as f64);
    }
    let m = iats.len() as f64;
    let mean = iats.iter().sum::<f64>() / m;
    let var = iats.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / m;
    let jitter_cv = if mean > 1e-6 { var.sqrt() / mean } else { 0.0 };

    // Discrete Fourier Transform Peak-to-Average Power Ratio over zero-mean IATs
    let k_max = (iats.len() / 2).max(1);
    let mut powers = Vec::with_capacity(k_max);
    for k in 1..=k_max {
        let mut re = 0.0;
        let mut im = 0.0;
        for (idx, &val) in iats.iter().enumerate() {
            let angle = 2.0 * std::f64::consts::PI * (k as f64) * (idx as f64) / m;
            let centered = val - mean;
            re += centered * angle.cos();
            im -= centered * angle.sin();
        }
        powers.push(re * re + im * im);
    }
    let mean_pow = powers.iter().sum::<f64>() / (powers.len() as f64);
    let max_pow = powers.iter().cloned().fold(0.0_f64, f64::max);
    let dft_papr = if mean_pow > 1e-9 { max_pow / mean_pow } else { 1.0 };

    (
        n,
        (mean * 100.0).round() / 100.0,
        (jitter_cv * 1000.0).round() / 1000.0,
        (dft_papr * 100.0).round() / 100.0,
        (avg_pkt_bytes * 10.0).round() / 10.0,
    )
}

fn parse_port(addr: &str) -> u16 {
    addr.rsplit(':').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
