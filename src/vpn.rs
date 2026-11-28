use qrcode::{render::svg, QrCode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnProfileSummary {
    pub name: String,
    pub path: String,
    pub address: String,
    pub endpoint: String,
    pub dns: String,
    pub allowed_ips: String,
    pub stealth_awg: bool,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnPeerTelemetry {
    pub iface: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub latest_handshake_ts: u64,
    pub handshake_age_sec: Option<u64>,
    pub health: String, // "HEALTHY" | "STALE" | "WAITING"
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub keepalive: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnIfaceTelemetry {
    pub name: String,
    pub public_key: String,
    pub listen_port: u16,
    pub fwmark: String,
    pub ip_addrs: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub peers: Vec<VpnPeerTelemetry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnStatus {
    pub ok: bool,
    pub connected: bool,
    pub active_iface: Option<String>,
    pub kill_switch: bool,
    pub kill_switch_alert: bool,
    pub wg_installed: bool,
    pub awg_installed: bool,
    pub interfaces: Vec<VpnIfaceTelemetry>,
    pub profiles: Vec<VpnProfileSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MobileQrResult {
    pub ok: bool,
    pub label: String,
    pub svg_qr: String,
    pub client_conf: String,
    pub server_peer_snippet: Option<String>,
    pub client_pubkey: Option<String>,
}

#[derive(Clone)]
pub struct VpnManager {
    profile_dir: PathBuf,
    kill_switch: Arc<RwLock<bool>>,
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnManager {
    pub fn new() -> Self {
        let base = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let profile_dir = base.join(".config").join("caprun").join("vpn");
        let _ = fs::create_dir_all(&profile_dir);
        let _ = fs::set_permissions(&profile_dir, fs::Permissions::from_mode(0o700));
        Self {
            profile_dir,
            kill_switch: Arc::new(RwLock::new(false)),
        }
    }

    pub fn set_kill_switch(&self, enabled: bool) -> bool {
        *self.kill_switch.write().unwrap() = enabled;
        enabled
    }

    pub fn save_profile(&self, raw_name: &str, content: &str) -> Result<VpnProfileSummary, String> {
        let name = sanitize_iface_name(raw_name)?;
        if !content.contains("[Interface]") {
            return Err("Invalid WireGuard config: missing [Interface] section".into());
        }
        let path = self.profile_dir.join(format!("{name}.conf"));
        fs::write(&path, content).map_err(|e| format!("Failed writing {}: {e}", path.display()))?;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        Ok(parse_profile_summary(&name, &path, content, false))
    }

    pub fn delete_profile(&self, raw_name: &str) -> Result<(), String> {
        let name = sanitize_iface_name(raw_name)?;
        let path = self.profile_dir.join(format!("{name}.conf"));
        if path.exists() {
            fs::remove_file(&path).map_err(|e| format!("Delete failed: {e}"))?;
            Ok(())
        } else {
            Err(format!("Profile '{name}' not found"))
        }
    }

    pub fn connect(&self, raw_name: &str) -> Result<String, String> {
        let name = sanitize_iface_name(raw_name)?;
        let path = self.profile_dir.join(format!("{name}.conf"));
        if !path.exists() {
            return Err(format!("Profile '{name}' does not exist"));
        }
        let content = fs::read_to_string(&path).unwrap_or_default();
        let use_awg = is_awg_config(&content) && bin_exists("awg-quick");
        let tool = if use_awg { "awg-quick" } else { "wg-quick" };
        run_priv_cmd(tool, &["up", &path.to_string_lossy()])
    }

    pub fn disconnect(&self, raw_name: &str) -> Result<String, String> {
        let name = sanitize_iface_name(raw_name)?;
        let path = self.profile_dir.join(format!("{name}.conf"));
        if path.exists() {
            let content = fs::read_to_string(&path).unwrap_or_default();
            let use_awg = is_awg_config(&content) && bin_exists("awg-quick");
            let tool = if use_awg { "awg-quick" } else { "wg-quick" };
            return run_priv_cmd(tool, &["down", &path.to_string_lossy()]);
        }
        // Fallback: tear down unmanaged interface directly
        run_priv_cmd("ip", &["link", "delete", "dev", &name])
    }

    pub fn status(&self) -> VpnStatus {
        let wg_installed = bin_exists("wg") && bin_exists("wg-quick");
        let awg_installed = bin_exists("awg") && bin_exists("awg-quick");
        let interfaces = collect_wg_telemetry();
        let active_names: Vec<String> = interfaces.iter().map(|i| i.name.clone()).collect();
        let active_iface = active_names.first().cloned();

        let mut profiles = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.profile_dir) {
            for ent in entries.flatten() {
                let p = ent.path();
                if p.extension().and_then(|e| e.to_str()) == Some("conf") {
                    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(content) = fs::read_to_string(&p) {
                            let active = active_names.iter().any(|n| n == stem);
                            profiles.push(parse_profile_summary(stem, &p, &content, active));
                        }
                    }
                }
            }
        }
        profiles.sort_by(|a, b| a.name.cmp(&b.name));

        let kill_switch = *self.kill_switch.read().unwrap();
        let any_stale = interfaces
            .iter()
            .flat_map(|i| i.peers.iter())
            .any(|p| p.health == "STALE");
        let kill_switch_alert = kill_switch && (interfaces.is_empty() || any_stale);

        VpnStatus {
            ok: true,
            connected: !interfaces.is_empty(),
            active_iface,
            kill_switch,
            kill_switch_alert,
            wg_installed,
            awg_installed,
            interfaces,
            profiles,
        }
    }

    pub fn qr_for_profile(&self, raw_name: &str) -> Result<MobileQrResult, String> {
        let name = sanitize_iface_name(raw_name)?;
        let path = self.profile_dir.join(format!("{name}.conf"));
        let content = fs::read_to_string(&path).map_err(|e| format!("Read profile failed: {e}"))?;
        let svg_qr = render_qr_svg(&content)?;
        Ok(MobileQrResult {
            ok: true,
            label: format!("Profile: {name}"),
            svg_qr,
            client_conf: content,
            server_peer_snippet: None,
            client_pubkey: None,
        })
    }

    pub fn generate_mobile_peer(
        &self,
        server_endpoint: &str,
        server_pubkey: &str,
        client_addr: &str,
        dns: &str,
    ) -> Result<MobileQrResult, String> {
        if server_endpoint.trim().is_empty() || server_pubkey.trim().is_empty() {
            return Err("Both server_endpoint (host:port) and server_pubkey are required".into());
        }
        let (privkey, pubkey) = generate_wg_keypair()?;
        let addr = if client_addr.trim().is_empty() {
            "10.99.0.2/32"
        } else {
            client_addr.trim()
        };
        let dns_val = if dns.trim().is_empty() {
            "1.1.1.1"
        } else {
            dns.trim()
        };

        let client_conf = format!(
            "[Interface]\nPrivateKey = {privkey}\nAddress = {addr}\nDNS = {dns_val}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            server_pubkey.trim(),
            server_endpoint.trim()
        );
        let server_peer_snippet = format!(
            "[Peer]\n# Mobile peer generated by caprun\nPublicKey = {pubkey}\nAllowedIPs = {addr}\n"
        );
        let svg_qr = render_qr_svg(&client_conf)?;

        Ok(MobileQrResult {
            ok: true,
            label: format!("Mobile Peer ({addr})"),
            svg_qr,
            client_conf,
            server_peer_snippet: Some(server_peer_snippet),
            client_pubkey: Some(pubkey),
        })
    }
}

fn sanitize_iface_name(raw: &str) -> Result<String, String> {
    let clean: String = raw
        .trim()
        .trim_end_matches(".conf")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(15)
        .collect();
    if clean.is_empty() {
        Err("Profile name must contain 1-15 ASCII letters, digits, '_' or '-'".into())
    } else {
        Ok(clean)
    }
}

fn is_awg_config(content: &str) -> bool {
    content
        .lines()
        .any(|l| {
            let t = l.trim();
            t.starts_with("Jc ") || t.starts_with("Jc=") || t.starts_with("H1 ") || t.starts_with("H1=")
        })
}

fn parse_profile_summary(
    name: &str,
    path: &Path,
    content: &str,
    active: bool,
) -> VpnProfileSummary {
    let mut address = String::new();
    let mut endpoint = String::new();
    let mut dns = String::new();
    let mut allowed_ips = String::new();

    for line in content.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "address" if address.is_empty() => address = v.trim().to_string(),
                "endpoint" if endpoint.is_empty() => endpoint = v.trim().to_string(),
                "dns" if dns.is_empty() => dns = v.trim().to_string(),
                "allowedips" if allowed_ips.is_empty() => allowed_ips = v.trim().to_string(),
                _ => {}
            }
        }
    }

    VpnProfileSummary {
        name: name.to_string(),
        path: path.to_string_lossy().into_owned(),
        address,
        endpoint,
        dns,
        allowed_ips,
        stealth_awg: is_awg_config(content),
        active,
    }
}

fn render_qr_svg(data: &str) -> Result<String, String> {
    let code = QrCode::new(data.as_bytes()).map_err(|e| format!("QR encode error: {e}"))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(210, 210)
        .dark_color(svg::Color("#0f172a"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

fn generate_wg_keypair() -> Result<(String, String), String> {
    let priv_out = Command::new("wg")
        .arg("genkey")
        .output()
        .map_err(|e| format!("Failed running `wg genkey` (install wireguard-tools): {e}"))?;
    if !priv_out.status.success() {
        return Err(String::from_utf8_lossy(&priv_out.stderr).trim().to_string());
    }
    let privkey = String::from_utf8_lossy(&priv_out.stdout).trim().to_string();

    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed running `wg pubkey`: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(privkey.as_bytes());
    }
    let pub_out = child
        .wait_with_output()
        .map_err(|e| format!("`wg pubkey` wait error: {e}"))?;
    if !pub_out.status.success() {
        return Err(String::from_utf8_lossy(&pub_out.stderr).trim().to_string());
    }
    let pubkey = String::from_utf8_lossy(&pub_out.stdout).trim().to_string();
    Ok((privkey, pubkey))
}

fn bin_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_priv_cmd(bin: &str, args: &[&str]) -> Result<String, String> {
    // First try sudo -n (cleanest for wg-quick on non-root OpsDeck)
    let out = Command::new("sudo")
        .arg("-n")
        .arg(bin)
        .args(args)
        .output()
        .or_else(|_| Command::new(bin).args(args).output())
        .map_err(|e| format!("Failed to execute {bin}: {e}"))?;

    if out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Ok(if stdout.is_empty() { stderr } else { stdout });
    }

    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if err.contains("password is required") || err.contains("a terminal is required") {
        return Err(format!(
            "Passwordless sudo needed for 1-click GUI toggle. Run once:\n  echo \"$USER ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick, /usr/sbin/ip\" | sudo tee /etc/sudoers.d/caprun-vpn && sudo chmod 0440 /etc/sudoers.d/caprun-vpn\n({err})"
        ));
    }
    Err(if err.is_empty() {
        format!("{bin} exited with status {}", out.status)
    } else {
        err
    })
}

fn collect_wg_telemetry() -> Vec<VpnIfaceTelemetry> {
    let mut dump = String::new();
    for bin in ["wg", "awg"] {
        if !bin_exists(bin) {
            continue;
        }
        let out = Command::new("sudo")
            .args(["-n", bin, "show", "all", "dump"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .or_else(|| {
                Command::new(bin)
                    .args(["show", "all", "dump"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
            });
        if let Some(o) = out {
            dump.push_str(&String::from_utf8_lossy(&o.stdout));
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut ifaces: Vec<VpnIfaceTelemetry> = Vec::new();
    for line in dump.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() == 5 {
            let name = cols[0].to_string();
            let (rx_sys, tx_sys) = read_sysfs_bytes(&name);
            ifaces.push(VpnIfaceTelemetry {
                name: name.clone(),
                public_key: cols[2].to_string(),
                listen_port: cols[3].parse().unwrap_or(0),
                fwmark: cols[4].to_string(),
                ip_addrs: read_iface_ips(&name),
                rx_bytes: rx_sys,
                tx_bytes: tx_sys,
                peers: Vec::new(),
            });
        } else if cols.len() >= 9 {
            let iface_name = cols[0];
            let hs_ts: u64 = cols[5].parse().unwrap_or(0);
            let age = if hs_ts > 0 {
                Some(now.saturating_sub(hs_ts))
            } else {
                None
            };
            let health = match age {
                None => "WAITING".to_string(),
                Some(s) if s < 180 => "HEALTHY".to_string(),
                Some(_) => "STALE".to_string(),
            };
            let peer = VpnPeerTelemetry {
                iface: iface_name.to_string(),
                public_key: cols[1].to_string(),
                endpoint: cols[3].to_string(),
                allowed_ips: cols[4].to_string(),
                latest_handshake_ts: hs_ts,
                handshake_age_sec: age,
                health,
                rx_bytes: cols[6].parse().unwrap_or(0),
                tx_bytes: cols[7].parse().unwrap_or(0),
                keepalive: cols[8].to_string(),
            };
            if let Some(ifc) = ifaces.iter_mut().find(|i| i.name == iface_name) {
                ifc.peers.push(peer);
            }
        }
    }
    ifaces
}

fn read_sysfs_bytes(iface: &str) -> (u64, u64) {
    let rx = fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_bytes"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let tx = fs::read_to_string(format!("/sys/class/net/{iface}/statistics/tx_bytes"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    (rx, tx)
}

fn read_iface_ips(iface: &str) -> String {
    Command::new("ip")
        .args(["-br", "addr", "show", "dev", iface])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.split_whitespace().skip(2).collect::<Vec<_>>().join(", ")
        })
        .unwrap_or_default()
}

impl VpnManager {
    /// Hot-swaps an active WireGuard peer's exit server IP:port without tearing down the tunnel.
    pub fn switch_endpoint(
        &self,
        raw_iface: &str,
        peer_pubkey: &str,
        new_endpoint: &str,
        persist_profile: bool,
    ) -> Result<String, String> {
        let iface = sanitize_iface_name(raw_iface)?;
        let pk = peer_pubkey.trim();
        let ep = new_endpoint.trim();
        if pk.is_empty() || ep.is_empty() || !ep.contains(':') {
            return Err("Provide peer_pubkey and new_endpoint as host:port (e.g. 185.213.154.68:51820)".into());
        }
        let out = run_priv_cmd("wg", &["set", &iface, "peer", pk, "endpoint", ep])?;
        if persist_profile {
            let path = self.profile_dir.join(format!("{iface}.conf"));
            if let Ok(content) = fs::read_to_string(&path) {
                let updated: Vec<String> = content
                    .lines()
                    .map(|l| {
                        if l.trim_start().to_ascii_lowercase().starts_with("endpoint") {
                            format!("Endpoint = {ep}")
                        } else {
                            l.to_string()
                        }
                    })
                    .collect();
                let _ = fs::write(&path, updated.join("
") + "
");
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
        Ok(if out.is_empty() {
            format!("Switched {iface} exit server endpoint to {ep}")
        } else {
            out
        })
    }
}
