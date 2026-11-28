use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use std::time::Duration;

const SOCKS_PORT: u16 = 9150;
const CTRL_PORT: u16 = 9151;
const DNS_PORT: u16 = 9153;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitHop {
    pub fingerprint: String,
    pub nickname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionCircuit {
    pub id: String,
    pub status: String,
    pub purpose: String,
    pub hops: Vec<CircuitHop>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionStatus {
    pub ok: bool,
    pub tor_installed: bool,
    pub running: bool,
    pub socks_addr: String,
    pub control_addr: String,
    pub dns_addr: String,
    pub exit_nodes: String,
    pub strict_nodes: bool,
    pub bootstrap: String,
    pub circuits: Vec<OnionCircuit>,
    pub browser_cmd: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionFetchResult {
    pub ok: bool,
    pub url: String,
    pub status_line: String,
    pub headers: String,
    pub body_preview: String,
    pub byte_len: usize,
}

#[derive(Clone)]
pub struct OnionRouter {
    base_dir: PathBuf,
    data_dir: PathBuf,
    torrc_path: PathBuf,
    pid_path: PathBuf,
    log_path: PathBuf,
    exit_nodes: Arc<RwLock<String>>,
    strict_nodes: Arc<RwLock<bool>>,
}

impl Default for OnionRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl OnionRouter {
    pub fn new() -> Self {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let base_dir = home.join(".config").join("caprun").join("onion");
        let data_dir = base_dir.join("data");
        let _ = fs::create_dir_all(&data_dir);
        let _ = fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o700));
        let _ = fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700));

        Self {
            torrc_path: base_dir.join("torrc"),
            pid_path: base_dir.join("tor.pid"),
            log_path: base_dir.join("tor.log"),
            base_dir,
            data_dir,
            exit_nodes: Arc::new(RwLock::new(String::new())),
            strict_nodes: Arc::new(RwLock::new(true)),
        }
    }

    pub fn start(&self, exit_spec: Option<&str>, strict: Option<bool>) -> Result<OnionStatus, String> {
        if !bin_exists("tor") {
            return Err("`tor` binary not found. Install with: sudo apt-get install -y tor".into());
        }
        if let Some(spec) = exit_spec {
            *self.exit_nodes.write().unwrap() = normalize_exit_spec(spec);
        }
        if let Some(st) = strict {
            *self.strict_nodes.write().unwrap() = st;
        }
        self.write_torrc()?;

        if self.is_control_alive() {
            let _ = self.apply_exit_live();
            return Ok(self.status());
        }

        let out = Command::new("tor")
            .args([
                "-f",
                &self.torrc_path.to_string_lossy(),
                "--RunAsDaemon",
                "1",
            ])
            .output()
            .map_err(|e| format!("Failed to start tor: {e}"))?;

        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Err(format!("tor startup failed: {err} {stdout}"));
        }

        // Wait briefly for ControlPort cookie to appear
        for _ in 0..15 {
            if self.is_control_alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        Ok(self.status())
    }

    pub fn stop(&self) -> Result<OnionStatus, String> {
        if self.is_control_alive() {
            let _ = self.control_cmd("SIGNAL SHUTDOWN");
            std::thread::sleep(Duration::from_millis(300));
        }
        if let Ok(pid_str) = fs::read_to_string(&self.pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                let _ = Command::new("kill").arg(pid.to_string()).status();
            }
        }
        let _ = fs::remove_file(&self.pid_path);
        Ok(self.status())
    }

    pub fn set_exit(&self, raw_spec: &str, strict: bool) -> Result<OnionStatus, String> {
        let norm = normalize_exit_spec(raw_spec);
        *self.exit_nodes.write().unwrap() = norm;
        *self.strict_nodes.write().unwrap() = strict;
        self.write_torrc()?;

        if self.is_control_alive() {
            self.apply_exit_live()?;
        }
        Ok(self.status())
    }

    pub fn new_identity(&self) -> Result<String, String> {
        if !self.is_control_alive() {
            return Err("Onion router is not running".into());
        }
        self.control_cmd("SIGNAL NEWNYM")?;
        Ok("New 3-hop circuit identity requested (SIGNAL NEWNYM).".into())
    }

    pub fn check_exit_ip(&self) -> Result<serde_json::Value, String> {
        if !self.is_control_alive() {
            return Err("Start the Onion Router first before checking Tor exit IP".into());
        }
        let out = Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "14",
                "--socks5-hostname",
                &format!("127.0.0.1:{SOCKS_PORT}"),
                "https://check.torproject.org/api/ip",
            ])
            .output()
            .map_err(|e| format!("curl failed: {e}"))?;

        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        let txt = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str(&txt).map_err(|_| format!("Unexpected Tor check response: {txt}"))
    }

    pub fn fetch_onion(&self, url: &str) -> Result<OnionFetchResult, String> {
        if !self.is_control_alive() {
            return Err("Start the Onion Router first to browse .onion addresses".into());
        }
        let u = url.trim();
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err("URL must begin with http:// or https://".into());
        }
        if u.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("URL contains invalid whitespace or control characters".into());
        }

        let out = Command::new("curl")
            .args([
                "-sS",
                "-L",
                "--max-time",
                "25",
                "--max-filesize",
                "262144",
                "--socks5-hostname",
                &format!("127.0.0.1:{SOCKS_PORT}"),
                "-i",
                "--",
                u,
            ])
            .output()
            .map_err(|e| format!("curl execution failed: {e}"))?;

        if !out.status.success() && out.stdout.is_empty() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }

        let raw = String::from_utf8_lossy(&out.stdout);
        let (headers, body) = raw
            .split_once("\r\n\r\n")
            .or_else(|| raw.split_once("\n\n"))
            .unwrap_or(("", raw.as_ref()));

        let status_line = headers.lines().next().unwrap_or("HTTP (no status line)").to_string();
        let preview: String = body.chars().take(4000).collect();

        Ok(OnionFetchResult {
            ok: true,
            url: u.to_string(),
            status_line,
            headers: headers.to_string(),
            body_preview: preview,
            byte_len: body.len(),
        })
    }

    pub fn status(&self) -> OnionStatus {
        let tor_installed = bin_exists("tor");
        let running = self.is_control_alive();
        let exit_nodes = self.exit_nodes.read().unwrap().clone();
        let strict_nodes = *self.strict_nodes.read().unwrap();

        let mut bootstrap = if running {
            "Connecting...".to_string()
        } else {
            "Stopped".to_string()
        };
        let mut circuits = Vec::new();

        if running {
            if let Ok(lines) = self.control_cmd("GETINFO status/bootstrap-phase") {
                if let Some(l) = lines.iter().find(|s| s.contains("PROGRESS=")) {
                    bootstrap = l
                        .trim_start_matches("250-status/bootstrap-phase=")
                        .to_string();
                }
            }
            if let Ok(lines) = self.control_cmd("GETINFO circuit-status") {
                circuits = parse_circuits(&lines);
            }
        }

        OnionStatus {
            ok: true,
            tor_installed,
            running,
            socks_addr: format!("127.0.0.1:{SOCKS_PORT}"),
            control_addr: format!("127.0.0.1:{CTRL_PORT}"),
            dns_addr: format!("127.0.0.1:{DNS_PORT}"),
            exit_nodes,
            strict_nodes,
            bootstrap,
            circuits,
            browser_cmd: format!(
                "chromium --user-data-dir=/tmp/caprun-onion-browser --proxy-server=\"socks5://127.0.0.1:{SOCKS_PORT}\" --host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE 127.0.0.1\""
            ),
        }
    }

    fn write_torrc(&self) -> Result<(), String> {
        let exit = self.exit_nodes.read().unwrap().clone();
        let strict = *self.strict_nodes.read().unwrap();
        let _ = fs::create_dir_all(&self.base_dir);
        let _ = fs::create_dir_all(&self.data_dir);

        let mut cfg = format!(
            "SocksPort 127.0.0.1:{SOCKS_PORT}\n\
             ControlPort 127.0.0.1:{CTRL_PORT}\n\
             DNSPort 127.0.0.1:{DNS_PORT}\n\
             CookieAuthentication 1\n\
             DataDirectory {}\n\
             PidFile {}\n\
             Log notice file {}\n",
            self.data_dir.display(),
            self.pid_path.display(),
            self.log_path.display()
        );
        if !exit.is_empty() {
            cfg.push_str(&format!("ExitNodes {exit}\n"));
            cfg.push_str(&format!("StrictNodes {}\n", if strict { 1 } else { 0 }));
        }
        fs::write(&self.torrc_path, cfg).map_err(|e| format!("Failed writing torrc: {e}"))?;
        let _ = fs::set_permissions(&self.torrc_path, fs::Permissions::from_mode(0o600));
        Ok(())
    }

    fn apply_exit_live(&self) -> Result<(), String> {
        let exit = self.exit_nodes.read().unwrap().clone();
        let strict = *self.strict_nodes.read().unwrap();
        if exit.is_empty() {
            self.control_cmd("RESETCONF ExitNodes StrictNodes")?;
        } else {
            let cmd = format!(
                "SETCONF ExitNodes=\"{exit}\" StrictNodes={}",
                if strict { 1 } else { 0 }
            );
            self.control_cmd(&cmd)?;
        }
        let _ = self.control_cmd("SIGNAL NEWNYM");
        Ok(())
    }

    fn is_control_alive(&self) -> bool {
        let addr: SocketAddr = format!("127.0.0.1:{CTRL_PORT}").parse().unwrap();
        TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
    }

    fn control_cmd(&self, cmd: &str) -> Result<Vec<String>, String> {
        let addr: SocketAddr = format!("127.0.0.1:{CTRL_PORT}").parse().unwrap();
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .map_err(|e| format!("ControlPort connect failed: {e}"))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        let mut writer = stream
            .try_clone()
            .map_err(|e| format!("Socket clone failed: {e}"))?;
        let mut reader = BufReader::new(stream);

        let cookie_path = self.data_dir.join("control_auth_cookie");
        let cookie_bytes = fs::read(&cookie_path)
            .map_err(|e| format!("Missing Tor auth cookie ({}): {e}", cookie_path.display()))?;
        let cookie_hex: String = cookie_bytes.iter().map(|b| format!("{b:02x}")).collect();

        write!(writer, "AUTHENTICATE {cookie_hex}\r\n").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
        let mut auth_resp = String::new();
        reader.read_line(&mut auth_resp).map_err(|e| e.to_string())?;
        if !auth_resp.starts_with("250") {
            return Err(format!("Tor ControlPort auth rejected: {}", auth_resp.trim()));
        }

        write!(writer, "{cmd}\r\n").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        let mut in_data = false;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
            if in_data {
                if trimmed == "." {
                    in_data = false;
                } else {
                    out.push(trimmed);
                }
                continue;
            }
            if trimmed.starts_with("250+") {
                in_data = true;
                out.push(trimmed);
            } else if trimmed.starts_with("250-") {
                out.push(trimmed);
            } else if trimmed.starts_with("250 ") || trimmed == "250" {
                out.push(trimmed);
                break;
            } else if trimmed.starts_with('4') || trimmed.starts_with('5') {
                return Err(trimmed);
            }
        }

        let _ = write!(writer, "QUIT\r\n");
        Ok(out)
    }
}

fn normalize_exit_spec(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("auto") || t.eq_ignore_ascii_case("any") {
        return String::new();
    }
    let mut parts = Vec::new();
    for item in t.split(',') {
        let s = item.trim();
        if s.is_empty() {
            continue;
        }
        if s.len() == 2 && s.chars().all(|c| c.is_ascii_alphabetic()) {
            parts.push(format!("{{{}}}", s.to_ascii_lowercase()));
        } else {
            parts.push(s.to_string());
        }
    }
    parts.join(",")
}

fn parse_circuits(lines: &[String]) -> Vec<OnionCircuit> {
    let mut out = Vec::new();
    for l in lines {
        let cols: Vec<&str> = l.split_whitespace().collect();
        if cols.len() < 3 || cols[1] != "BUILT" {
            continue;
        }
        let hops: Vec<CircuitHop> = cols[2]
            .split(',')
            .filter(|h| !h.is_empty())
            .map(|h| {
                let (fp, nick) = h
                    .split_once('~')
                    .or_else(|| h.split_once('='))
                    .unwrap_or((h, "relay"));
                CircuitHop {
                    fingerprint: fp.trim_start_matches('$').chars().take(10).collect(),
                    nickname: nick.to_string(),
                }
            })
            .collect();
        if hops.is_empty() {
            continue;
        }
        let purpose = cols
            .iter()
            .find_map(|c| c.strip_prefix("PURPOSE="))
            .unwrap_or("GENERAL")
            .to_string();
        out.push(OnionCircuit {
            id: cols[0].to_string(),
            status: cols[1].to_string(),
            purpose,
            hops,
        });
        if out.len() >= 8 {
            break;
        }
    }
    out
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
