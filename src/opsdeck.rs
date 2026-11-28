use crate::{
    cortex_stdp::{StdpCortex, Stim},
    ja4, soc_loop,
    spiderweb::{ChronoLine, Spiderweb},
};
use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Path, RawQuery, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use aya::{
    include_bytes_aligned,
    maps::{HashMap as BpfHashMap, MapData, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use caprun_common::FlowEvent;
use serde::Deserialize;
use std::{
    collections::VecDeque,
    fs::OpenOptions,
    net::Ipv4Addr,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::broadcast;

static XDP_ELF: &[u8] = include_bytes_aligned!("../caprun-ebpf/target/bpfel-unknown-none/release/caprun-ebpf");
static OPSDECK_HTML: &str = include_str!("opsdeck.html");
const PY_BACKEND: &str = "http://127.0.0.1:8096";

struct SharedState {
    cortex: Mutex<StdpCortex>,
    stims: Mutex<Vec<Stim>>,
    events: Mutex<VecDeque<String>>,
    blocklist: Mutex<Option<BpfHashMap<MapData, u32, u8>>>,
    blocked_ips: Mutex<Vec<String>>,
    spiderweb: Arc<Mutex<Spiderweb>>,
    xdp_mode: String,
    iface: String,
    llm_url: String,
    http: reqwest::Client,
    frame_tx: broadcast::Sender<(Vec<u8>, String)>,
    chrono_tx: broadcast::Sender<ChronoLine>,
    pub tls: crate::tls_decrypt::TlsKeyStore,
    pub prism: crate::prism::PrismEngine,
    pub vpn: crate::vpn::VpnManager,
}

fn push_event(st: &SharedState, line: String, x: u32, y: u32, amp: f32) {
    if let Ok(mut q) = st.events.lock() {
        if q.len() >= 40 { q.pop_front(); }
        q.push_back(line);
    }
    if let Ok(mut s) = st.stims.lock() {
        if s.len() < 64 { s.push(Stim { x: x % 512, y: y % 512, amp, _pad: 0 }); }
    }
}

fn arm_xdp_ip(st: &SharedState, ip_str: &str, add: bool) -> Result<String> {
    let ip: Ipv4Addr = ip_str.trim().parse()?;
    let key = u32::from_ne_bytes(ip.octets());
    if let Ok(mut guard) = st.blocklist.lock() {
        if let Some(map) = guard.as_mut() {
            if add { map.insert(key, 1u8, 0)?; } else { let _ = map.remove(&key); }
        }
    }
    if let Ok(mut list) = st.blocked_ips.lock() {
        if add && !list.contains(&ip.to_string()) { list.push(ip.to_string()); }
        if !add { list.retain(|x| x != &ip.to_string()); }
    }
    Ok(if add { format!("XDP_DROP armed for {ip}") } else { format!("Released {ip}") })
}

fn attach_xdp(iface: &str) -> (String, Option<Ebpf>, Option<BpfHashMap<MapData, u32, u8>>, Option<RingBuf<MapData>>) {
    unsafe {
        let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
        let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
    }
    let mut bpf = match Ebpf::load(XDP_ELF) {
        Ok(b) => b,
        Err(e) => return (format!("userspace_fallback (load: {e})"), None, None, None),
    };
    let mode = match bpf.program_mut("caprun_xdp").and_then(|p| TryInto::<&mut Xdp>::try_into(p).ok()) {
        Some(xdp) => match xdp.load() {
            Ok(()) => {
                if xdp.attach(iface, XdpFlags::default()).is_ok() {
                    format!("XDP_NATIVE attached to {iface}")
                } else {
                    match xdp.attach(iface, XdpFlags::SKB_MODE) {
                        Ok(_) => format!("XDP_SKB attached to {iface}"),
                        Err(e) => format!("userspace_fallback (attach: {e})"),
                    }
                }
            }
            Err(e) => format!("userspace_fallback (prog_load: {e})"),
        },
        None => "userspace_fallback (missing caprun_xdp)".into(),
    };
    let bl = bpf.take_map("BLOCKLIST").and_then(|m| BpfHashMap::try_from(m).ok());
    let ring = bpf.take_map("FLOW_RING").and_then(|m| RingBuf::try_from(m).ok());
    (mode, Some(bpf), bl, ring)
}

pub fn run_opsdeck(iface: String, port: u16, llm_url: String) -> Result<()> {
    let mut py_child = if std::path::Path::new("secsuite.py").exists() {
        let log = OpenOptions::new().create(true).append(true).open("/tmp/secsuite_8096.log").ok();
        let mut cmd = Command::new("python3");
        cmd.arg("./secsuite.py").env("SECSUITE_PORT", "8096");
        if let Some(f) = log {
            if let Ok(f2) = f.try_clone() { cmd.stdout(f).stderr(f2); }
        }
        cmd.spawn().ok()
    } else {
        None
    };

    let rt = tokio::runtime::Runtime::new()?;
    let res = rt.block_on(async move {
        let cortex = StdpCortex::new()?;
        let adapter = cortex.adapter_name.clone();
        let (frame_tx, _) = broadcast::channel(4);
        let (chrono_tx, _) = broadcast::channel(64);
        let (xdp_mode, ebpf_opt, bl_opt, ring_opt) = attach_xdp(&iface);
        let _keep_bpf = ebpf_opt;

        let spiderweb = Arc::new(Mutex::new(Spiderweb::new()));
        let http = reqwest::Client::builder().timeout(Duration::from_secs(60)).build().unwrap_or_default();

        let state = Arc::new(SharedState {
            cortex: Mutex::new(cortex),
            stims: Mutex::new(Vec::new()),
            events: Mutex::new(VecDeque::new()),
            blocklist: Mutex::new(bl_opt),
            blocked_ips: Mutex::new(Vec::new()),
            spiderweb: spiderweb.clone(),
            xdp_mode: xdp_mode.clone(),
            iface: iface.clone(),
            llm_url,
            http,
            frame_tx,
            chrono_tx,
            tls: crate::tls_decrypt::TlsKeyStore::new(),
        prism: crate::prism::PrismEngine::new(),
        vpn: crate::vpn::VpnManager::new(),
});

        // 1. Live AF_PACKET wire sniffer -> feeds BOTH Cortex 1 (STDP) and Cortex 2 (Chronovisor) + Spiderweb
        let st_sniff = state.clone();
        let sniffer_ok = crate::spiderweb::spawn_sniffer(spiderweb, move |msg, x, y, amp, line| {
            push_event(&st_sniff, msg, x, y, amp);
            let _ = st_sniff.chrono_tx.send(line);
        });

        // 2. Zero-copy eBPF RingBuf drainer
        if let Some(mut ring) = ring_opt {
            let st = state.clone();
            std::thread::spawn(move || loop {
                while let Some(item) = ring.next() {
                    if item.len() >= std::mem::size_of::<FlowEvent>() {
                        let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const FlowEvent) };
                        let src = Ipv4Addr::from(ev.src_ip.to_ne_bytes());
                        let x = (ev.src_ip ^ (ev.src_ip >> 16)) % 512;
                        let y = (ev.dst_port as u32) % 512;
                        let syn = if (ev.tcp_flags & 2) != 0 { "SYN " } else { "" };
                        push_event(&st, format!("XDP {syn}{src} -> :{} ({}B)", ev.dst_port, ev.pkt_len), x, y, 1.35);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            });
        }

        // 3. 30 FPS Persistent STDP VRAM Cortex ticker
        {
            let st = state.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_millis(33));
                loop {
                    iv.tick().await;
                    let batch: Vec<Stim> = st.stims.lock().map(|mut s| s.drain(..).collect()).unwrap_or_default();
                    let (rgba, us, surp, tick) = {
                        let mut c = st.cortex.lock().unwrap();
                        let (r, u, s) = c.step(&batch);
                        (r, u, s, c.tick)
                    };
                    let meta = format!(
                        "{adapter} | {} | wire={} | tick {tick} | {:.2} ms | surprise {surp}",
                        st.xdp_mode, if sniffer_ok { "LIVE" } else { "OFF" }, us as f64 / 1000.0
                    );
                    let _ = st.frame_tx.send((rgba, meta));
                }
            });
        }

        let app = Router::new()
            .route("/", get(|| async { Html(OPSDECK_HTML) }))
            .route("/ws/cortex", get(ws_cortex))
            .route("/ws/chrono", get(ws_chrono))
            .route("/ws/term", get(ws_term))
            .route("/api/status", get(api_status))
            .route("/api/xdp/block", post(api_xdp_block))
            .route("/api/xdp/unblock", post(api_xdp_unblock))
            .route("/api/stdp/save", post(api_stdp_save))
            .route("/api/stdp/load", post(api_stdp_load))
            .route("/api/stdp/diff", post(api_stdp_diff))
            .route("/api/ja4", post(api_ja4))
            .route("/api/soc/triage", post(api_soc_triage))
            .route("/api/llm/inspect", post(api_llm_inspect))
            .route("/api/spiderweb/flows", get(api_sw_flows))
            .route("/api/spiderweb/iptraf", get(api_sw_iptraf))
            .route("/api/spiderweb/reconstruct", post(api_sw_reconstruct))
            .route("/api/{*path}", get(proxy_get).post(proxy_post))
        .route("/api/tls/keylog", post(api_tls_keylog))
        .route("/api/tls/status", get(api_tls_status))
        .route("/api/prism/status", get(api_prism_status))
        .route("/api/prism/inspect", post(api_prism_inspect))
        .route("/api/prism/synthesize", post(api_prism_synthesize))
        .route("/api/prism/arm", post(api_prism_arm))
        .route("/api/prism/rollback", post(api_prism_rollback))
        .route("/api/vpn/status", get(api_vpn_status))
        .route("/api/vpn/import", post(api_vpn_import))
        .route("/api/vpn/delete", post(api_vpn_delete))
        .route("/api/vpn/connect", post(api_vpn_connect))
        .route("/api/vpn/disconnect", post(api_vpn_disconnect))
        .route("/api/vpn/qr", post(api_vpn_qr))
        .route("/api/vpn/exit_ip", get(api_vpn_exit_ip))
        .route("/api/vpn/killswitch", post(api_vpn_killswitch))
            .with_state(state);

        println!("caprun 10-tab OpsDeck ({xdp_mode} | wire_sniffer={sniffer_ok}) -> http://localhost:{port}");
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
        axum::serve(listener, app).await?;
        Ok(())
    });

    if let Some(ref mut ch) = py_child { let _ = ch.kill(); }
    res
}

async fn ws_cortex(ws: WebSocketUpgrade, State(st): State<Arc<SharedState>>) -> impl IntoResponse {
    ws.on_upgrade(move |mut sock: WebSocket| async move {
        let mut rx = st.frame_tx.subscribe();
        while let Ok((rgba, meta)) = rx.recv().await {
            if sock.send(Message::Binary(rgba.into())).await.is_err() { break; }
            if sock.send(Message::Text(meta.into())).await.is_err() { break; }
        }
    })
}

async fn ws_chrono(ws: WebSocketUpgrade, State(st): State<Arc<SharedState>>) -> impl IntoResponse {
    ws.on_upgrade(move |mut sock: WebSocket| async move {
        let mut rx = st.chrono_tx.subscribe();
        while let Ok(line) = rx.recv().await {
            if let Ok(txt) = serde_json::to_string(&line) {
                if sock.send(Message::Text(txt.into())).await.is_err() { break; }
            }
        }
    })
}


async fn api_sw_iptraf(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let snap = st.spiderweb.lock().unwrap().iptraf_snapshot();
    Json(serde_json::to_value(snap).unwrap_or_default())
}

async fn api_sw_flows(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let flows = st.spiderweb.lock().unwrap().list_flows();
    Json(serde_json::json!({ "count": flows.len(), "flows": flows }))
}

#[derive(Deserialize)] struct ReconReq { id: u64 }
async fn api_sw_reconstruct(State(st): State<Arc<SharedState>>, Json(r): Json<ReconReq>) -> Json<serde_json::Value> {
    match st.spiderweb.lock().unwrap().reconstruct_with_tls(r.id, &st.tls) {
        Some(rec) => Json(serde_json::json!({ "ok": true, "reconstruction": rec })),
        None => Json(serde_json::json!({ "ok": false, "error": "Flow expired or not found" })),
    }
}

async fn proxy_get(State(st): State<Arc<SharedState>>, Path(path): Path<String>, RawQuery(q): RawQuery) -> impl IntoResponse {
    let url = match q {
        Some(qs) => format!("{PY_BACKEND}/api/{path}?{qs}"),
        None => format!("{PY_BACKEND}/api/{path}"),
    };
    match st.http.get(&url).send().await {
        Ok(r) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], r.text().await.unwrap_or_else(|_| "{}".into())),
        Err(e) => (StatusCode::BAD_GATEWAY, [(header::CONTENT_TYPE, "application/json")], format!(r#"{{"ok":false,"error":"backend_offline: {e}"}}"#)),
    }
}

async fn proxy_post(State(st): State<Arc<SharedState>>, Path(path): Path<String>, body: Bytes) -> impl IntoResponse {
    let h = blake3::hash(path.as_bytes());
    let b = h.as_bytes();
    push_event(&st, format!("TOOL /api/{path}"), (b[0] as u32) * 2, (b[1] as u32) * 2, 1.6);
    let url = format!("{PY_BACKEND}/api/{path}");
    match st.http.post(&url).header("Content-Type", "application/json").body(body).send().await {
        Ok(r) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], r.text().await.unwrap_or_else(|_| "{}".into())),
        Err(e) => (StatusCode::BAD_GATEWAY, [(header::CONTENT_TYPE, "application/json")], format!(r#"{{"ok":false,"error":"backend_offline: {e}"}}"#)),
    }
}

async fn api_status(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let blocked = st.blocked_ips.lock().unwrap().clone();
    let recent: Vec<String> = st.events.lock().unwrap().iter().rev().take(8).cloned().collect();
    Json(serde_json::json!({ "iface": st.iface, "xdp_mode": st.xdp_mode, "blocked_ips": blocked, "recent_events": recent }))
}

#[derive(Deserialize)] struct IpReq { ip: String }
async fn api_xdp_block(State(st): State<Arc<SharedState>>, Json(r): Json<IpReq>) -> Json<serde_json::Value> {
    match arm_xdp_ip(&st, &r.ip, true) {
        Ok(m) => { push_event(&st, format!("SPIKE {m}"), 420, 443, 2.0); Json(serde_json::json!({"ok": true, "msg": m})) }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}
async fn api_xdp_unblock(State(st): State<Arc<SharedState>>, Json(r): Json<IpReq>) -> Json<serde_json::Value> {
    match arm_xdp_ip(&st, &r.ip, false) {
        Ok(m) => Json(serde_json::json!({"ok": true, "msg": m})),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

async fn api_stdp_save(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let res = st.cortex.lock().unwrap().save_baseline();
    Json(match res { Ok(m) => serde_json::json!({"ok": true, "msg": m}), Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}) })
}
async fn api_stdp_load(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let res = st.cortex.lock().unwrap().load_baseline();
    Json(match res { Ok(m) => serde_json::json!({"ok": true, "msg": m}), Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}) })
}
async fn api_stdp_diff(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let res = st.cortex.lock().unwrap().diff_baseline();
    Json(match res {
        Ok((max_d, drifted)) => serde_json::json!({"ok": true, "max_weight_delta": max_d, "drifted_neurons": drifted}),
        Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
    })
}

#[derive(Deserialize)] struct Ja4Req { ip: String, hex: Option<String> }
async fn api_ja4(State(st): State<Arc<SharedState>>, Json(r): Json<Ja4Req>) -> Json<serde_json::Value> {
    let sample: Vec<u8> = vec![
        0x16,0x03,0x01,0x00,0x41, 0x01,0x00,0x00,0x3d, 0x03,0x03,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
        0x00, 0x00,0x06, 0x13,0x01,0x13,0x02,0x13,0x03, 0x01,0x00,
        0x00,0x0e, 0x00,0x00,0x00,0x00, 0x00,0x2b,0x00,0x03,0x02,0x03,0x04,
    ];
    let bytes = r.hex.as_deref().filter(|h| !h.trim().is_empty()).and_then(|h| {
        let clean: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len()).step_by(2).map(|i| u8::from_str_radix(&clean[i..i+2], 16).ok()).collect::<Option<Vec<u8>>>()
    }).unwrap_or(sample);

    let fp = ja4::parse_client_hello(&bytes).unwrap_or_else(|| "invalid_client_hello".into());
    let ip_u32 = r.ip.parse::<Ipv4Addr>().map(|a| u32::from_ne_bytes(a.octets())).unwrap_or(0);
    let (x, y) = ja4::cortex_coord(ip_u32, &fp);
    push_event(&st, format!("JA4 {} -> {fp} @({x},{y})", r.ip), x, y, 1.8);
    Json(serde_json::json!({"ok": true, "ip": r.ip, "ja4": fp, "cortex_xy": [x, y]}))
}

#[derive(Deserialize)] struct SocReq { ip: String, enforce: Option<bool> }
async fn api_soc_triage(State(st): State<Arc<SharedState>>, Json(r): Json<SocReq>) -> Json<serde_json::Value> {
    let recent: Vec<String> = st.events.lock().unwrap().iter().cloned().collect();
    let verdict = soc_loop::triage(&st.llm_url, &recent, &r.ip).await;
    let mut enforced = None;
    if r.enforce.unwrap_or(false) && verdict.action == "block_ip" {
        enforced = arm_xdp_ip(&st, &verdict.ip, true).ok();
    }
    Json(serde_json::json!({ "verdict": verdict, "enforced": enforced }))
}

async fn ws_term(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(|mut sock: WebSocket| async move {
        let mut sess = match crate::pty_term::spawn_bash(72, 14) {
            Ok(s) => s,
            Err(e) => {
                let _ = sock.send(Message::Text(format!("PTY error: {e}\r\n").into())).await;
                return;
            }
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
        std::thread::spawn(move || crate::pty_term::read_loop(sess.master_read, tx));
        loop {
            tokio::select! {
                Some(out) = rx.recv() => {
                    if sock.send(Message::Text(out.into())).await.is_err() { break; }
                }
                msg = sock.recv() => {
                    match msg {
                        Some(Ok(Message::Text(t))) => {
                            if !crate::pty_term::write_all(&mut sess.master_write, t.as_bytes()) { break; }
                        }
                        Some(Ok(Message::Binary(b))) => {
                            if !crate::pty_term::write_all(&mut sess.master_write, &b) { break; }
                        }
                        _ => break,
                    }
                }
            }
        }
        let _ = sess.child.kill();
    })
}

#[derive(Deserialize)] struct LlmReq { context: String }
async fn api_llm_inspect(State(st): State<Arc<SharedState>>, Json(r): Json<LlmReq>) -> Json<serde_json::Value> {
    let body = serde_json::json!({
        "model": "local",
        "temperature": 0.2,
        "max_tokens": 220,
        "messages": [
            { "role": "system", "content": "You are an expert packet dissector. Explain what this packet is doing, any security risks, and what data it carries in 3 concise bullet points." },
            { "role": "user", "content": r.context }
        ]
    });
    match st.http.post(format!("{}/v1/chat/completions", st.llm_url.trim_end_matches('/'))).json(&body).send().await {
        Ok(resp) => {
            let v = resp.json::<serde_json::Value>().await.unwrap_or_default();
            let reply = v["choices"][0]["message"]["content"].as_str().unwrap_or("Empty LLM response").to_string();
            Json(serde_json::json!({ "ok": true, "source": "llama.cpp", "reply": reply }))
        }
        Err(e) => Json(serde_json::json!({ "ok": false, "error": format!("llama-server offline on {}: {e}", st.llm_url) })),
    }
}

#[derive(Deserialize)]
struct KeylogUploadReq {
    mode: String,          // "path" | "keylog_text" | "pcap_b64" | "raw_decrypt"
    path: Option<String>,
    content: Option<String>,
    secret_hex: Option<String>,
    cipher: Option<String>,
}

async fn api_tls_status(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    st.tls.refresh_from_disk();
    let (sessions, keys, path) = st.tls.stats();
    Json(serde_json::json!({ "ok": true, "sessions": sessions, "keys": keys, "keylog_path": path }))
}

async fn api_tls_keylog(State(st): State<Arc<SharedState>>, Json(r): Json<KeylogUploadReq>) -> Json<serde_json::Value> {
    match r.mode.as_str() {
        "path" => {
            let p = r.path.unwrap_or_default();
            match st.tls.load_keylog_file(&p) {
                Ok(added) => {
                    let (sessions, keys, _) = st.tls.stats();
                    Json(serde_json::json!({ "ok": true, "added": added, "sessions": sessions, "keys": keys, "watching": p }))
                }
                Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
            }
        }
        "keylog_text" => {
            let txt = r.content.unwrap_or_default();
            let added = st.tls.load_keylog_text(&txt);
            let (sessions, keys, _) = st.tls.stats();
            Json(serde_json::json!({ "ok": true, "added": added, "sessions": sessions, "keys": keys }))
        }
        "pcap_b64" => {
            let raw = b64_decode_simple(r.content.as_deref().unwrap_or(""));
            match crate::tls_decrypt::parse_pcap_payloads(&raw) {
                Ok(pkts) => {
                    let mut combined = Vec::new();
                    for pkt in &pkts {
                        combined.extend_from_slice(pkt);
                    }
                    let decrypted = st.tls.try_decrypt_stream(&combined, &combined);
                    let (sessions, keys, _) = st.tls.stats();
                    if let Some((info, plain)) = decrypted {
                        Json(serde_json::json!({
                            "ok": true,
                            "packets": pkts.len(),
                            "sessions": sessions,
                            "keys": keys,
                            "cipher": info,
                            "plaintext": String::from_utf8_lossy(&plain)
                        }))
                    } else {
                        Json(serde_json::json!({
                            "ok": true,
                            "packets": pkts.len(),
                            "sessions": sessions,
                            "keys": keys,
                            "plaintext": format!("Parsed {} TCP payloads from PCAP ({} bytes). Load matching SSLKEYLOGFILE keys to decrypt TLS 1.3 records.", pkts.len(), combined.len())
                        }))
                    }
                }
                Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
            }
        }
        _ => Json(serde_json::json!({ "ok": false, "error": "unknown mode" })),
    }
}

fn b64_decode_simple(input: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u8;
    for b in input.bytes() {
        if b == b'=' { break; }
        if let Some(pos) = T.iter().position(|&c| c == b) {
            buf = (buf << 6) | (pos as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xff) as u8);
            }
        }
    }
    out
}



#[derive(Deserialize)]
struct PrismInspectReq {
    flow_id: u64,
    proto: String,
    src: String,
    dst: String,
}

#[derive(Deserialize)]
struct PrismRuleToggleReq {
    id: u64,
}

async fn api_prism_status(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let snaps = st.spiderweb.lock().unwrap().prism_snapshots();
    st.prism.ingest_snapshots(&snaps);
    let (flows, shadow, armed) = st.prism.summary_stats();
    Json(serde_json::json!({
        "ok": true,
        "tracked_flows": flows,
        "shadow_rules": shadow,
        "armed_rules": armed,
        "rules": st.prism.list_rules()
    }))
}

async fn api_prism_inspect(State(st): State<Arc<SharedState>>, Json(r): Json<PrismInspectReq>) -> Json<serde_json::Value> {
    let snaps = st.spiderweb.lock().unwrap().prism_snapshots();
    st.prism.ingest_snapshots(&snaps);
    let dna = st.prism.inspect_flow(r.flow_id, &r.proto, &r.src, &r.dst);
    Json(serde_json::json!({ "ok": true, "dna": dna, "rules": st.prism.list_rules() }))
}

async fn api_prism_synthesize(State(st): State<Arc<SharedState>>, Json(r): Json<PrismInspectReq>) -> Json<serde_json::Value> {
    let snaps = st.spiderweb.lock().unwrap().prism_snapshots();
    st.prism.ingest_snapshots(&snaps);
    let dna = st.prism.inspect_flow(r.flow_id, &r.proto, &r.src, &r.dst);

    let dst_ip = r.dst.split(':').next().unwrap_or(&r.dst).to_string();
    let dst_port = r.dst.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
    let pid = dna.lineage.as_ref().map(|l| l.pid);

    let prompt = format!(
        "Flow {} {}->{} | Score={}/100 ({}) | IAT={}ms CV={} PAPR={} | Lineage={:?}. Recommend one containment action (XDP_DROP_TUPLE, FREEZE_PID, RATE_LIMIT, or PCAP_RECORD) and a 1-sentence reason.",
        dna.proto, dna.src, dna.dst, dna.beacon_score, dna.classification,
        dna.mean_iat_ms, dna.jitter_cv, dna.dft_papr, dna.lineage.as_ref().map(|l| &l.parent_chain)
    );

    let body = serde_json::json!({
        "model": "local",
        "temperature": 0.1,
        "max_tokens": 120,
        "messages": [
            { "role": "system", "content": "You are Prism, a Linux NDR/EDR policy synthesizer. Reply concisely with the recommended action name and a brief justification." },
            { "role": "user", "content": prompt }
        ]
    });

    let llm_reason = match st.http.post(format!("{}/v1/chat/completions", st.llm_url.trim_end_matches('/'))).json(&body).send().await {
        Ok(resp) => {
            let v = resp.json::<serde_json::Value>().await.unwrap_or_default();
            v["choices"][0]["message"]["content"].as_str().unwrap_or("Spectral/lineage threshold review").to_string()
        }
        Err(_) => format!("Heuristic Shadow Rule: {} (score {}/100)", dna.classification, dna.beacon_score),
    };

    let action = if llm_reason.contains("FREEZE_PID") && pid.is_some() {
        "FREEZE_PID"
    } else if llm_reason.contains("XDP_DROP_TUPLE") {
        "XDP_DROP_TUPLE"
    } else if llm_reason.contains("RATE_LIMIT") {
        "RATE_LIMIT"
    } else {
        "PCAP_RECORD"
    };

    let rule = st.prism.add_shadow_rule(action.into(), dst_ip, dst_port, pid, llm_reason);
    Json(serde_json::json!({ "ok": true, "rule": rule, "dna": dna, "rules": st.prism.list_rules() }))
}

async fn api_prism_arm(State(st): State<Arc<SharedState>>, Json(r): Json<PrismRuleToggleReq>) -> Json<serde_json::Value> {
    match st.prism.set_rule_mode(r.id, true) {
        Ok(rule) => Json(serde_json::json!({ "ok": true, "rule": rule, "rules": st.prism.list_rules() })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

async fn api_prism_rollback(State(st): State<Arc<SharedState>>, Json(r): Json<PrismRuleToggleReq>) -> Json<serde_json::Value> {
    match st.prism.set_rule_mode(r.id, false) {
        Ok(rule) => Json(serde_json::json!({ "ok": true, "rule": rule, "rules": st.prism.list_rules() })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize)]
struct VpnImportReq {
    name: String,
    content: String,
}

#[derive(Deserialize)]
struct VpnNameReq {
    name: String,
}

#[derive(Deserialize)]
struct VpnQrReq {
    mode: String, // "profile" | "mobile_peer"
    name: Option<String>,
    server_endpoint: Option<String>,
    server_pubkey: Option<String>,
    client_addr: Option<String>,
    dns: Option<String>,
}

#[derive(Deserialize)]
struct VpnKillSwitchReq {
    enabled: bool,
}

async fn api_vpn_status(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    Json(serde_json::to_value(st.vpn.status()).unwrap_or_default())
}

async fn api_vpn_import(State(st): State<Arc<SharedState>>, Json(r): Json<VpnImportReq>) -> Json<serde_json::Value> {
    match st.vpn.save_profile(&r.name, &r.content) {
        Ok(prof) => Json(serde_json::json!({ "ok": true, "profile": prof, "status": st.vpn.status() })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

async fn api_vpn_delete(State(st): State<Arc<SharedState>>, Json(r): Json<VpnNameReq>) -> Json<serde_json::Value> {
    match st.vpn.delete_profile(&r.name) {
        Ok(()) => Json(serde_json::json!({ "ok": true, "status": st.vpn.status() })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

async fn api_vpn_connect(State(st): State<Arc<SharedState>>, Json(r): Json<VpnNameReq>) -> Json<serde_json::Value> {
    let vpn = st.vpn.clone();
    let name = r.name.clone();
    let res = tokio::task::spawn_blocking(move || vpn.connect(&name))
        .await
        .unwrap_or_else(|e| Err(format!("Join error: {e}")));
    match res {
        Ok(msg) => Json(serde_json::json!({ "ok": true, "output": msg, "status": st.vpn.status() })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e, "status": st.vpn.status() })),
    }
}

async fn api_vpn_disconnect(State(st): State<Arc<SharedState>>, Json(r): Json<VpnNameReq>) -> Json<serde_json::Value> {
    let vpn = st.vpn.clone();
    let name = r.name.clone();
    let res = tokio::task::spawn_blocking(move || vpn.disconnect(&name))
        .await
        .unwrap_or_else(|e| Err(format!("Join error: {e}")));
    match res {
        Ok(msg) => Json(serde_json::json!({ "ok": true, "output": msg, "status": st.vpn.status() })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e, "status": st.vpn.status() })),
    }
}

async fn api_vpn_qr(State(st): State<Arc<SharedState>>, Json(r): Json<VpnQrReq>) -> Json<serde_json::Value> {
    let res = match r.mode.as_str() {
        "profile" => st.vpn.qr_for_profile(r.name.as_deref().unwrap_or("")),
        "mobile_peer" => st.vpn.generate_mobile_peer(
            r.server_endpoint.as_deref().unwrap_or(""),
            r.server_pubkey.as_deref().unwrap_or(""),
            r.client_addr.as_deref().unwrap_or("10.99.0.2/32"),
            r.dns.as_deref().unwrap_or("1.1.1.1"),
        ),
        _ => Err("Unknown QR mode (expected 'profile' or 'mobile_peer')".into()),
    };
    match res {
        Ok(qr) => Json(serde_json::to_value(qr).unwrap_or_default()),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

async fn api_vpn_exit_ip(State(st): State<Arc<SharedState>>) -> Json<serde_json::Value> {
    let req = st
        .http
        .get("https://api.ipify.org?format=json")
        .timeout(std::time::Duration::from_secs(4))
        .send()
        .await;
    match req {
        Ok(resp) => {
            let v = resp.json::<serde_json::Value>().await.unwrap_or_default();
            Json(serde_json::json!({ "ok": true, "ip": v["ip"].as_str().unwrap_or("unknown") }))
        }
        Err(e) => Json(serde_json::json!({ "ok": false, "error": format!("Exit IP lookup failed: {e}") })),
    }
}

async fn api_vpn_killswitch(State(st): State<Arc<SharedState>>, Json(r): Json<VpnKillSwitchReq>) -> Json<serde_json::Value> {
    let enabled = st.vpn.set_kill_switch(r.enabled);
    Json(serde_json::json!({ "ok": true, "kill_switch": enabled, "status": st.vpn.status() }))
}
