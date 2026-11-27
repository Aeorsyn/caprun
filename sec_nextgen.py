#!/usr/bin/env python3
import collections, math, socket, time
import cortex, sec_engine

FREQ_TOP = set(b"etaoinshrdlcumwfgypb ETAOINSHRDLU0123456789/:._-")

def _wgsl_run(elements, seed, iters, wgsl):
    msg = f"WGSL:{elements}:{seed}:{iters}:{wgsl.encode().hex()}\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(cortex.SOCK)
        s.sendall(msg)
        buf = b""
        while not buf.endswith(b"\n"):
            ch = s.recv(4096)
            if not ch: break
            buf += ch
    reply = buf.decode(errors="replace").strip()
    if not reply.startswith("OK:"):
        raise RuntimeError(reply)
    _, cs, us, adapter = reply.split(":", 3)
    return cs, int(us), adapter

def _shannon(data):
    if not data: return 0.0
    n = len(data)
    cnt = collections.Counter(data)
    return round(-sum((c / n) * math.log2(c / n) for c in cnt.values()), 3)

def gpu_xor_entropy(payload_str, push_fn):
    s = (payload_str or "").strip()
    if s.lower().startswith("hex:"):
        raw = bytes.fromhex(s[4:].replace(" ", ""))
    else:
        try:
            clean = s.replace(" ", "")
            raw = bytes.fromhex(clean) if (len(clean) >= 8 and len(clean) % 2 == 0) else s.encode()
        except ValueError:
            raw = s.encode()
    sample = raw[:128] or b"\x00"
    n = len(sample)
    arr = ",".join(f"{b}u" for b in sample)
    wgsl = f"""struct Params {{ seed: u32, count: u32, iters: u32, _pad: u32 }};
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {{
    let k = gid.x;
    if (k >= params.count) {{ return; }}
    var buf = array<u32, {n}>({arr});
    var score = 0.0;
    for (var i = 0u; i < {n}u; i = i + 1u) {{
        let b = buf[i] ^ (k & 255u);
        if ((b >= 97u && b <= 122u) || b == 32u || b == 47u || b == 58u) {{ score += 2.0; }}
        else if (b >= 32u && b <= 126u) {{ score += 0.8; }}
        else {{ score -= 2.5; }}
    }}
    out_buf[k] = score / f32({n}u);
}}"""
    _, us, adapter = _wgsl_run(256, 0, n, wgsl)
    ent = _shannon(raw)
    cands = []
    for k in range(256):
        dec = bytes(b ^ k for b in sample)
        sc = sum(2 if b in FREQ_TOP else (0.5 if 32 <= b <= 126 else -3) for b in dec) / n
        cands.append((round(sc, 2), k, dec.decode("ascii", errors="replace")))
    cands.sort(reverse=True)
    best_sc, best_k, best_txt = cands[0]
    verdict = "PACKED_OR_ENCRYPTED" if ent >= 7.0 else ("XOR_OBFUSCATED" if best_k != 0 and best_sc > 1.1 else "CLEARTEXT_OR_BENIGN")
    hex_sig = " ".join(f"{b:02X}" for b in sample[:16])
    yara = f'rule caprun_xor_{best_k:02x} {{\n  meta: verdict = "{verdict}"\n  strings: $s = {{ {hex_sig} }}\n  condition: $s\n}}'
    if verdict != "CLEARTEXT_OR_BENIGN":
        for i in range(4): push_fn(f"10.99.{best_k}.{i}", 4444 + i * 20, f"NG_XOR {verdict} k=0x{best_k:02x}")
    sec_engine.log_delta("silicon_lab", "gpu_xor_entropy", f"{verdict}_H{ent}_k{best_k:02x}", us)
    return {
        "adapter": adapter, "gpu_ms": round(us / 1000.0, 2), "bytes": len(raw),
        "shannon_entropy": ent, "verdict": verdict,
        "top_keys": [{"key_hex": f"0x{k:02x}", "score": sc, "preview": txt[:64]} for sc, k, txt in cands[:3]],
        "yara_rule": yara,
    }
def gpu_beacon_hunt(ts_csv, target_ip, push_fn):
    pts = [float(x.strip()) for x in (ts_csv or "").split(",") if x.strip()]
    if len(pts) < 4:
        return {"ok": False, "error": "Provide at least 4 comma-separated timestamps."}
    pts.sort()
    dts = [max(0.01, pts[i + 1] - pts[i]) for i in range(len(pts) - 1)][:64]
    n = len(dts)
    arr = ",".join(f"{d:.3f}" for d in dts)
    wgsl = f"""struct Params {{ seed: u32, count: u32, iters: u32, _pad: u32 }};
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {{
    let tid = gid.x;
    if (tid >= params.count) {{ return; }}
    var dts = array<f32, {n}>({arr});
    let cand_p = f32(tid + 1u);
    var err = 0.0;
    for (var i = 0u; i < {n}u; i = i + 1u) {{
        err += abs(dts[i] - cand_p) / max(1.0, cand_p);
    }}
    out_buf[tid] = 1.0 / (1.0 + err / f32({n}u));
}}"""
    _, us, adapter = _wgsl_run(256, 0, n, wgsl)
    mean_dt = sum(dts) / n
    jitter_pct = round((sum(abs(d - mean_dt) for d in dts) / n) / max(0.01, mean_dt) * 100.0, 2)
    is_beacon = jitter_pct <= 25.0
    ip = (target_ip or "203.0.113.42").strip()
    if is_beacon:
        for i in range(5): push_fn(ip, 443 + i * 16, f"C2_BEACON {ip} T={mean_dt:.1f}s jit={jitter_pct}%")
    sec_engine.log_delta("silicon_lab", "gpu_beacon_hunt", f"{ip}_T{mean_dt:.1f}s_J{jitter_pct}", us)
    return {
        "ok": True, "adapter": adapter, "gpu_ms": round(us / 1000.0, 2),
        "target_ip": ip, "intervals": n, "dominant_period_sec": round(mean_dt, 2),
        "jitter_pct": jitter_pct, "verdict": "C2_BEACON_DETECTED" if is_beacon else "APERIODIC_HUMAN",
        "suricata_rule": f'alert ip any any -> {ip} any (msg:"CAPRUN C2 Beacon T={mean_dt:.0f}s"; threshold:type both, track by_src, count 4, seconds {int(mean_dt * 5)}; sid:990001; rev:1;)',
        "nft_rule": f"sudo nft add rule inet filter output ip daddr {ip} counter drop",
    }

def gpu_dga_tunnel(domains_str, push_fn):
    doms = [d.strip().lower() for d in (domains_str or "").replace(",", "\n").splitlines() if d.strip()][:64]
    if not doms:
        return {"ok": False, "error": "Provide at least one domain."}
    flat = [ord(c) for d in doms for c in d[:32]][:512] or [97]
    n = len(flat)
    arr = ",".join(f"{b}u" for b in flat)
    wgsl = f"""struct Params {{ seed: u32, count: u32, iters: u32, _pad: u32 }};
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {{
    let tid = gid.x;
    if (tid >= params.count) {{ return; }}
    var ch = array<u32, {n}>({arr});
    let b = ch[tid % {n}u];
    let is_v = select(0.0, 1.0, b == 97u || b == 101u || b == 105u || b == 111u || b == 117u);
    let is_d = select(0.0, 1.0, b >= 48u && b <= 57u);
    out_buf[tid] = is_d * 2.0 - is_v;
}}"""
    _, us, adapter = _wgsl_run(max(64, n), 0, len(doms), wgsl)
    rows, sinkholes = [], []
    for d in doms:
        lbl = d.split(".")[0]
        ent = _shannon(lbl.encode())
        v_rat = sum(1 for c in lbl if c in "aeiou") / max(1, len(lbl))
        d_rat = sum(1 for c in lbl if c.isdigit()) / max(1, len(lbl))
        if len(lbl) >= 20 and ent >= 3.4:
            cls = "DNS_TUNNEL"
        elif ent >= 3.3 and (v_rat < 0.22 or d_rat > 0.28):
            cls = "DGA_MALWARE"
        else:
            cls = "CLEAN"
        if cls != "CLEAN":
            push_fn(d, 53, f"NG_DNS {cls} {d[:28]}")
            sinkholes.append(f"address=/{d}/0.0.0.0")
        rows.append({"domain": d, "label_len": len(lbl), "entropy": ent, "vowel_pct": round(v_rat * 100, 1), "verdict": cls})
    sec_engine.log_delta("silicon_lab", "gpu_dga_tunnel", f"flagged_{len(sinkholes)}_of_{len(doms)}", us)
    return {
        "ok": True, "adapter": adapter, "gpu_ms": round(us / 1000.0, 2),
        "results": rows, "dnsmasq_sinkhole": "\n".join(sinkholes) or "# All tested domains clean.",
    }
