#!/usr/bin/env python3
import hashlib, json, os, socket, sqlite3, subprocess, sys, time, urllib.request

LLAMA_URL = os.environ.get("LLAMA_URL", "http://127.0.0.1:8080/v1/chat/completions")
CAS_DIR = os.path.expanduser("~/.cas")
SOCK_PATH = os.path.join(CAS_DIR, "vulkan.sock")
DB_PATH = os.path.join(CAS_DIR, "graph.db")
BIN = os.path.expanduser("~/caprun/target/release/caprun")

PRESETS = {
    "mandelbrot": """struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let x = f32(idx % 512u) / 512.0 * 3.0 - 2.0;
    let y = f32(idx / 512u) / 512.0 * 2.4 - 1.2;
    var zr = 0.0; var zi = 0.0; var k = 0u;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        let nr = zr * zr - zi * zi + x; zi = 2.0 * zr * zi + y; zr = nr;
        if (zr * zr + zi * zi > 4.0) { break; } k = k + 1u;
    }
    out_buf[idx] = f32(k);
}""",
    "sine_wave": """struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    var acc = 0.0; let phase = f32(params.seed) * 0.01;
    let base = f32(idx) * 0.0005;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        acc = acc + sin(base + f32(i) * 0.1 + phase) * cos(base * 2.0 - phase);
    }
    out_buf[idx] = acc;
}""",
    "collatz": """struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    var n = idx + params.seed + 1u; var steps = 0u;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        if (n <= 1u) { break; }
        if ((n & 1u) == 0u) { n = n >> 1u; } else { n = 3u * n + 1u; }
        steps = steps + 1u;
    }
    out_buf[idx] = f32(steps);
}""",
}

SYSTEM_PROMPT = """You are the WGSL intent compiler for caprun (a Vulkan capability broker).
Return STRICT JSON with keys:
- "action": "wgsl" | "graph"
- "name": short snake_case label (max 18 chars)
- "preset": null OR one of "mandelbrot", "sine_wave", "collatz"
- "wgsl": complete WGSL compute shader string (required if preset is null)
- "elements": integer (1..1048576, default 262144)
- "iters": integer (1..4096, default 128)
- "seed": integer (default 42)
WGSL ABI RULES (must match exactly):
struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) { ... }
Return ONLY valid JSON."""
def ask_llama(messages):
    payload = json.dumps({
        "model": "local",
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": messages,
    }).encode()
    req = urllib.request.Request(
        LLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        data = json.loads(r.read().decode())
    return json.loads(data["choices"][0]["message"]["content"])

def fallback_plan(goal):
    g = goal.lower()
    if any(k in g for k in ("graph", "history", "audit", "show")):
        return {"action": "graph"}
    if any(k in g for k in ("collatz", "hailstone", "3n+1")):
        return {"action": "wgsl", "name": "llm_collatz", "preset": "collatz", "elements": 262144, "iters": 256, "seed": 42}
    if any(k in g for k in ("sine", "wave", "trig", "interference", "audio")):
        return {"action": "wgsl", "name": "llm_sine_wave", "preset": "sine_wave", "elements": 262144, "iters": 128, "seed": 42}
    return {"action": "wgsl", "name": "llm_mandelbrot", "preset": "mandelbrot", "elements": 262144, "iters": 128, "seed": 42}

def dispatch_wgsl(wgsl, elements, seed, iters):
    if not os.path.exists(SOCK_PATH):
        raise RuntimeError(f"Warm broker socket missing at {SOCK_PATH}. Run: ./target/release/caprun broker &")
    msg = f"WGSL:{elements}:{seed}:{iters}:{wgsl.encode('utf-8').hex()}\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK_PATH)
        s.sendall(msg)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk: break
            buf += chunk
    reply = buf.decode(errors="replace").strip()
    if reply.startswith("OK:"):
        _, cs, us, adapter = reply.split(":", 3)
        return True, (int(cs), int(us), adapter)
    return False, reply

def commit_graph(wgsl, name, cs, us):
    h = hashlib.sha256(wgsl.encode("utf-8")).hexdigest()
    os.makedirs(os.path.join(CAS_DIR, "blobs"), exist_ok=True)
    blob = os.path.join(CAS_DIR, "blobs", h)
    if not os.path.exists(blob):
        open(blob, "w", encoding="utf-8").write(wgsl)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO semantic_deltas (ts_unix, capability_hash, entity, relation, value, latency_us) VALUES (?, ?, ?, ?, ?, ?)",
        (int(time.time()), h, name[:20], "llm_wgsl_vulkan", f"cs_{cs}", us),
    )
    conn.commit()
    conn.close()
    return h[:12]

def main():
    goal = " ".join(sys.argv[1:]).strip()
    if not goal:
        print('Usage: ./intent.py "compute a sine wave interference pattern on the GPU"')
        sys.exit(1)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": goal}]
    used_llm = False
    try:
        plan = ask_llama(messages)
        used_llm = True
        print(f"[intent] Synthesized by local llama-server ({LLAMA_URL})")
    except Exception as e:
        print(f"[intent] llama-server offline ({type(e).__name__}) -> offline WGSL router")
        plan = fallback_plan(goal)

    if plan.get("action") == "graph":
        subprocess.run([BIN, "graph", "--limit", "10"], check=False)
        return

    name = str(plan.get("name") or "llm_wgsl_job")
    preset = plan.get("preset")
    wgsl = PRESETS.get(preset) if preset in PRESETS else (plan.get("wgsl") or PRESETS["mandelbrot"])
    elements = max(1, min(1048576, int(plan.get("elements", 262144))))
    iters = max(1, min(8192, int(plan.get("iters", 128))))
    seed = int(plan.get("seed", 42))

    ok, res = dispatch_wgsl(wgsl, elements, seed, iters)
    if not ok and used_llm:
        print(f"[intent] Broker rejected shader: {res}")
        print("[intent] Feeding wgpu error back to llama-server for 1-shot repair...")
        messages.append({"role": "assistant", "content": json.dumps(plan)})
        messages.append({"role": "user", "content": f"Broker rejected WGSL with: {res}. Fix the WGSL and return valid JSON."})
        plan = ask_llama(messages)
        wgsl = plan.get("wgsl") or PRESETS["mandelbrot"]
        ok, res = dispatch_wgsl(wgsl, elements, seed, iters)

    if not ok:
        print(f"[intent] FAILED: {res}")
        sys.exit(1)

    cs, us, adapter = res
    short_h = commit_graph(wgsl, name, cs, us)
    print(f"[vulkan-broker:WARM] {adapter} | {elements} threads x {iters} iters in {us/1000:.2f} ms | checksum={cs}")
    print(f"[graph] Committed {short_h} ({name} --[llm_wgsl_vulkan]--> cs_{cs})")

if __name__ == "__main__":
    main()
