#!/usr/bin/env python3
import hashlib, json, os, socket, sqlite3, subprocess, sys, time

CAS_DIR = os.path.expanduser("~/.cas")
SOCK_PATH = os.path.join(CAS_DIR, "vulkan.sock")
DB_PATH = os.path.join(CAS_DIR, "graph.db")
BIN = os.path.expanduser("~/caprun/target/release/caprun")
SERVER_INFO = {"name": "caprun-mcp", "version": "0.1.0"}

TOOLS = [
    {
        "name": "run_wgsl_gpu",
        "description": "Validate and run a WGSL compute shader on caprun's warm Vulkan broker. ABI: struct Params { seed: u32, count: u32, iters: u32, _pad: u32 }; @binding(0) out_buf: array<f32>; @binding(1) params: Params; @compute @workgroup_size(64) fn main.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "wgsl": {"type": "string"},
                "elements": {"type": "integer", "default": 262144},
                "iters": {"type": "integer", "default": 128},
                "seed": {"type": "integer", "default": 42},
            },
            "required": ["wgsl"],
        },
    },
    {
        "name": "bench_gpu",
        "description": "Run caprun's FP32 TFLOPS Vulkan benchmark.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "iters": {"type": "integer", "default": 4096},
                "runs": {"type": "integer", "default": 3},
            },
        },
    },
    {
        "name": "query_graph",
        "description": "Read recent provenance deltas from ~/.cas/graph.db.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 10}},
        },
    },
]
def run_wgsl_gpu(args):
    wgsl = str(args.get("wgsl", ""))
    name = str(args.get("name", "mcp_wgsl_job"))[:20]
    elements = max(1, min(1048576, int(args.get("elements", 262144))))
    iters = max(1, min(65536, int(args.get("iters", 128))))
    seed = int(args.get("seed", 42)) & 0xFFFFFFFF
    if not os.path.exists(SOCK_PATH):
        return True, f"Broker socket missing at {SOCK_PATH}. Start: {BIN} broker &"
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
    if not reply.startswith("OK:"):
        return True, f"Vulkan broker rejected shader: {reply}"
    _, cs, us, adapter = reply.split(":", 3)
    h = hashlib.sha256(wgsl.encode("utf-8")).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO semantic_deltas (ts_unix, capability_hash, entity, relation, value, latency_us) VALUES (?,?,?,?,?,?)",
        (int(time.time()), h, name, "mcp_wgsl_vulkan", f"cs_{cs}", int(us)),
    )
    conn.commit()
    conn.close()
    return False, json.dumps({
        "status": "ok", "adapter": adapter, "elements": elements,
        "iters": iters, "latency_ms": round(int(us) / 1000.0, 2),
        "checksum": int(cs), "sha256": h[:16], "graph_entity": name,
    })

def call_tool(name, args):
    if name == "run_wgsl_gpu":
        return run_wgsl_gpu(args)
    if name == "bench_gpu":
        it = str(max(1, min(65536, int(args.get("iters", 4096)))))
        rn = str(max(1, min(10, int(args.get("runs", 3)))))
        p = subprocess.run([BIN, "bench-gpu", "--iters", it, "--runs", rn], capture_output=True, text=True)
        return p.returncode != 0, (p.stdout + p.stderr).strip()
    if name == "query_graph":
        lim = str(max(1, min(50, int(args.get("limit", 10)))))
        p = subprocess.run([BIN, "graph", "--limit", lim], capture_output=True, text=True)
        return p.returncode != 0, (p.stdout + p.stderr).strip()
    return True, f"Unknown tool: {name}"
def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def main():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw: continue
        try:
            req = json.loads(raw)
        except Exception:
            continue
        mid, method = req.get("id"), req.get("method")
        if method == "server/discover":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "resultType": "complete",
                "protocolVersions": ["2026-07-28", "2025-11-25", "2024-11-05"],
                "capabilities": {"tools": {}},
                "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
            }})
        elif method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            }})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"resultType": "complete", "tools": TOOLS}})
        elif method == "tools/call":
            p = req.get("params") or {}
            is_err, text = call_tool(p.get("name", ""), p.get("arguments") or {})
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "resultType": "complete",
                "content": [{"type": "text", "text": text}],
                "isError": is_err,
            }})
        elif mid is not None:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}})

if __name__ == "__main__":
    main()
