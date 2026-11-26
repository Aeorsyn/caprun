#!/usr/bin/env python3
import concurrent.futures, hashlib, os, socket, sqlite3, time
import cortex

HASH_WGSL = """struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= params.count) { return; }
    var h = (i ^ params.seed) * 2654435761u;
    for (var k = 0u; k < params.iters; k = k + 1u) {
        h = ((h << 13u) ^ h) * 1597334677u;
        h = h ^ (h >> 17u);
    }
    out_buf[i] = f32(h & 65535u) / 65535.0;
}"""

def log_delta(entity, relation, value, us, tag="secsuite"):
    os.makedirs(os.path.dirname(cortex.DB_PATH), exist_ok=True)
    h = hashlib.sha256(f"{tag}:{entity}:{value}".encode()).hexdigest()
    conn = sqlite3.connect(cortex.DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS semantic_deltas (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts_unix INTEGER NOT NULL,
        capability_hash TEXT NOT NULL, entity TEXT NOT NULL,
        relation TEXT NOT NULL, value TEXT NOT NULL, latency_us INTEGER NOT NULL)""")
    conn.execute(
        "INSERT INTO semantic_deltas (ts_unix, capability_hash, entity, relation, value, latency_us) VALUES (?,?,?,?,?,?)",
        (int(time.time()), h, entity[:24], relation[:24], value[:48], int(us)),
    )
    conn.commit()
    conn.close()

def get_graph(limit=30):
    if not os.path.exists(cortex.DB_PATH): return []
    conn = sqlite3.connect(cortex.DB_PATH)
    rows = conn.execute(
        "SELECT id, ts_unix, capability_hash, entity, relation, value, latency_us FROM semantic_deltas ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "ts": r[1], "hash": r[2][:12], "entity": r[3],
         "relation": r[4], "value": r[5], "ms": round(r[6] / 1000.0, 2)}
        for r in rows
    ]
def parse_ports(spec):
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                for p in range(max(1, int(a)), min(65535, int(b)) + 1):
                    out.add(p)
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535: out.add(p)
    return sorted(out)[:2048]

def probe_port(host, port):
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=0.35) as s:
            s.settimeout(0.35)
            banner = ""
            try:
                if port in (80, 443, 8000, 8080, 8088, 8090, 8095, 8443, 3000, 5000):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = s.recv(512)
                banner = data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            ms = round((time.perf_counter() - t0) * 1000.0, 2)
            notes = []
            low = banner.lower()
            if "http/" in low:
                for hdr in ("strict-transport-security", "content-security-policy", "x-frame-options"):
                    if hdr not in low: notes.append("no-" + hdr.split("-")[0])
            first = banner.splitlines()[0][:64] if banner else "open (no banner)"
            return {"port": port, "ms": ms, "banner": first, "notes": ", ".join(notes) or "ok"}
    except Exception:
        return None

def scan_target(host, port_spec, push_fn):
    ports = parse_ports(port_spec)
    t0 = time.perf_counter()
    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for res in ex.map(lambda p: probe_port(host, p), ports):
            if res:
                hits.append(res)
                push_fn(host, res["port"], f"SCAN {host}:{res['port']} {res['banner'][:24]}")
    hits.sort(key=lambda x: x["port"])
    us = int((time.perf_counter() - t0) * 1_000_000)
    log_delta("secsuite_recon", "port_scan", f"{host}_open_{len(hits)}_of_{len(ports)}", us)
    return {"host": host, "scanned": len(ports), "elapsed_ms": round(us / 1000.0, 1), "open": hits}

def gpu_wgsl_audit(elements=262144, iters=512, seed=42, poison=False):
    wgsl = "invalid_wgsl_payload { @crash_broker }" if poison else HASH_WGSL
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
        log_delta("secsuite_sandbox", "wgsl_rejected", reply[:42], 1000)
        return {"ok": False, "rejected": True, "message": reply}
    _, cs, us, adapter = reply.split(":", 3)
    us_i = max(1, int(us))
    m_hashes = round((elements * iters) / us_i, 2)
    log_delta("secsuite_gpu", "wgsl_keyspace", f"{m_hashes}MHps_cs_{cs}", us_i)
    return {"ok": True, "adapter": adapter, "ms": round(us_i / 1000.0, 2),
            "m_hashes_sec": m_hashes, "checksum": cs, "elements": elements, "iters": iters}
