#!/usr/bin/env python3
import collections, http.server, json, re, socket, subprocess, sys, threading, time, urllib.parse, zlib
import cortex, sec_nextgen, sec_engine, sec_jtr, sec_kdf, sec_modules, sec_msf, sec_ui

FLOW_Q = collections.deque(maxlen=512)
TCPDUMP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)")

def push_flow(ip, port, label):
    x = (zlib.crc32(str(ip).encode()) % 480) + 16
    y = (int(port) % 480) + 16
    FLOW_Q.append((((x & 65535) << 16) | (y & 65535), label))

def stdin_loop():
    for line in sys.stdin:
        m = TCPDUMP_RE.search(line)
        if m:
            src, _, dst, dp = m.groups()
            push_flow(src, dp, f"PKT {src} -> {dst}:{dp}")

def ss_loop():
    while True:
        try:
            out = subprocess.check_output(["ss", "-H", "-tun"], text=True, stderr=subprocess.DEVNULL)
            for ln in out.splitlines():
                c = ln.split()
                if len(c) < 6: continue
                _, lp = c[4].rsplit(":", 1)
                rip, _ = c[5].rsplit(":", 1)
                if lp.isdigit() and lp != "8095":
                    push_flow(rip, lp, f"SOCK {rip} -> :{lp} ({c[1]})")
        except Exception:
            pass
        time.sleep(0.12)

class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

class Hdl(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, obj, dl=None):
        b = json.dumps(obj, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if dl: self.send_header("Content-Disposition", f'attachment; filename="{dl}"')
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n).decode() or "{}")
        try:
            if self.path == "/api/scan":
                self.send_json(sec_engine.scan_target(body.get("host", "127.0.0.1"), body.get("ports", "1-1024"), push_flow))
            elif self.path == "/api/gpu_hash":
                self.send_json(sec_engine.gpu_wgsl_audit(
                    int(body.get("elements", 262144)), int(body.get("iters", 512)),
                    int(time.time()) & 0xFFFF, bool(body.get("poison", False))))
            elif self.path == "/api/fuzz":
                self.send_json(sec_modules.web_fuzz(body.get("url", "http://127.0.0.1:8095"), body.get("words", ""), push_flow))
            elif self.path == "/api/tls":
                self.send_json(sec_modules.tls_dns_audit(body.get("host", "github.com"), int(body.get("port", 443))))
            elif self.path == "/api/ba_run":
                self.send_json(sec_msf.run_tool(body.get("id", ""), body.get("target", "127.0.0.1"), push_flow))
            elif self.path == "/api/ng_xor":
                self.send_json(sec_nextgen.gpu_xor_entropy(body.get("payload", ""), push_flow))
            elif self.path == "/api/ng_beacon":
                self.send_json(sec_nextgen.gpu_beacon_hunt(body.get("ts", ""), body.get("ip", "203.0.113.42"), push_flow))
            elif self.path == "/api/ng_dga":
                self.send_json(sec_nextgen.gpu_dga_tunnel(body.get("domains", ""), push_flow))
            elif self.path == "/api/jtr_sweep":
                self.send_json(sec_jtr.gpu_audit_keyspace(body.get("hash", ""), body.get("mask", "?f?f?f?f"), push_flow))
            elif self.path == "/api/hash_gen":
                pw = body.get("pw", "flint26").encode()
                self.send_json({"sha256": __import__("hashlib").sha256(pw).hexdigest()})
            elif self.path == "/api/kdf_audit":
                self.send_json(sec_kdf.audit_hashes(body.get("samples", []), push_flow))
            elif self.path == "/api/kdf_bench":
                self.send_json(sec_kdf.bench_kdf(body.get("gpu_mhps", 150.0), body.get("len", 8), body.get("charset", 36)))
            elif self.path == "/api/msf":
                self.send_json(sec_msf.msf_exec(body.get("cmd", ""), push_flow))
            elif self.path == "/api/canary":
                self.send_json(sec_modules.toggle_canary(int(body.get("port", 2222)), body.get("profile", "ssh"), push_flow))
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == "/reset":
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(cortex.SOCK); s.sendall(b"CORTEX:RESET\n"); s.recv(64)
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
            elif u.path == "/api/ba_list":
                self.send_json(sec_msf.list_catalog())
            elif u.path == "/api/threats":
                self.send_json({"threats": sec_modules.get_threats(), "canaries": sorted(sec_modules.CANARIES.keys())})
            elif u.path == "/api/graph":
                self.send_json(sec_engine.get_graph(40))
            elif u.path == "/api/report":
                self.send_json({"generated_at": int(time.time()), "provenance": sec_engine.get_graph(100)}, "caprun_forensic_report.json")
            elif u.path == "/step":
                q = urllib.parse.parse_qs(u.query)
                t, m = int(q.get("t", ["0"])[0]), int(q.get("m", ["0"])[0]) & 3
                st, label = (FLOW_Q.popleft() if FLOW_Q else (0xFFFFFFFF, "idle"))
                rgb, us, surp = cortex.broker_cortex(t, st, m)
                if st != 0xFFFFFFFF and surp >= 140:
                    sec_engine.log_delta("netsec_cortex", "anomaly_spike", f"s{surp}_{label[:28]}", us)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Gpu-Us", str(us))
                self.send_header("X-Surprise", str(surp))
                self.send_header("X-Flow", label)
                self.send_header("Content-Length", str(len(rgb)))
                self.end_headers()
                self.wfile.write(rgb)
            else:
                b = sec_ui.HTML.encode()
                self.send_response(200); self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass

def ensure_broker():
    import os
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(cortex.SOCK)
        return
    except OSError:
        pass
    try: os.remove(cortex.SOCK)
    except OSError: pass
    subprocess.Popen(["./target/release/caprun", "broker"], stdout=open("/tmp/caprun_broker.log", "ab"), stderr=subprocess.STDOUT)
    for _ in range(30):
        time.sleep(0.1)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(cortex.SOCK)
            return
        except OSError:
            pass

if __name__ == "__main__":
    ensure_broker()
    piped = not sys.stdin.isatty()
    threading.Thread(target=stdin_loop if piped else ss_loop, daemon=True).start()
    print(f"Caprun SecSuite OpsDeck ({'tcpdump pipe' if piped else 'ss poller'}) -> http://localhost:8095")
    try:
        Server(("0.0.0.0", 8095), Hdl).serve_forever()
    except KeyboardInterrupt:
        print("\nSecSuite stopped.")
