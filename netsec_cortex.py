#!/usr/bin/env python3
import collections, http.server, os, re, socket, sqlite3, subprocess, sys, threading, time, urllib.parse, zlib
import cortex

FLOW_Q = collections.deque(maxlen=256)
LAST_LOG = 0.0
TCPDUMP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)")

def push_flow(ip, port, label):
    x = (zlib.crc32(ip.encode()) % 480) + 16
    y = (int(port) % 480) + 16
    FLOW_Q.append((((x & 65535) << 16) | (y & 65535), label, int(port)))

def stdin_tcpdump_loop():
    for line in sys.stdin:
        m = TCPDUMP_RE.search(line)
        if m:
            src, _, dst, dport = m.groups()
            push_flow(src, dport, f"{src} -> {dst}:{dport}")

def ss_poll_loop():
    while True:
        try:
            out = subprocess.check_output(["ss", "-H", "-tun"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                c = line.split()
                if len(c) < 6: continue
                lip, lport = c[4].rsplit(":", 1)
                rip, _ = c[5].rsplit(":", 1)
                if lport.isdigit() and lport != "8090":
                    push_flow(rip, lport, f"{rip} -> :{lport} ({c[1]})")
        except Exception:
            pass
        time.sleep(0.08)

def log_anomaly(surp, label, us):
    global LAST_LOG
    now = time.time()
    if surp < 140 or (now - LAST_LOG) < 1.5: return
    LAST_LOG = now
    conn = sqlite3.connect(cortex.DB_PATH)
    conn.execute(
        "INSERT INTO semantic_deltas (ts_unix, capability_hash, entity, relation, value, latency_us) VALUES (?,?,?,?,?,?)",
        (int(now), cortex.WGSL_HASH, "netsec_cortex", "anomaly_spike", f"s{surp}_{label[:32]}", int(us)),
    )
    conn.commit()
    conn.close()
HTML = r"""<!doctype html><html><head><meta charset=utf-8><title>caprun // NetSec Spiking Cortex</title>
<style>
body{margin:0;background:#050811;color:#e2e8f0;font-family:monospace;display:flex;flex-direction:column;align-items:center;padding:14px;user-select:none}
.bar{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
button{background:#1e293b;color:#38bdf8;border:1px solid #334155;padding:7px 12px;border-radius:6px;cursor:pointer;font-family:monospace}
button.on{background:#0284c7;color:#fff;border-color:#38bdf8}
#stat{font-size:12px;color:#34d399;margin-bottom:4px}
#flow{font-size:12px;color:#f472b6;margin-bottom:8px;min-height:16px}
canvas{border:1px solid #1e3a5f;border-radius:8px;box-shadow:0 0 36px #0ea5e933;cursor:crosshair;max-width:92vmin;height:auto}
</style></head><body>
<h3>caprun // NetSec 262k Spiking Cortex (X = Source IP | Y = Dest Port)</h3>
<div class=bar>
  <button data-m="0" class="on">Composite</button>
  <button data-m="1">Prediction Error (Anomalies)</button>
  <button data-m="2">Working Memory (Baseline)</button>
  <button id="rst">Clear Memory</button>
</div>
<div id=stat>connecting to Iris Xe broker...</div>
<div id=flow>waiting for network flows...</div>
<canvas id=c width=512 height=512></canvas>
<script>
const c=document.getElementById('c'), ctx=c.getContext('2d'), img=ctx.createImageData(512,512);
const stat=document.getElementById('stat'), flow=document.getElementById('flow');
let mode=0, tick=0, fpsN=0, fpsT=performance.now(), fps='60.0';
document.querySelectorAll('[data-m]').forEach(b=>b.addEventListener('click', ()=>{
  mode=Number(b.dataset.m); document.querySelectorAll('[data-m]').forEach(x=>x.classList.toggle('on', x===b));
}));
document.getElementById('rst').addEventListener('click', ()=>fetch('/reset'));
async function step(){
  try{
    const r = await fetch(`/step?t=${tick++}&m=${mode}`);
    const us = Number(r.headers.get('X-Gpu-Us')||0);
    const surp = Number(r.headers.get('X-Surprise')||0);
    const fl = r.headers.get('X-Flow')||'idle';
    const rgb = new Uint8Array(await r.arrayBuffer());
    if(rgb.length===512*512*3){
      const d=img.data;
      for(let i=0,j=0;i<rgb.length;i+=3,j+=4){ d[j]=rgb[i]; d[j+1]=rgb[i+1]; d[j+2]=rgb[i+2]; d[j+3]=255; }
      ctx.putImageData(img,0,0);
    }
    fpsN++; const now=performance.now();
    if(now-fpsT>=500){ fps=(fpsN*1000/(now-fpsT)).toFixed(1); fpsN=0; fpsT=now; }
    stat.textContent=`Iris Xe: ${(us/1000).toFixed(2)} ms | ${fps} FPS | Surprise neurons: ${surp}`;
    if(fl!=='idle') flow.textContent=`LAST FLOW: ${fl}`;
  }catch(e){ stat.textContent='Error: '+e.message; }
  requestAnimationFrame(step);
}
step();
</script></body></html>"""

class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

class Hdl(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == "/reset":
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(cortex.SOCK); s.sendall(b"CORTEX:RESET\n"); s.recv(64)
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
            elif u.path == "/step":
                q = urllib.parse.parse_qs(u.query)
                t = int(q.get("t", ["0"])[0])
                m = int(q.get("m", ["0"])[0]) & 3
                st, label = 0xFFFFFFFF, "idle"
                if FLOW_Q: st, label, _ = FLOW_Q.popleft()
                rgb, us, surp = cortex.broker_cortex(t, st, m)
                if st != 0xFFFFFFFF: log_anomaly(surp, label, us)
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
                b = HTML.encode()
                self.send_response(200); self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass

if __name__ == "__main__":
    mode = "tcpdump stdin pipe" if not sys.stdin.isatty() else "ss live socket poller"
    t = threading.Thread(target=stdin_tcpdump_loop if not sys.stdin.isatty() else ss_poll_loop, daemon=True)
    t.start()
    print(f"caprun NetSec Cortex ({mode}) -> http://0.0.0.0:8090")
    try:
        Server(("0.0.0.0", 8090), Hdl).serve_forever()
    except KeyboardInterrupt:
        print("\nNetSec Cortex stopped.")
