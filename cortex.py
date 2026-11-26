#!/usr/bin/env python3
import hashlib, http.server, os, socket, sqlite3, time, urllib.parse

SOCK = os.path.expanduser("~/.cas/vulkan.sock")
DB_PATH = os.path.expanduser("~/.cas/graph.db")
LAST_LOG = 0.0

CORTEX_WGSL = """struct Params { seed: u32, count: u32, iters: u32, stim: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@group(0) @binding(2) var<storage, read> st_in: array<vec4<f32>>;
@group(0) @binding(3) var<storage, read_write> st_out: array<vec4<f32>>;

fn at(x: i32, y: i32) -> vec4<f32> {
    let wx = u32((x + 512) & 511);
    let wy = u32((y + 512) & 511);
    return st_in[(wy << 9u) | wx];
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let x = i32(idx & 511u);
    let y = i32(idx >> 9u);
    let me = st_in[idx];

    // Mexican-hat cortical coupling: short-range excitation, medium-range inhibition
    let exc = (at(x+1,y).y + at(x-1,y).y + at(x,y+1).y + at(x,y-1).y
             + at(x+2,y+2).y + at(x-2,y-2).y + at(x+2,y-2).y + at(x-2,y+2).y) * 0.125;
    let inh = (at(x+5,y).y + at(x-5,y).y + at(x,y+5).y + at(x,y-5).y
             + at(x+4,y+4).y + at(x-4,y-4).y + at(x+4,y-4).y + at(x-4,y+4).y) * 0.125;

    // External sensory injection from pointer drag/click
    var ext = 0.0;
    if (params.stim != 0xFFFFFFFFu) {
        let sx = f32((params.stim >> 16u) & 65535u);
        let sy = f32(params.stim & 65535u);
        let d = length(vec2<f32>(f32(x) - sx, f32(y) - sy));
        ext = exp(-(d * d) / 180.0);
    }

    // Predictive coding: top-down expectation vs sensory + lateral drive
    let pred = me.z;
    let drive_in = ext * 1.15 + exc * 0.85;
    let err = clamp(drive_in - pred, -1.0, 1.0);
    let surprise = abs(err);

    // Leaky Integrate-and-Fire (LIF) neuron update
    var v = me.x * 0.84 + ext * 0.65 + exc * 0.52 - inh * 0.36 + err * 0.42;
    let fired = select(0.0, 1.0, v >= 1.0);
    if (fired > 0.5) { v = 0.0; }
    v = clamp(v, 0.0, 1.2);

    // Recurrent working-memory trace (sustains attractors after stimulus ends)
    let wm = clamp(me.y * 0.988 + fired * 0.48 + exc * 0.015 - inh * 0.012, 0.0, 1.0);
    let next_pred = clamp(pred + err * 0.09, 0.0, 1.0);
    st_out[idx] = vec4<f32>(v, wm, next_pred, surprise);

    // Render modes: 0=Composite, 1=Surprise/Error, 2=Working Memory Attractors
    var col = vec3<f32>(0.0);
    if (params.iters == 1u) {
        col = vec3<f32>(surprise * 1.4, surprise * 0.25, surprise * 0.85);
    } else if (params.iters == 2u) {
        col = vec3<f32>(wm * 0.15, wm * 0.85, wm * 1.1);
    } else {
        col = vec3<f32>(surprise * 1.35 + fired * 0.95, wm * 0.82 + fired * 0.95, wm * 1.15 + surprise * 0.45);
    }
    let ri = u32(clamp(col.x, 0.0, 1.0) * 255.0);
    let gi = u32(clamp(col.y, 0.0, 1.0) * 255.0);
    let bi = u32(clamp(col.z, 0.0, 1.0) * 255.0);
    out_buf[idx] = f32((ri << 16u) | (gi << 8u) | bi);
}"""

WGSL_HEX = CORTEX_WGSL.encode("utf-8").hex()
WGSL_HASH = hashlib.sha256(CORTEX_WGSL.encode("utf-8")).hexdigest()

def log_surprise(surp, stim, us):
    global LAST_LOG
    now = time.time()
    if surp < 180 or (now - LAST_LOG) < 2.0: return
    LAST_LOG = now
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS semantic_deltas (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts_unix INTEGER NOT NULL,
        capability_hash TEXT NOT NULL, entity TEXT NOT NULL,
        relation TEXT NOT NULL, value TEXT NOT NULL, latency_us INTEGER NOT NULL)""")
    sx, sy = (stim >> 16) & 65535, stim & 65535
    conn.execute(
        "INSERT INTO semantic_deltas (ts_unix, capability_hash, entity, relation, value, latency_us) VALUES (?,?,?,?,?,?)",
        (int(now), WGSL_HASH, "spiking_cortex", "surprise_episode", f"err_{surp}_xy_{sx}_{sy}", int(us)),
    )
    conn.commit()
    conn.close()
HTML = r"""<!doctype html><html><head><meta charset=utf-8><title>caprun // 262k Spiking Cortex</title>
<style>
body{margin:0;background:#050811;color:#e2e8f0;font-family:monospace;display:flex;flex-direction:column;align-items:center;padding:14px;user-select:none}
.bar{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0;align-items:center}
button{background:#1e293b;color:#38bdf8;border:1px solid #334155;padding:7px 12px;border-radius:6px;cursor:pointer;font-family:monospace}
button.on{background:#0284c7;color:#fff;border-color:#38bdf8}
#stat{font-size:12px;color:#34d399;margin-bottom:8px}
canvas{border:1px solid #1e3a5f;border-radius:8px;box-shadow:0 0 36px #0ea5e933;cursor:crosshair;touch-action:none;max-width:92vmin;height:auto}
.leg{font-size:11px;color:#94a3b8;margin-top:8px}
</style></head><body>
<h3>caprun // 512x512 Predictive Spiking Cortex (262,144 LIF Neurons in VRAM)</h3>
<div class=bar>
  <button data-m="0" class="on">Composite</button>
  <button data-m="1">Prediction Error</button>
  <button data-m="2">Working Memory</button>
  <button id="btn_rst">Clear Memory</button>
</div>
<div id=stat>connecting to Iris Xe broker...</div>
<canvas id=c width=512 height=512></canvas>
<div class=leg>Click or drag on the cortical sheet to inject sensory stimuli. Cyan = Working Memory | White = LIF Spikes | Magenta = Surprise</div>
<script>
const c=document.getElementById('c'), ctx=c.getContext('2d'), img=ctx.createImageData(512,512), stat=document.getElementById('stat');
let mode=0, tick=0, down=false, sx=-1, sy=-1, fpsN=0, fpsT=performance.now(), fps='60.0';

document.querySelectorAll('[data-m]').forEach(b=>b.addEventListener('click', ()=>{
  mode=Number(b.dataset.m);
  document.querySelectorAll('[data-m]').forEach(x=>x.classList.toggle('on', x===b));
}));
document.getElementById('btn_rst').addEventListener('click', ()=>fetch('/reset'));

function setPtr(e){
  const r=c.getBoundingClientRect();
  sx=Math.max(0,Math.min(511,Math.floor(((e.clientX-r.left)/r.width)*512)));
  sy=Math.max(0,Math.min(511,Math.floor(((e.clientY-r.top)/r.height)*512)));
}
c.addEventListener('pointerdown', e=>{ down=true; setPtr(e); c.setPointerCapture(e.pointerId); });
c.addEventListener('pointermove', e=>{ if(down) setPtr(e); });
c.addEventListener('pointerup', ()=>{ down=false; });

async function step(){
  try{
    const stim = down ? (((sx & 65535) << 16) | (sy & 65535)) >>> 0 : 0xFFFFFFFF;
    const r = await fetch(`/step?t=${tick++}&s=${stim}&m=${mode}`);
    const us = Number(r.headers.get('X-Gpu-Us')||0);
    const surp = Number(r.headers.get('X-Surprise')||0);
    const rgb = new Uint8Array(await r.arrayBuffer());
    if(rgb.length===512*512*3){
      const d=img.data;
      for(let i=0,j=0;i<rgb.length;i+=3,j+=4){ d[j]=rgb[i]; d[j+1]=rgb[i+1]; d[j+2]=rgb[i+2]; d[j+3]=255; }
      ctx.putImageData(img,0,0);
    }
    fpsN++; const now=performance.now();
    if(now-fpsT>=500){ fps=(fpsN*1000/(now-fpsT)).toFixed(1); fpsN=0; fpsT=now; }
    stat.textContent=`Iris Xe: ${(us/1000).toFixed(2)} ms | ${fps} FPS | Surprise neurons: ${surp} | Persistent VRAM state`;
  }catch(e){ stat.textContent='Broker error: '+e.message; }
  requestAnimationFrame(step);
}
step();
</script></body></html>"""

def broker_cortex(tick, stim, mode):
    msg = f"CORTEX:{tick}:{stim}:{mode}:{WGSL_HEX}\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall(msg)
        hdr = b""
        while not hdr.endswith(b"\n"):
            ch = s.recv(1)
            if not ch: break
            hdr += ch
        parts = hdr.decode().strip().split(":")
        if parts[0] != "OK_CORTEX": raise RuntimeError(hdr.decode())
        need, us, surp = int(parts[1]), int(parts[2]), int(parts[3])
        buf = bytearray()
        while len(buf) < need:
            chunk = s.recv(min(65536, need - len(buf)))
            if not chunk: break
            buf.extend(chunk)
        return bytes(buf), us, surp

class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

class Hdl(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == "/reset":
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(SOCK); s.sendall(b"CORTEX:RESET\n"); s.recv(64)
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
            elif u.path == "/step":
                q = urllib.parse.parse_qs(u.query)
                t = int(q.get("t", ["0"])[0])
                st = int(q.get("s", ["4294967295"])[0]) & 0xFFFFFFFF
                m = int(q.get("m", ["0"])[0]) & 3
                rgb, us, surp = broker_cortex(t, st, m)
                if st != 0xFFFFFFFF: log_surprise(surp, st, us)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Gpu-Us", str(us))
                self.send_header("X-Surprise", str(surp))
                self.send_header("Content-Length", str(len(rgb)))
                self.end_headers()
                self.wfile.write(rgb)
            else:
                b = HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass

if __name__ == "__main__":
    print("caprun 262,144-neuron Spiking Cortex -> http://0.0.0.0:8090")
    try:
        Server(("0.0.0.0", 8090), Hdl).serve_forever()
    except KeyboardInterrupt:
        print("\nCortex stopped.")
