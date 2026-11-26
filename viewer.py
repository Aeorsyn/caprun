#!/usr/bin/env python3
import http.server, os, socket, urllib.parse

SOCK = os.path.expanduser("~/.cas/vulkan.sock")
W, H = 512, 512

SHADERS = {
    "raymarch": """struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
fn rot(a: f32) -> mat2x2<f32> { let c = cos(a); let s = sin(a); return mat2x2<f32>(c, -s, s, c); }
fn map(p_in: vec3<f32>, t: f32) -> f32 {
    var p = p_in;
    let xz = rot(t * 0.7) * p.xz; p.x = xz.x; p.z = xz.y;
    let xy = rot(t * 0.45) * p.xy; p.x = xy.x; p.y = xy.y;
    let q = vec2<f32>(length(p.xz) - 1.05, p.y);
    let torus = length(q) - 0.34;
    let orb = length(p - vec3<f32>(sin(t * 1.4) * 0.55, cos(t * 1.1) * 0.35, 0.0)) - 0.42;
    return min(torus, orb);
}
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let uv = (vec2<f32>(f32(idx % 512u), f32(idx / 512u)) / 512.0) * 2.0 - 1.0;
    let t = f32(params.seed) * 0.04;
    let ro = vec3<f32>(0.0, 0.0, -3.1);
    let rd = normalize(vec3<f32>(uv.x, -uv.y, 1.55));
    var dist = 0.0; var hit = false; var steps = 0u;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        let d = map(ro + rd * dist, t);
        if (d < 0.004) { hit = true; steps = i; break; }
        dist = dist + d;
        if (dist > 10.0) { break; }
    }
    var col = vec3<f32>(0.02, 0.03, 0.08) + vec3<f32>(0.0, 0.06, 0.14) * max(0.0, 1.0 - length(uv));
    if (hit) {
        let p = ro + rd * dist; let e = 0.003;
        let n = normalize(vec3<f32>(
            map(p + vec3<f32>(e,0.0,0.0), t) - map(p - vec3<f32>(e,0.0,0.0), t),
            map(p + vec3<f32>(0.0,e,0.0), t) - map(p - vec3<f32>(0.0,e,0.0), t),
            map(p + vec3<f32>(0.0,0.0,e), t) - map(p - vec3<f32>(0.0,0.0,e), t)
        ));
        let l = normalize(vec3<f32>(0.7, 0.9, -0.8));
        let diff = max(dot(n, l), 0.0);
        let spec = pow(max(dot(reflect(-l, n), -rd), 0.0), 28.0);
        let rim = pow(1.0 - max(dot(n, -rd), 0.0), 3.0);
        let base = 0.5 + 0.5 * cos(t + p.xyx + vec3<f32>(0.0, 2.0, 4.0));
        col = base * (0.15 + 0.85 * diff) + vec3<f32>(0.2, 0.9, 1.0) * rim * 0.7 + vec3<f32>(1.0) * spec * 0.8;
        col = col * (1.0 - f32(steps) / f32(params.iters) * 0.45);
    }
    let ri = u32(clamp(col.x, 0.0, 1.0) * 255.0);
    let gi = u32(clamp(col.y, 0.0, 1.0) * 255.0);
    let bi = u32(clamp(col.z, 0.0, 1.0) * 255.0);
    out_buf[idx] = f32((ri << 16u) | (gi << 8u) | bi);
}""",
    "aurora": """struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let uv = vec2<f32>(f32(idx % 512u), f32(idx / 512u)) / 512.0;
    let t = f32(params.seed) * 0.05;
    let v = sin(uv.x * 10.0 + t) + sin((uv.y * 8.0 + t * 0.7) * 1.2)
          + sin((uv.x * 6.0 + uv.y * 6.0 + t * 1.1))
          + sin(length(uv - vec2<f32>(0.5, 0.5)) * 18.0 - t * 2.0);
    let r = 0.5 + 0.5 * sin(v * 1.4 + 0.0);
    let g = 0.5 + 0.5 * sin(v * 1.4 + 2.1);
    let b = 0.5 + 0.5 * sin(v * 1.4 + 4.2);
    out_buf[idx] = f32((u32(r * 255.0) << 16u) | (u32(g * 255.0) << 8u) | u32(b * 255.0));
}""",
    "mandelbrot": """struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let uv = (vec2<f32>(f32(idx % 512u), f32(idx / 512u)) / 512.0) * 2.0 - 1.0;
    let zoom = pow(0.97, f32(params.seed % 160u));
    let c = vec2<f32>(-0.743643887, 0.131825904) + uv * (1.4 * zoom);
    var z = vec2<f32>(0.0, 0.0); var k = 0u;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        z = vec2<f32>(z.x*z.x - z.y*z.y + c.x, 2.0*z.x*z.y + c.y);
        if (dot(z, z) > 4.0) { break; }
        k = k + 1u;
    }
    var col = vec3<f32>(0.0);
    if (k < params.iters) {
        let f = f32(k) / f32(params.iters);
        col = 0.5 + 0.5 * cos(6.283 * (f * 3.0 + vec3<f32>(0.0, 0.33, 0.67)));
    }
    out_buf[idx] = f32((u32(col.x * 255.0) << 16u) | (u32(col.y * 255.0) << 8u) | u32(col.z * 255.0));
}""",
}
HTML = """<!doctype html><html><head><meta charset=utf-8><title>caprun Live Silicon Viewport</title>
<style>body{background:#090d16;color:#e2e8f0;font-family:monospace;display:flex;flex-direction:column;align-items:center;padding:18px;margin:0}
canvas{border:1px solid #334155;border-radius:8px;box-shadow:0 0 30px #0ea5e933}
.bar{display:flex;gap:10px;margin:12px 0;align-items:center}
button{background:#1e293b;color:#38bdf8;border:1px solid #334155;padding:8px 14px;border-radius:6px;cursor:pointer;font-family:monospace}
button.on{background:#0284c7;color:#fff}</style></head><body>
<h3>caprun // Live Iris Xe Sandboxed Shader Stream (512x512)</h3>
<div class=bar>
  <button id=b_raymarch class=on onclick="setS('raymarch')">3D Raymarch</button>
  <button id=b_mandelbrot onclick="setS('mandelbrot')">Mandelbrot Zoom</button>
  <button id=b_aurora onclick="setS('aurora')">Aurora Plasma</button>
  <span id=stat style="margin-left:10px;color:#34d399">starting...</span>
</div>
<canvas id=c width=512 height=512></canvas>
<script>
const ctx=c.getContext('2d'), img=ctx.createImageData(512,512), d=img.data;
let sh='raymarch', frame=0, fpsT=performance.now(), fpsN=0, fps=0;
function setS(s){ sh=s; frame=0; document.querySelectorAll('button').forEach(b=>b.classList.remove('on')); document.getElementById('b_'+s).classList.add('on'); }
async function tick(){
  const r = await fetch(`/frame?s=${sh}&f=${frame++}`);
  const us = Number(r.headers.get('X-Gpu-Us')||0);
  const rgb = new Uint8Array(await r.arrayBuffer());
  for(let i=0,j=0; i<rgb.length; i+=3,j+=4){ d[j]=rgb[i]; d[j+1]=rgb[i+1]; d[j+2]=rgb[i+2]; d[j+3]=255; }
  ctx.putImageData(img,0,0);
  fpsN++; const now=performance.now();
  if(now-fpsT>=500){ fps=(fpsN*1000/(now-fpsT)).toFixed(1); fpsN=0; fpsT=now; }
  stat.textContent=`GPU: ${(us/1000).toFixed(2)} ms | Stream: ${fps} FPS | 0 B extracted`;
  requestAnimationFrame(tick);
}
tick();
</script></body></html>"""

def fetch_frame(wgsl, frame, iters=64):
    msg = f"FRAME:{W*H}:{frame}:{iters}:{wgsl.encode().hex()}\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall(msg)
        hdr = b""
        while not hdr.endswith(b"\n"):
            c = s.recv(1)
            if not c: break
            hdr += c
        parts = hdr.decode().strip().split(":")
        if parts[0] != "OK_FRAME":
            raise RuntimeError(hdr.decode())
        need, us = int(parts[1]), int(parts[2])
        buf = bytearray()
        while len(buf) < need:
            chunk = s.recv(min(65536, need - len(buf)))
            if not chunk: break
            buf.extend(chunk)
        return bytes(buf), us

class Hdl(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/frame":
            q = urllib.parse.parse_qs(u.query)
            sh = q.get("s", ["raymarch"])[0]
            fr = int(q.get("f", ["0"])[0])
            iters = 96 if sh == "mandelbrot" else 64
            rgb, us = fetch_frame(SHADERS.get(sh, SHADERS["raymarch"]), fr, iters)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Gpu-Us", str(us))
            self.send_header("Content-Length", str(len(rgb)))
            self.end_headers()
            self.wfile.write(rgb)
        else:
            b = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

if __name__ == "__main__":
    print("Live caprun Iris Xe viewport -> http://0.0.0.0:8090")
    http.server.ThreadingHTTPServer(("0.0.0.0", 8090), Hdl).serve_forever()
