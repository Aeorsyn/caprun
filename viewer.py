#!/usr/bin/env python3
import http.server, os, socket, urllib.parse

SOCK = os.path.expanduser("~/.cas/vulkan.sock")

SHADERS = {
    "hyperfold": """struct Params { seed: u32, count: u32, iters: u32, cam: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
fn rot(a: f32) -> mat2x2<f32> { let c = cos(a); let s = sin(a); return mat2x2<f32>(c, -s, s, c); }
fn gyroid(p: vec3<f32>, sc: f32) -> f32 { let q = p * sc; return dot(sin(q), cos(q.yzx)) / sc; }
fn map(p_in: vec3<f32>, t: f32) -> f32 {
    var p = p_in;
    let tw = rot(p.z * 0.24 + t * 0.28) * p.xy;
    p.x = tw.x; p.y = tw.y;
    let g1 = gyroid(p + vec3<f32>(0.0, 0.0, t * 1.3), 2.1);
    let g2 = gyroid(p * 1.75 - vec3<f32>(t * 0.55, 0.0, 0.0), 3.3) * 0.34;
    let tunnel = 0.68 - length(p.xy);
    return max(abs(g1 + g2) - 0.13, tunnel);
}
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let side = select(512u, 1024u, params.count > 262144u);
    let uv = (vec2<f32>(f32(idx % side), f32(idx / side)) / f32(side)) * 2.0 - 1.0;
    let t = f32(params.seed) * 0.04;
    let yaw = (f32((params.cam >> 16u) & 65535u) / 65535.0 - 0.5) * 6.283185;
    let pitch = (f32(params.cam & 65535u) / 65535.0 - 0.5) * 2.2;
    let ro = vec3<f32>(0.0, 0.0, 0.0);
    var rd = normalize(vec3<f32>(uv.x, -uv.y, 1.25));
    let ry = rot(pitch) * rd.yz; rd.y = ry.x; rd.z = ry.y;
    let rx = rot(yaw) * rd.xz; rd.x = rx.x; rd.z = rx.y;
    var dist = 0.0; var glow = vec3<f32>(0.0); var hit = false;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        let p = ro + rd * dist;
        let d = map(p, t);
        let ph = 0.5 + 0.5 * cos(t * 0.7 + dist * 0.48 + vec3<f32>(0.0, 2.1, 4.2));
        glow = glow + ph * (0.011 / (0.045 + abs(d)));
        if (d < 0.005) { hit = true; break; }
        dist = dist + d * 0.78;
        if (dist > 14.0) { break; }
    }
    var col = glow * 0.14;
    if (hit) {
        let p = ro + rd * dist; let e = 0.005;
        let n = normalize(vec3<f32>(
            map(p + vec3<f32>(e,0.0,0.0), t) - map(p - vec3<f32>(e,0.0,0.0), t),
            map(p + vec3<f32>(0.0,e,0.0), t) - map(p - vec3<f32>(0.0,e,0.0), t),
            map(p + vec3<f32>(0.0,0.0,e), t) - map(p - vec3<f32>(0.0,0.0,e), t)
        ));
        let fres = pow(1.0 - max(dot(n, -rd), 0.0), 2.5);
        let irid = 0.5 + 0.5 * cos(dot(n, rd) * 4.0 + dist * 0.6 + vec3<f32>(0.2, 2.3, 4.1));
        col = col + irid * (0.35 + 0.9 * fres) * exp(-dist * 0.16);
    }
    col = col / (col + vec3<f32>(1.0));
    let ri = u32(clamp(col.x, 0.0, 1.0) * 255.0);
    let gi = u32(clamp(col.y, 0.0, 1.0) * 255.0);
    let bi = u32(clamp(col.z, 0.0, 1.0) * 255.0);
    out_buf[idx] = f32((ri << 16u) | (gi << 8u) | bi);
}""",
    "raymarch": """struct Params { seed: u32, count: u32, iters: u32, cam: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
fn rot(a: f32) -> mat2x2<f32> { let c = cos(a); let s = sin(a); return mat2x2<f32>(c, -s, s, c); }
fn map(p_in: vec3<f32>, t: f32) -> f32 {
    var p = p_in;
    let xz = rot(t * 0.55) * p.xz; p.x = xz.x; p.z = xz.y;
    let xy = rot(t * 0.35) * p.xy; p.x = xy.x; p.y = xy.y;
    let q = vec2<f32>(length(p.xz) - 1.05, p.y);
    return min(length(q) - 0.34, length(p - vec3<f32>(sin(t * 1.4) * 0.55, cos(t * 1.1) * 0.35, 0.0)) - 0.42);
}
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let side = select(512u, 1024u, params.count > 262144u);
    let uv = (vec2<f32>(f32(idx % side), f32(idx / side)) / f32(side)) * 2.0 - 1.0;
    let t = f32(params.seed) * 0.04;
    let yaw = (f32((params.cam >> 16u) & 65535u) / 65535.0 - 0.5) * 6.283185;
    let pitch = (f32(params.cam & 65535u) / 65535.0 - 0.5) * 2.6;
    var ro = vec3<f32>(0.0, 0.0, -3.1);
    var rd = normalize(vec3<f32>(uv.x, -uv.y, 1.55));
    let ry0 = rot(pitch) * ro.yz; ro.y = ry0.x; ro.z = ry0.y;
    let ry1 = rot(pitch) * rd.yz; rd.y = ry1.x; rd.z = ry1.y;
    let rx0 = rot(yaw) * ro.xz; ro.x = rx0.x; ro.z = rx0.y;
    let rx1 = rot(yaw) * rd.xz; rd.x = rx1.x; rd.z = rx1.y;
    var dist = 0.0; var hit = false; var steps = 0u;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        let d = map(ro + rd * dist, t);
        if (d < 0.004) { hit = true; steps = i; break; }
        dist = dist + d; if (dist > 10.0) { break; }
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
        col = (base * (0.15 + 0.85 * diff) + vec3<f32>(0.2, 0.9, 1.0) * rim * 0.7 + vec3<f32>(1.0) * spec * 0.8) * (1.0 - f32(steps) / f32(params.iters) * 0.45);
    }
    out_buf[idx] = f32((u32(clamp(col.x,0.0,1.0)*255.0)<<16u)|(u32(clamp(col.y,0.0,1.0)*255.0)<<8u)|u32(clamp(col.z,0.0,1.0)*255.0));
}""",
    "mandelbrot": """struct Params { seed: u32, count: u32, iters: u32, cam: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let side = select(512u, 1024u, params.count > 262144u);
    let uv = (vec2<f32>(f32(idx % side), f32(idx / side)) / f32(side)) * 2.0 - 1.0;
    let pan = (vec2<f32>(f32((params.cam >> 16u) & 65535u), f32(params.cam & 65535u)) / 65535.0 - 0.5) * 0.8;
    let zoom = pow(0.97, f32(params.seed % 160u));
    let c = vec2<f32>(-0.743643887, 0.131825904) + (uv + pan) * (1.4 * zoom);
    var z = vec2<f32>(0.0, 0.0); var k = 0u;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        z = vec2<f32>(z.x*z.x - z.y*z.y + c.x, 2.0*z.x*z.y + c.y);
        if (dot(z, z) > 4.0) { break; } k = k + 1u;
    }
    var col = vec3<f32>(0.0);
    if (k < params.iters) { let f = f32(k)/f32(params.iters); col = 0.5 + 0.5 * cos(6.283*(f*3.0 + vec3<f32>(0.0,0.33,0.67))); }
    out_buf[idx] = f32((u32(col.x*255.0)<<16u)|(u32(col.y*255.0)<<8u)|u32(col.z*255.0));
}""",
    "aurora": """struct Params { seed: u32, count: u32, iters: u32, cam: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let side = select(512u, 1024u, params.count > 262144u);
    let uv = vec2<f32>(f32(idx % side), f32(idx / side)) / f32(side);
    let pan = vec2<f32>(f32((params.cam >> 16u) & 65535u), f32(params.cam & 65535u)) / 65535.0 - 0.5;
    let t = f32(params.seed) * 0.05; let p = uv + pan * 1.5;
    let v = sin(p.x*10.0+t)+sin((p.y*8.0+t*0.7)*1.2)+sin(p.x*6.0+p.y*6.0+t*1.1)+sin(length(p-vec2<f32>(0.5))*18.0-t*2.0);
    let r = 0.5+0.5*sin(v*1.4); let g = 0.5+0.5*sin(v*1.4+2.1); let b = 0.5+0.5*sin(v*1.4+4.2);
    out_buf[idx] = f32((u32(r*255.0)<<16u)|(u32(g*255.0)<<8u)|u32(b*255.0));
}""",
}
HTML = """<!doctype html><html><head><meta charset=utf-8><title>caprun Live Silicon Viewport</title>
<style>body{background:#090d16;color:#e2e8f0;font-family:monospace;display:flex;flex-direction:column;align-items:center;padding:16px;margin:0;user-select:none}
canvas{border:1px solid #334155;border-radius:8px;box-shadow:0 0 30px #0ea5e933;cursor:grab;touch-action:none;max-width:92vw;height:auto}
canvas:active{cursor:grabbing}
.bar{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0;align-items:center;justify-content:center}
button{background:#1e293b;color:#38bdf8;border:1px solid #334155;padding:7px 12px;border-radius:6px;cursor:pointer;font-family:monospace}
button.on{background:#0284c7;color:#fff;border-color:#38bdf8}
.hint{font-size:12px;color:#34d399;margin-bottom:8px}</style></head><body>
<h3>caprun // Live Iris Xe Sandboxed Shader Stream</h3>
<div class=bar>
  <button data-sh="hyperfold" class="on">Hyperfold 4D</button>
  <button data-sh="raymarch">3D Torus</button>
  <button data-sh="mandelbrot">Mandelbrot</button>
  <button data-sh="aurora">Aurora</button>
  <span style="color:#475569">|</span>
  <button data-res="512" class="on">512x512</button>
  <button data-res="1024">1024x1024 HD</button>
  <button id="btn_reset">Reset Cam</button>
</div>
<div class=hint id=stat>starting...</div>
<canvas id=c width=512 height=512></canvas>
<script>
const c = document.getElementById('c'), ctx = c.getContext('2d'), stat = document.getElementById('stat');
let sh = 'hyperfold', res = 512, img = ctx.createImageData(512, 512);
let frame = 0, fpsT = performance.now(), fpsN = 0, fps = '0.0';
let yaw = 0.5, pitch = 0.5, drag = false, lx = 0, ly = 0;

document.querySelectorAll('[data-sh]').forEach(btn => {
  btn.addEventListener('click', () => {
    sh = btn.dataset.sh; frame = 0;
    document.querySelectorAll('[data-sh]').forEach(b => b.classList.toggle('on', b === btn));
  });
});
document.querySelectorAll('[data-res]').forEach(btn => {
  btn.addEventListener('click', () => {
    res = Number(btn.dataset.res); c.width = res; c.height = res; img = ctx.createImageData(res, res);
    document.querySelectorAll('[data-res]').forEach(b => b.classList.toggle('on', b === btn));
  });
});
document.getElementById('btn_reset').addEventListener('click', () => { yaw = 0.5; pitch = 0.5; });

c.addEventListener('pointerdown', e => { drag = true; lx = e.clientX; ly = e.clientY; c.setPointerCapture(e.pointerId); });
c.addEventListener('pointermove', e => {
  if (!drag) return;
  yaw = (yaw + (e.clientX - lx) * 0.0025 + 1) % 1;
  pitch = Math.max(0.05, Math.min(0.95, pitch + (e.clientY - ly) * 0.0025));
  lx = e.clientX; ly = e.clientY;
});
c.addEventListener('pointerup', () => { drag = false; });
c.addEventListener('dblclick', () => { yaw = 0.5; pitch = 0.5; });

async function tick() {
  try {
    const curRes = res, curSh = sh;
    const cam = (((Math.round(yaw * 65535) & 65535) << 16) | (Math.round(pitch * 65535) & 65535)) >>> 0;
    const r = await fetch(`/frame?s=${curSh}&f=${frame++}&r=${curRes}&c=${cam}`);
    if (!r.ok) { stat.textContent = 'Broker error: ' + await r.text(); }
    else {
      const us = Number(r.headers.get('X-Gpu-Us') || 0);
      const rgb = new Uint8Array(await r.arrayBuffer());
      if (curRes === res && rgb.length === curRes * curRes * 3) {
        const d = img.data;
        for (let i = 0, j = 0; i < rgb.length; i += 3, j += 4) { d[j]=rgb[i]; d[j+1]=rgb[i+1]; d[j+2]=rgb[i+2]; d[j+3]=255; }
        ctx.putImageData(img, 0, 0);
      }
      fpsN++; const now = performance.now();
      if (now - fpsT >= 500) { fps = (fpsN * 1000 / (now - fpsT)).toFixed(1); fpsN = 0; fpsT = now; }
      stat.textContent = `${curSh} | ${res}x${res} | GPU: ${(us/1000).toFixed(2)} ms | ${fps} FPS | Drag to orbit`;
    }
  } catch (e) { stat.textContent = 'Stream error: ' + e.message; }
  requestAnimationFrame(tick);
}
tick();
</script></body></html>"""

def fetch_frame(wgsl, side, frame, iters, cam):
    msg = f"FRAME:{side*side}:{frame}:{iters}:{cam}:{wgsl.encode().hex()}\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall(msg)
        hdr = b""
        while not hdr.endswith(b"\n"):
            ch = s.recv(1)
            if not ch: break
            hdr += ch
        parts = hdr.decode().strip().split(":")
        if parts[0] != "OK_FRAME": raise RuntimeError(hdr.decode())
        need, us = int(parts[1]), int(parts[2])
        buf = bytearray()
        while len(buf) < need:
            chunk = s.recv(min(65536, need - len(buf)))
            if not chunk: break
            buf.extend(chunk)
        return bytes(buf), us

class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

class Hdl(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/frame":
            q = urllib.parse.parse_qs(u.query)
            sh = q.get("s", ["hyperfold"])[0]
            fr = int(q.get("f", ["0"])[0])
            side = 1024 if q.get("r", ["512"])[0] == "1024" else 512
            cam = int(q.get("c", ["2147516415"])[0]) & 0xFFFFFFFF
            iters = 96 if sh == "mandelbrot" else (72 if sh == "hyperfold" else 64)
            try:
                rgb, us = fetch_frame(SHADERS.get(sh, SHADERS["hyperfold"]), side, fr, iters, cam)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Gpu-Us", str(us))
                self.send_header("Content-Length", str(len(rgb)))
                self.end_headers()
                self.wfile.write(rgb)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                try:
                    b = str(e).encode()
                    self.send_response(500); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        else:
            b = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

if __name__ == "__main__":
    print("Live caprun Iris Xe viewport (4 modes + HD toggle) -> http://0.0.0.0:8090")
    try:
        Server(("0.0.0.0", 8090), Hdl).serve_forever()
    except KeyboardInterrupt:
        print("\nViewer stopped.")
