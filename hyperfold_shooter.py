#!/usr/bin/env python3
import hashlib, http.server, json, os, socket, sqlite3, time, urllib.parse

SOCK = os.path.expanduser("~/.cas/vulkan.sock")
DB_PATH = os.path.expanduser("~/.cas/graph.db")
SIDE = 512

HYPERFOLD_WGSL = """struct Params { seed: u32, count: u32, iters: u32, cam: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
fn rot(a: f32) -> mat2x2<f32> { let c = cos(a); let s = sin(a); return mat2x2<f32>(c, -s, s, c); }
fn gyroid(p: vec3<f32>, sc: f32) -> f32 { let q = p * sc; return dot(sin(q), cos(q.yzx)) / sc; }
fn map(p_in: vec3<f32>, t: f32) -> f32 {
    var p = p_in;
    let tw = rot(p.z * 0.22 + t * 0.25) * p.xy;
    p.x = tw.x; p.y = tw.y;
    let g1 = gyroid(p + vec3<f32>(0.0, 0.0, t * 1.8), 2.0);
    let g2 = gyroid(p * 1.7 - vec3<f32>(t * 0.5, 0.0, 0.0), 3.2) * 0.32;
    let tunnel = 0.74 - length(p.xy);
    return max(abs(g1 + g2) - 0.13, tunnel);
}
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x; if (idx >= params.count) { return; }
    let uv = (vec2<f32>(f32(idx % 512u), f32(idx / 512u)) / 512.0) * 2.0 - 1.0;
    let t = f32(params.seed) * 0.045;
    let sx = (f32((params.cam >> 16u) & 65535u) / 65535.0 - 0.5) * 2.0;
    let sy = (f32(params.cam & 65535u) / 65535.0 - 0.5) * 2.0;
    let ro = vec3<f32>(sx * 0.32, -sy * 0.28, 0.0);
    var rd = normalize(vec3<f32>(uv.x, -uv.y, 1.35));
    let bank = rot(-sx * 0.42) * rd.xy; rd.x = bank.x; rd.y = bank.y;
    let yaw = rot(sx * 0.35) * rd.xz; rd.x = yaw.x; rd.z = yaw.y;
    let pit = rot(sy * 0.28) * rd.yz; rd.y = pit.x; rd.z = pit.y;
    var dist = 0.0; var glow = vec3<f32>(0.0); var hit = false;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        let p = ro + rd * dist;
        let d = map(p, t);
        let ph = 0.5 + 0.5 * cos(t * 0.7 + dist * 0.46 + vec3<f32>(0.0, 2.1, 4.2));
        glow = glow + ph * (0.011 / (0.045 + abs(d)));
        if (d < 0.005) { hit = true; break; }
        dist = dist + d * 0.80;
        if (dist > 14.0) { break; }
    }
    var col = glow * 0.14;
    if (hit) {
        let p = ro + rd * dist; let e = 0.006;
        let n = normalize(vec3<f32>(
            map(p + vec3<f32>(e,0.0,0.0), t) - map(p - vec3<f32>(e,0.0,0.0), t),
            map(p + vec3<f32>(0.0,e,0.0), t) - map(p - vec3<f32>(0.0,e,0.0), t),
            map(p + vec3<f32>(0.0,0.0,e), t) - map(p - vec3<f32>(0.0,0.0,e), t)
        ));
        let fres = pow(1.0 - max(dot(n, -rd), 0.0), 2.4);
        let irid = 0.5 + 0.5 * cos(dot(n, rd) * 4.0 + dist * 0.55 + vec3<f32>(0.2, 2.3, 4.1));
        col = col + irid * (0.35 + 0.85 * fres) * exp(-dist * 0.15);
    }
    col = col / (col + vec3<f32>(1.0));
    out_buf[idx] = f32((u32(clamp(col.x,0.0,1.0)*255.0)<<16u)|(u32(clamp(col.y,0.0,1.0)*255.0)<<8u)|u32(clamp(col.z,0.0,1.0)*255.0));
}"""

WGSL_HEX = HYPERFOLD_WGSL.encode("utf-8").hex()
WGSL_HASH = hashlib.sha256(HYPERFOLD_WGSL.encode("utf-8")).hexdigest()

def fetch_frame(frame, cam):
    msg = f"FRAME:{SIDE*SIDE}:{frame}:64:{cam}:{WGSL_HEX}\n".encode()
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

def commit_score(score, wave, kills, avg_us):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS semantic_deltas (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts_unix INTEGER NOT NULL,
        capability_hash TEXT NOT NULL, entity TEXT NOT NULL,
        relation TEXT NOT NULL, value TEXT NOT NULL, latency_us INTEGER NOT NULL)""")
    val = f"s{score}_w{wave}_k{kills}"
    conn.execute(
        "INSERT INTO semantic_deltas (ts_unix, capability_hash, entity, relation, value, latency_us) VALUES (?,?,?,?,?,?)",
        (int(time.time()), WGSL_HASH, "hyperfold_shooter", "high_score_run", val, int(avg_us)),
    )
    conn.commit()
    rows = conn.execute(
        "SELECT value, latency_us FROM semantic_deltas WHERE entity='hyperfold_shooter' ORDER BY id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    parsed = []
    for v, us in rows:
        try:
            p = v.split("_")
            parsed.append({"score": int(p[0][1:]), "wave": int(p[1][1:]), "kills": int(p[2][1:]), "ms": round(us/1000, 2)})
        except Exception:
            pass
    parsed.sort(key=lambda x: x["score"], reverse=True)
    return parsed[:5]
HTML = r"""<!doctype html><html><head><meta charset=utf-8><title>HYPERFOLD 4D // caprun Iris Xe</title>
<style>
*{box-sizing:border-box;user-select:none}
body{margin:0;background:#050811;color:#e2e8f0;font-family:monospace;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;overflow:hidden}
#wrap{position:relative;width:min(90vmin,720px);height:min(90vmin,720px);border:1px solid #1e3a5f;border-radius:10px;box-shadow:0 0 40px #0ea5e944;overflow:hidden;cursor:crosshair}
canvas{position:absolute;inset:0;width:100%;height:100%}
#hud{position:absolute;top:10px;left:12px;right:12px;display:flex;justify-content:space-between;font-size:13px;pointer-events:none;text-shadow:0 0 8px #000}
.barwrap{width:140px;height:10px;background:#0f172a;border:1px solid #38bdf8;border-radius:5px;overflow:hidden;margin-top:4px}
#shbar{height:100%;width:100%;background:linear-gradient(90deg,#06b6d4,#34d399);transition:width 0.1s}
#foot{position:absolute;bottom:8px;left:12px;right:12px;display:flex;justify-content:space-between;font-size:11px;color:#7dd3fc;pointer-events:none;text-shadow:0 0 6px #000}
#ov{position:absolute;inset:0;background:#050811cc;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:20px}
#ov h1{margin:0 0 8px;color:#38bdf8;letter-spacing:3px;font-size:26px}
#ov p{margin:4px 0;color:#cbd5e1;font-size:13px}
button{margin-top:14px;background:#0284c7;color:#fff;border:1px solid #38bdf8;padding:10px 22px;border-radius:6px;font-family:monospace;font-size:14px;cursor:pointer}
button:hover{background:#0369a1}
#lb{margin-top:14px;font-size:12px;color:#34d399;text-align:left;min-width:260px}
</style></head><body>
<div id=wrap>
  <canvas id=bg width=512 height=512></canvas>
  <canvas id=fg width=512 height=512></canvas>
  <div id=hud>
    <div>SCORE <b id=sc>0</b> &nbsp; WAVE <b id=wv>1</b> &nbsp; x<b id=mp>1</b></div>
    <div>SHIELD <span id=shv>100%</span><div class=barwrap><div id=shbar></div></div></div>
  </div>
  <div id=foot><span id=tel>GPU: -- ms | 60 FPS</span><span>WASD/Mouse: Steer | Click/Space: Fire | Shift: Boost</span></div>
  <div id=ov>
    <h1>HYPERFOLD 4D</h1>
    <p>Live Intel Iris Xe Vulkan Gyroid Tunnel via caprun broker</p>
    <p style="color:#94a3b8">Mouse or WASD banks the 4D tunnel. Click or Space fires twin plasma.</p>
    <button id=startBtn>LAUNCH SORTIE</button>
    <div id=lb></div>
  </div>
</div>
<script>
const bg=document.getElementById('bg'), bctx=bg.getContext('2d'), img=bctx.createImageData(512,512);
const fg=document.getElementById('fg'), ctx=fg.getContext('2d');
const ov=document.getElementById('ov'), scEl=document.getElementById('sc'), wvEl=document.getElementById('wv');
const mpEl=document.getElementById('mp'), shvEl=document.getElementById('shv'), shbar=document.getElementById('shbar');
const tel=document.getElementById('tel'), lb=document.getElementById('lb');

let actx=null;
function sfx(f1,f2,dur,type='sawtooth',vol=0.07){
  try{
    if(!actx) actx=new (window.AudioContext||window.webkitAudioContext)();
    const o=actx.createOscillator(), g=actx.createGain();
    o.type=type; o.frequency.setValueAtTime(f1,actx.currentTime);
    o.frequency.exponentialRampToValueAtTime(f2,actx.currentTime+dur);
    g.gain.setValueAtTime(vol,actx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001,actx.currentTime+dur);
    o.connect(g); g.connect(actx.destination); o.start(); o.stop(actx.currentTime+dur);
  }catch(e){}
}

let running=false, gpuFrame=0, gpuUs=1500, fpsN=0, fpsT=performance.now(), fps='60.0';
let px=0, py=0, tx=0, ty=0, keys={}, firing=false, boost=false;
let score=0, wave=1, kills=0, mult=1, shield=100, fireCd=0, spawnCd=0, flash=0;
let bolts=[], enemies=[], ebolts=[], sparks=[], rings=[];

window.addEventListener('keydown', e=>{ keys[e.code]=true; if(e.code==='Space'){ firing=true; e.preventDefault(); } if(e.code==='ShiftLeft'||e.code==='ShiftRight') boost=true; });
window.addEventListener('keyup', e=>{ keys[e.code]=false; if(e.code==='Space') firing=false; if(e.code==='ShiftLeft'||e.code==='ShiftRight') boost=false; });
fg.addEventListener('pointermove', e=>{
  const r=fg.getBoundingClientRect();
  tx=Math.max(-1,Math.min(1,((e.clientX-r.left)/r.width)*2-1));
  ty=Math.max(-1,Math.min(1,((e.clientY-r.top)/r.height)*2-1));
});
fg.addEventListener('pointerdown', e=>{ if(e.button===2) boost=true; else firing=true; });
window.addEventListener('pointerup', ()=>{ firing=false; boost=false; });
fg.addEventListener('contextmenu', e=>e.preventDefault());

async function pumpGpu(){
  while(true){
    try{
      const cx=Math.round((px*0.5+0.5)*65535)&65535;
      const cy=Math.round((py*0.5+0.5)*65535)&65535;
      const cam=((cx<<16)|cy)>>>0;
      gpuFrame += boost ? 2 : 1;
      const r=await fetch(`/frame?f=${gpuFrame}&c=${cam}`);
      gpuUs=Number(r.headers.get('X-Gpu-Us')||gpuUs);
      const rgb=new Uint8Array(await r.arrayBuffer());
      if(rgb.length===512*512*3){
        const d=img.data;
        for(let i=0,j=0;i<rgb.length;i+=3,j+=4){ d[j]=rgb[i]; d[j+1]=rgb[i+1]; d[j+2]=rgb[i+2]; d[j+3]=255; }
        bctx.putImageData(img,0,0);
      }
    }catch(e){ await new Promise(r=>setTimeout(r,50)); }
  }
}
pumpGpu();
function proj(x,y,z){
  const s = 1.0 / Math.max(0.18, z);
  return { sx: 256 + (x - px*0.45)*210*s, sy: 256 + (y - py*0.45)*210*s, s };
}

function boom(x,y,z,col,n=16){
  rings.push({x,y,z,r:6,life:1,col});
  for(let i=0;i<n;i++){
    const a=Math.random()*6.283, sp=0.02+Math.random()*0.07;
    sparks.push({x,y,z,vx:Math.cos(a)*sp,vy:Math.sin(a)*sp,vz:(Math.random()-0.5)*0.08,life:1,col});
  }
}

function startRun(){
  score=0; wave=1; kills=0; mult=1; shield=100; flash=0;
  bolts=[]; enemies=[]; ebolts=[]; sparks=[]; rings=[];
  running=true; ov.style.display='none'; sfx(220,880,0.2,'triangle',0.09);
}
document.getElementById('startBtn').addEventListener('click', startRun);

async function gameOver(){
  running=false; sfx(180,45,0.45,'sawtooth',0.12);
  ov.style.display='flex';
  ov.querySelector('h1').textContent='HULL BREACHED';
  ov.querySelector('p').textContent=`FINAL SCORE: ${score}  |  WAVE ${wave}  |  KILLS: ${kills}`;
  document.getElementById('startBtn').textContent='FLY AGAIN';
  lb.textContent='Committing run to ~/.cas/graph.db...';
  try{
    const r=await fetch('/score',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({score,wave,kills,avg_us:gpuUs})});
    const top=await r.json();
    lb.innerHTML='<b>~/.cas/graph.db TOP RUNS</b><br>'+top.map((t,i)=>`#${i+1} &nbsp; ${String(t.score).padStart(6,' ')} pts &nbsp; W${t.wave} &nbsp; K${t.kills} &nbsp; (${t.ms}ms)`).join('<br>');
  }catch(e){ lb.textContent='Graph commit skipped.'; }
}

let lastT=performance.now();
function loop(now){
  const dt=Math.min(0.05,(now-lastT)/1000); lastT=now;
  fpsN++; if(now-fpsT>=500){ fps=(fpsN*1000/(now-fpsT)).toFixed(1); fpsN=0; fpsT=now; }
  tel.textContent=`Iris Xe: ${(gpuUs/1000).toFixed(2)} ms | ${fps} FPS | 0 B extracted`;

  let kx=(keys.KeyD||keys.ArrowRight?1:0)-(keys.KeyA||keys.ArrowLeft?1:0);
  let ky=(keys.KeyS||keys.ArrowDown?1:0)-(keys.KeyW||keys.ArrowUp?1:0);
  if(kx||ky){ tx=Math.max(-1,Math.min(1,tx+kx*dt*1.9)); ty=Math.max(-1,Math.min(1,ty+ky*dt*1.9)); }
  px += (tx-px)*Math.min(1,dt*11);
  py += (ty-py)*Math.min(1,dt*11);

  ctx.clearRect(0,0,512,512);
  if(running){
    wave = 1 + Math.floor(kills / 10);
    fireCd -= dt; spawnCd -= dt; flash = Math.max(0, flash - dt*3);
    if(firing && fireCd<=0){
      fireCd = boost ? 0.08 : 0.12;
      bolts.push({x:px-0.11,y:py+0.07,z:0.45},{x:px+0.11,y:py+0.07,z:0.45});
      sfx(820,260,0.07,'square',0.04);
    }
    if(spawnCd<=0){
      spawnCd = Math.max(0.28, 1.05 - wave*0.07);
      const kind = (wave>=2 && Math.random()<0.28) ? 2 : (Math.random()<0.45 ? 1 : 0);
      enemies.push({
        x:(Math.random()*2-1)*0.85, y:(Math.random()*2-1)*0.75, z:6.8,
        hp: kind===2 ? 3 : 1, kind, ph:Math.random()*6.28,
        spd: 1.4 + wave*0.18 + (kind===1?0.5:0), shot:0.9+Math.random()*1.2
      });
    }

    for(let i=bolts.length-1;i>=0;i--){
      const b=bolts[i]; b.z += dt*(boost?12:9.5);
      const p=proj(b.x,b.y,b.z), p2=proj(b.x,b.y,Math.max(0.2,b.z-0.35));
      ctx.strokeStyle='#38bdf8'; ctx.lineWidth=Math.max(1.5,4*p.s);
      ctx.beginPath(); ctx.moveTo(p2.sx,p2.sy); ctx.lineTo(p.sx,p.sy); ctx.stroke();
      if(b.z>7.5) bolts.splice(i,1);
    }

    for(let i=enemies.length-1;i>=0;i--){
      const e=enemies[i];
      e.z -= dt*(e.spd + (boost?1.2:0));
      e.ph += dt*2.6;
      e.x += Math.sin(e.ph)*(e.kind===1?0.55:0.25)*dt;
      e.y += Math.cos(e.ph*0.8)*0.22*dt;
      e.shot -= dt;
      if(e.shot<=0 && e.z>1.6 && e.z<5.2){
        e.shot = Math.max(0.9, 2.2 - wave*0.1);
        ebolts.push({x:e.x,y:e.y,z:e.z,vx:(px-e.x)*0.45,vy:(py-e.y)*0.45});
      }
      let hit=false;
      for(let j=bolts.length-1;j>=0;j--){
        const b=bolts[j];
        if(Math.abs(b.z-e.z)<0.45 && Math.hypot(b.x-e.x,b.y-e.y)<(e.kind===2?0.28:0.22)){
          bolts.splice(j,1); e.hp--; hit=true;
          if(e.hp<=0){
            kills++; score += (e.kind===2?300:100)*mult; mult=Math.min(8,mult+1);
            boom(e.x,e.y,e.z, e.kind===2?'#f43f5e':'#34d399', e.kind===2?24:14);
            sfx(260,60,0.16,'sawtooth',0.08); enemies.splice(i,1); break;
          }else{ boom(e.x,e.y,e.z,'#facc15',6); sfx(520,300,0.05,'triangle',0.05); }
        }
      }
      if(!enemies[i]) continue;
      if(e.z<0.55){
        if(Math.hypot(e.x-px,e.y-py)<0.32){ shield-=22; mult=1; flash=1; sfx(120,40,0.22,'sawtooth',0.1); }
        enemies.splice(i,1); continue;
      }
      const p=proj(e.x,e.y,e.z), rad=Math.max(4,(e.kind===2?26:18)*p.s);
      ctx.save(); ctx.translate(p.sx,p.sy); ctx.rotate(e.ph);
      ctx.strokeStyle = hit?'#fff':(e.kind===2?'#f43f5e':(e.kind===1?'#facc15':'#22d3ee'));
      ctx.lineWidth=2; ctx.beginPath();
      const sides = e.kind===2?6:(e.kind===1?4:3);
      for(let k=0;k<=sides;k++){ const a=k*6.283/sides; k?ctx.lineTo(Math.cos(a)*rad,Math.sin(a)*rad):ctx.moveTo(Math.cos(a)*rad,Math.sin(a)*rad); }
      ctx.stroke(); ctx.restore();
    }

    for(let i=ebolts.length-1;i>=0;i--){
      const eb=ebolts[i]; eb.z -= dt*3.6; eb.x += eb.vx*dt; eb.y += eb.vy*dt;
      const p=proj(eb.x,eb.y,eb.z);
      ctx.fillStyle='#fb7185'; ctx.beginPath(); ctx.arc(p.sx,p.sy,Math.max(2,7*p.s),0,6.283); ctx.fill();
      if(eb.z<0.48){
        if(Math.hypot(eb.x-px,eb.y-py)<0.26){ shield-=14; mult=1; flash=1; sfx(140,55,0.18,'sawtooth',0.09); }
        ebolts.splice(i,1);
      }
    }

    // Ship reticle + banked wings
    const sx=256+px*185, sy=256+py*185;
    ctx.save(); ctx.translate(sx,sy); ctx.rotate(px*0.45);
    ctx.strokeStyle=boost?'#facc15':'#38bdf8'; ctx.lineWidth=2;
    ctx.beginPath(); ctx.moveTo(0,-16); ctx.lineTo(22,12); ctx.lineTo(6,7); ctx.lineTo(0,14); ctx.lineTo(-6,7); ctx.lineTo(-22,12); ctx.closePath(); ctx.stroke();
    ctx.restore();
    // Aiming crosshair ahead
    ctx.strokeStyle='#38bdf888'; ctx.lineWidth=1;
    ctx.beginPath(); ctx.arc(sx,sy,12,0,6.283); ctx.stroke();

    if(flash>0){ ctx.fillStyle=`rgba(244,63,94,${flash*0.35})`; ctx.fillRect(0,0,512,512); }
    scEl.textContent=score; wvEl.textContent=wave; mpEl.textContent=mult;
    shvEl.textContent=Math.max(0,Math.round(shield))+'%';
    shbar.style.width=Math.max(0,shield)+'%';
    if(shield<=0) gameOver();
  }

  for(let i=rings.length-1;i>=0;i--){
    const g=rings[i]; g.life-=dt*2.4; g.r+=dt*90;
    const p=proj(g.x,g.y,g.z);
    ctx.strokeStyle=g.col; ctx.globalAlpha=Math.max(0,g.life); ctx.lineWidth=2;
    ctx.beginPath(); ctx.arc(p.sx,p.sy,g.r*p.s,0,6.283); ctx.stroke(); ctx.globalAlpha=1;
    if(g.life<=0) rings.splice(i,1);
  }
  for(let i=sparks.length-1;i>=0;i--){
    const sp=sparks[i]; sp.x+=sp.vx; sp.y+=sp.vy; sp.z+=sp.vz; sp.life-=dt*2.2;
    const p=proj(sp.x,sp.y,Math.max(0.2,sp.z));
    ctx.fillStyle=sp.col; ctx.globalAlpha=Math.max(0,sp.life);
    ctx.fillRect(p.sx-2,p.sy-2,4,4); ctx.globalAlpha=1;
    if(sp.life<=0) sparks.splice(i,1);
  }
  requestAnimationFrame(loop);
}
requestAnimationFrame(loop);
</script></body></html>"""

class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

class Hdl(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == "/frame":
                q = urllib.parse.parse_qs(u.query)
                fr = int(q.get("f", ["0"])[0])
                cam = int(q.get("c", ["2147516415"])[0]) & 0xFFFFFFFF
                rgb, us = fetch_frame(fr, cam)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Gpu-Us", str(us))
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
    def do_POST(self):
        if self.path == "/score":
            n = int(self.headers.get("Content-Length", "0"))
            d = json.loads(self.rfile.read(n).decode() or "{}")
            top = commit_score(int(d.get("score",0)), int(d.get("wave",1)), int(d.get("kills",0)), int(d.get("avg_us",1500)))
            b = json.dumps(top).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

if __name__ == "__main__":
    print("HYPERFOLD 4D Space Shooter -> http://0.0.0.0:8090")
    try:
        Server(("0.0.0.0", 8090), Hdl).serve_forever()
    except KeyboardInterrupt:
        print("\nHyperfold stopped.")
