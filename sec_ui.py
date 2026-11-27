HTML = r"""<!doctype html><html><head><meta charset=utf-8><title>caprun // SecSuite OpsDeck</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#050811;color:#e2e8f0;font-family:monospace;padding:12px}
header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1e3a5f;padding-bottom:8px;margin-bottom:12px}
h2{margin:0;color:#38bdf8;font-size:16px;letter-spacing:1px}
.grid{display:grid;grid-template-columns:minmax(320px,520px) 1fr;gap:14px;align-items:start}
@media(max-width:960px){.grid{grid-template-columns:1fr}}
.card{background:#0b1222;border:1px solid #1e3a5f;border-radius:8px;padding:12px}
.bar{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
button{background:#1e293b;color:#38bdf8;border:1px solid #334155;padding:6px 10px;border-radius:5px;cursor:pointer;font-family:monospace;font-size:12px}
button.on,button.act{background:#0284c7;color:#fff;border-color:#38bdf8}
button.warn{background:#7f1d1d;color:#fecaca;border-color:#ef4444}
input{background:#050811;color:#e2e8f0;border:1px solid #334155;padding:6px 8px;border-radius:5px;font-family:monospace;font-size:12px}
canvas{width:100%;height:auto;border:1px solid #1e3a5f;border-radius:6px;display:block}
#stat{font-size:11px;color:#34d399;margin:6px 0 2px}
#flow{font-size:11px;color:#f472b6;min-height:15px;margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tab{display:none}.tab.on{display:block}
table{width:100%;border-collapse:collapse;font-size:11px;margin-top:8px}
th,td{border-bottom:1px solid #1e293b;padding:5px 6px;text-align:left}
th{color:#7dd3fc}
pre{background:#050811;border:1px solid #1e293b;padding:8px;border-radius:5px;font-size:11px;overflow:auto;max-height:280px;color:#34d399}
</style></head><body>
<header>
  <h2>CAPRUN // SECSUITE OPSDECK (262k VRAM Cortex + Vulkan Broker)</h2>
  <span style="font-size:11px;color:#94a3b8">Authorized Lab & Local Silicon Defense</span>
</header>
<div class=grid>
  <div class=card>
    <div class=bar>
      <button data-m="0" class="on">Composite</button>
      <button data-m="1">Anomalies</button>
      <button data-m="2">Baseline</button>
      <button id="rst">Clear VRAM</button>
    </div>
    <div id=stat>connecting to Iris Xe...</div>
    <div id=flow>waiting for telemetry...</div>
    <canvas id=c width=512 height=512></canvas>
  </div>
  <div class=card>
    <div class=bar>
      <button data-t="recon" class="on">1. Recon & Audit</button>
      <button data-t="gpu">2. GPU Keyspace Lab</button>
      <button data-t="graph">3. Forensics</button>
      <button data-t="off">4. Offense (Web/TLS)</button>
      <button data-t="def">5. Defense</button>
      <button data-t="ba">6. BlackArch + MSF</button>
      <button data-t="jtr">7. Next-Gen JtR + Hardening</button>
      <button data-t="ng">8. Silicon Lab</button>
    </div>
    <div id=t_recon class="tab on">
      <div class=bar>
        <input id=host value="127.0.0.1" style="width:150px" placeholder="Target IP">
        <input id=ports value="22,53,80,443,3000,5000,8000,8080,8090,8095,9000-9040" style="flex:1">
        <button class=act id=goScan>Run Scan</button>
      </div>
      <div id=scanMeta style="font-size:11px;color:#94a3b8">Scans feed live hits directly into the 512x512 VRAM Cortex.</div>
      <table><thead><tr><th>Port</th><th>ms</th><th>Banner / Service</th><th>Audit</th></tr></thead><tbody id=scanBody></tbody></table>
    </div>
    <div id=t_gpu class="tab">
      <div class=bar>
        <input id=gEl value="262144" style="width:90px" title="Threads">
        <input id=gIt value="512" style="width:70px" title="Rounds">
        <button class=act id=goGpu>Run WGSL Hash Sweep</button>
        <button class=warn id=goPoison>Test Poisoned WGSL</button>
      </div>
      <pre id=gpuOut>Ready. Dispatches validated WGSL to ~/.cas/vulkan.sock.</pre>
    </div>
    <div id=t_graph class="tab">
      <div class=bar>
        <button class=act id=goGraph>Refresh Provenance</button>
        <button id=dlRep>Export JSON Report</button>
      </div>
      <table><thead><tr><th>ID</th><th>Entity</th><th>Relation</th><th>Value</th><th>ms</th></tr></thead><tbody id=gBody></tbody></table>
    </div>
    <div id=t_off class="tab">
      <div class=bar>
        <input id=fUrl value="http://127.0.0.1:8095" style="width:170px">
        <input id=fWords placeholder="custom paths comma-sep (blank=default)" style="flex:1">
        <button class=act id=goFuzz>Web Fuzz</button>
      </div>
      <table><thead><tr><th>Path</th><th>Status</th><th>Bytes</th><th>Redirect</th></tr></thead><tbody id=fBody></tbody></table>
      <div class=bar style="margin-top:10px">
        <input id=tHost value="github.com" style="flex:1" placeholder="TLS/DNS Host">
        <input id=tPort value="443" style="width:60px">
        <button class=act id=goTls>TLS + DNS Audit</button>
      </div>
      <pre id=tlsOut>Ready for TLS cipher, cert expiry, and SPF/DMARC audit.</pre>
    </div>
    <div id=t_def class="tab">
      <div class=bar>
        <input id=cPort value="2222" style="width:70px">
        <select id=cProf style="background:#050811;color:#e2e8f0;border:1px solid #334155;padding:5px;border-radius:5px;font-family:monospace">
          <option value="ssh">Fake SSH</option><option value="redis">Fake Redis</option><option value="http">Fake Admin HTTP</option>
        </select>
        <button class=warn id=goCan>Arm / Disarm Canary</button>
        <button id=goThr>Refresh Threats</button>
      </div>
      <div id=canStat style="font-size:11px;color:#fbbf24;margin-bottom:6px">Active Canaries: none</div>
      <table><thead><tr><th>Attacker IP</th><th>Hits</th><th>Reason</th><th>Ready-to-Run Block Rule</th></tr></thead><tbody id=thrBody></tbody></table>
    </div>
    <div id=t_ba class="tab">
      <div class=bar>
        <input id=baTgt value="127.0.0.1" style="width:150px" placeholder="Target">
        <select id=baCat style="background:#050811;color:#e2e8f0;border:1px solid #334155;padding:5px;border-radius:5px;font-family:monospace">
          <option value="all">All Categories</option><option value="caprun">caprun</option><option value="recon">recon</option>
          <option value="web">web</option><option value="exploit">exploit</option><option value="sniff">sniff</option><option value="crack">crack</option>
        </select>
        <button id=baRef>Refresh Arsenal</button>
      </div>
      <div id=baGrid class=bar style="max-height:110px;overflow:auto"></div>
      <div class=bar style="margin-top:6px">
        <span id=msfP style="font-size:11px;color:#f472b6;align-self:center">msf6 &gt;</span>
        <input id=msfIn style="flex:1" placeholder="help | search | use <mod> | set RHOSTS 127.0.0.1 | run">
        <button class=act id=msfGo>Exec</button>
      </div>
      <pre id=msfOut>Caprun-MSF + BlackArch Deck ready. Type 'help' or click any arsenal tool above.</pre>
    </div>
    <div id=t_jtr class="tab">
      <div class=bar>
        <input id=jPw value="flint26" style="width:130px" placeholder="Test plaintext">
        <button id=goGenH>Hash Target</button>
        <input id=jMask value="flint?d?d" style="width:130px" placeholder="Mask (?f ?l ?u ?d ?a)">
        <button class=warn id=goJtr>Run Iris Xe Frequency Sweep</button>
      </div>
      <div class=bar>
        <input id=jHash style="flex:1" placeholder="64-char SHA-256 hex digest">
      </div>
      <pre id=jtrOut>Masks: ?f=freq(etaoin...) ?l=lower ?u=upper ?d=digit ?a=all+sym. Auto-generates scrypt defense on hit.</pre>
    </div>
    <div id=t_ng class="tab">
      <div class=bar>
        <input id=ngXor value="hex:2a363632786d6d21706c202330296c2d27366d202723212d2c" style="flex:1" placeholder="Hex or raw payload">
        <button class=warn id=goNgXor>GPU XOR + Entropy (YARA)</button>
      </div>
      <div class=bar>
        <input id=ngBip value="203.0.113.42" style="width:120px" placeholder="Dest IP">
        <input id=ngBts value="0, 59.2, 121.1, 179.8, 240.5, 298.9, 361.0, 419.4" style="flex:1" placeholder="Timestamps (sec)">
        <button class=act id=goNgBcn>GPU C2 Beacon Hunt</button>
      </div>
      <div class=bar>
        <input id=ngDga value="github.com, cloudflare.com, xq9k2m7v4p1z.top, 4a6f686e2d657866696c2d3031.c2.bad.net" style="flex:1" placeholder="Comma-sep domains">
        <button class=act id=goNgDga>GPU DGA / Tunnel Scan</button>
      </div>
      <pre id=ngOut>Silicon Lab: YARA, Zeek, and DNS blocklists rethought as WGSL parallel kernels + auto-defense rules.</pre>
    </div>
  </div>
</div>
<script>
const c=document.getElementById('c'), ctx=c.getContext('2d'), img=ctx.createImageData(512,512);
const stat=document.getElementById('stat'), flow=document.getElementById('flow');
let mode=0, tick=0, fpsN=0, fpsT=performance.now(), fps='60.0';

document.querySelectorAll('[data-m]').forEach(b=>b.onclick=()=>{
  mode=Number(b.dataset.m); document.querySelectorAll('[data-m]').forEach(x=>x.classList.toggle('on',x===b));
});
document.querySelectorAll('[data-t]').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('[data-t]').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x.id==='t_'+b.dataset.t));
  if(b.dataset.t==='graph') loadGraph();
});
document.getElementById('rst').onclick=()=>fetch('/reset');

async function step(){
  try{
    const r=await fetch(`/step?t=${tick++}&m=${mode}`);
    const us=Number(r.headers.get('X-Gpu-Us')||0), surp=Number(r.headers.get('X-Surprise')||0), fl=r.headers.get('X-Flow')||'idle';
    const rgb=new Uint8Array(await r.arrayBuffer());
    if(rgb.length===512*512*3){
      const d=img.data;
      for(let i=0,j=0;i<rgb.length;i+=3,j+=4){ d[j]=rgb[i]; d[j+1]=rgb[i+1]; d[j+2]=rgb[i+2]; d[j+3]=255; }
      ctx.putImageData(img,0,0);
    }
    fpsN++; const now=performance.now();
    if(now-fpsT>=500){ fps=(fpsN*1000/(now-fpsT)).toFixed(1); fpsN=0; fpsT=now; }
    stat.textContent=`Iris Xe: ${(us/1000).toFixed(2)} ms | ${fps} FPS | Surprise: ${surp}`;
    if(fl!=='idle') flow.textContent=fl;
  }catch(e){ stat.textContent='Broker error: '+e.message; }
  requestAnimationFrame(step);
}
step();

document.getElementById('goScan').onclick=async()=>{
  const host=document.getElementById('host').value.trim(), ports=document.getElementById('ports').value.trim();
  document.getElementById('scanMeta').textContent=`Scanning ${host}...`;
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,ports})});
  const d=await r.json();
  document.getElementById('scanMeta').textContent=`${d.host}: ${d.open.length} open / ${d.scanned} probed in ${d.elapsed_ms} ms (logged to graph.db)`;
  document.getElementById('scanBody').innerHTML=d.open.map(x=>`<tr><td><b>${x.port}</b></td><td>${x.ms}</td><td>${x.banner}</td><td>${x.notes}</td></tr>`).join('') || '<tr><td colspan=4>No open ports in range.</td></tr>';
};

async function runGpu(poison){
  const elements=Number(document.getElementById('gEl').value)||262144;
  const iters=Number(document.getElementById('gIt').value)||512;
  document.getElementById('gpuOut').textContent='Dispatching to Vulkan broker...';
  const r=await fetch('/api/gpu_hash',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({elements,iters,poison})});
  document.getElementById('gpuOut').textContent=JSON.stringify(await r.json(),null,2);
}
document.getElementById('goGpu').onclick=()=>runGpu(false);
document.getElementById('goPoison').onclick=()=>runGpu(true);

async function loadGraph(){
  const r=await fetch('/api/graph'); const rows=await r.json();
  document.getElementById('gBody').innerHTML=rows.map(x=>`<tr><td>${x.id}</td><td>${x.entity}</td><td>${x.relation}</td><td>${x.value}</td><td>${x.ms}</td></tr>`).join('');
}
document.getElementById('goGraph').onclick=loadGraph;
document.getElementById('dlRep').onclick=()=>{ window.location='/api/report'; };

document.getElementById('goFuzz').onclick=async()=>{
  const url=document.getElementById('fUrl').value.trim(), words=document.getElementById('fWords').value.trim();
  const r=await fetch('/api/fuzz',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url,words})});
  const d=await r.json();
  document.getElementById('fBody').innerHTML=d.found.map(x=>`<tr><td>${x.path}</td><td><b>${x.status}</b></td><td>${x.bytes}</td><td>${x.loc}</td></tr>`).join('') || '<tr><td colspan=4>No hits.</td></tr>';
};
document.getElementById('goTls').onclick=async()=>{
  const host=document.getElementById('tHost').value.trim(), port=Number(document.getElementById('tPort').value)||443;
  const r=await fetch('/api/tls',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,port})});
  document.getElementById('tlsOut').textContent=JSON.stringify(await r.json(),null,2);
};
async function loadThreats(){
  const r=await fetch('/api/threats'); const d=await r.json();
  document.getElementById('canStat').textContent='Active Canaries: '+(d.canaries.length?d.canaries.join(', '):'none');
  document.getElementById('thrBody').innerHTML=d.threats.map(x=>`<tr><td><b>${x.ip}</b></td><td>${x.hits}</td><td>${x.reason}</td><td><code>${x.ufw}</code></td></tr>`).join('') || '<tr><td colspan=4>No threat trips yet.</td></tr>';
}
document.getElementById('goCan').onclick=async()=>{
  const port=Number(document.getElementById('cPort').value)||2222, profile=document.getElementById('cProf').value;
  await fetch('/api/canary',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port,profile})});
  loadThreats();
};
document.getElementById('goThr').onclick=loadThreats;

let BA_TOOLS=[];
async function loadBA(){
  const r=await fetch('/api/ba_list'); BA_TOOLS=await r.json(); renderBA();
}
function renderBA(){
  const cat=document.getElementById('baCat').value;
  const g=document.getElementById('baGrid');
  g.innerHTML=BA_TOOLS.filter(t=>cat==='all'||t.cat===cat).map(t=>
    `<button title="${t.desc}" style="opacity:${t.installed?1:0.45}" onclick="runBA('${t.id}')">[${t.cat}] ${t.id}</button>`
  ).join('');
}
window.runBA=async(id)=>{
  const target=document.getElementById('baTgt').value.trim();
  document.getElementById('msfOut').textContent=`Running ${id} against ${target}...`;
  const r=await fetch('/api/ba_run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,target})});
  const d=await r.json();
  document.getElementById('msfOut').textContent=`[${id} | ${d.ms||0}ms]
`+d.output;
};
async function sendMSF(){
  const inp=document.getElementById('msfIn'), cmd=inp.value.trim(); if(!cmd) return;
  inp.value='';
  const r=await fetch('/api/msf',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd})});
  const d=await r.json();
  document.getElementById('msfP').textContent=`msf6 (${d.prompt.split('/').pop()}) >`;
  document.getElementById('msfOut').textContent=`$ ${cmd}
`+d.output;
}
document.getElementById('baCat').onchange=renderBA;
document.getElementById('baRef').onclick=loadBA;
document.getElementById('msfGo').onclick=sendMSF;
document.getElementById('msfIn').addEventListener('keydown', e=>{ if(e.key==='Enter') sendMSF(); });
loadBA();

async function genTestHash(){
  const pw=document.getElementById('jPw').value;
  const r=await fetch('/api/hash_gen',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pw})});
  const d=await r.json(); document.getElementById('jHash').value=d.sha256;
}
document.getElementById('goGenH').onclick=genTestHash;
document.getElementById('goJtr').onclick=async()=>{
  if(!document.getElementById('jHash').value) await genTestHash();
  const hash=document.getElementById('jHash').value.trim(), mask=document.getElementById('jMask').value.trim();
  document.getElementById('jtrOut').textContent='Compiling WGSL frequency kernel & sweeping on Intel Iris Xe...';
  const r=await fetch('/api/jtr_sweep',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hash,mask})});
  document.getElementById('jtrOut').textContent=JSON.stringify(await r.json(),null,2);
};
genTestHash();

document.getElementById('goNgXor').onclick=async()=>{
  const payload=document.getElementById('ngXor').value;
  document.getElementById('ngOut').textContent='Running 256-key parallel XOR + Shannon entropy on Iris Xe...';
  const r=await fetch('/api/ng_xor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload})});
  document.getElementById('ngOut').textContent=JSON.stringify(await r.json(),null,2);
};
document.getElementById('goNgBcn').onclick=async()=>{
  const ip=document.getElementById('ngBip').value, ts=document.getElementById('ngBts').value;
  document.getElementById('ngOut').textContent='Running WGSL C2 periodicity sweep on Iris Xe...';
  const r=await fetch('/api/ng_beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,ts})});
  document.getElementById('ngOut').textContent=JSON.stringify(await r.json(),null,2);
};
document.getElementById('goNgDga').onclick=async()=>{
  const domains=document.getElementById('ngDga').value;
  document.getElementById('ngOut').textContent='Scoring DGA & DNS-tunnel entropy on Iris Xe...';
  const r=await fetch('/api/ng_dga',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domains})});
  document.getElementById('ngOut').textContent=JSON.stringify(await r.json(),null,2);
};
</script></body></html>"""
