#!/usr/bin/env python3
import os, shlex, shutil, subprocess, time
import sec_engine, sec_modules

CATALOG = [
    {"id": "nmap_fast", "cat": "recon", "bin": "nmap", "cmd": "nmap -F -T4 {target}", "desc": "Fast top-100 port scan"},
    {"id": "nmap_svc", "cat": "recon", "bin": "nmap", "cmd": "nmap -sV --top-ports 25 {target}", "desc": "Service version fingerprint"},
    {"id": "whois", "cat": "recon", "bin": "whois", "cmd": "whois {target}", "desc": "Domain/IP WHOIS record"},
    {"id": "dig_any", "cat": "recon", "bin": "dig", "cmd": "dig +short ANY {target}", "desc": "DNS record dump"},
    {"id": "curl_hdr", "cat": "web", "bin": "curl", "cmd": "curl -sI --max-time 4 {target}", "desc": "HTTP response header probe"},
    {"id": "nikto", "cat": "web", "bin": "nikto", "cmd": "nikto -h {target} -maxtime 20s", "desc": "Web vulnerability scan"},
    {"id": "gobuster", "cat": "web", "bin": "gobuster", "cmd": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q", "desc": "Directory brute-forcer"},
    {"id": "sqlmap", "cat": "web", "bin": "sqlmap", "cmd": "sqlmap -u {target} --batch --level=1 --risk=1", "desc": "Automated SQLi audit"},
    {"id": "msf_ver", "cat": "exploit", "bin": "msfconsole", "cmd": "msfconsole -q -x 'version; exit'", "desc": "Metasploit Framework check"},
    {"id": "searchsploit", "cat": "exploit", "bin": "searchsploit", "cmd": "searchsploit {target}", "desc": "Exploit-DB local search"},
    {"id": "tshark", "cat": "sniff", "bin": "tshark", "cmd": "tshark -c 20 -a duration:5", "desc": "20-packet live capture"},
    {"id": "ss_listen", "cat": "sniff", "bin": "ss", "cmd": "ss -tulnp", "desc": "Active local listening sockets"},
    {"id": "hashcat_b", "cat": "crack", "bin": "hashcat", "cmd": "hashcat -b -m 0", "desc": "MD5 GPU benchmark"},
    {"id": "caprun_gpu", "cat": "caprun", "bin": "./target/release/caprun", "cmd": "./target/release/caprun bench-gpu", "desc": "1 TFLOPS Vulkan benchmark"},
    {"id": "caprun_esc", "cat": "caprun", "bin": "./target/release/caprun", "cmd": "./target/release/caprun --test-escape", "desc": "3.65ms seccomp-BPF escape test"},
]

def list_catalog():
    out = []
    for t in CATALOG:
        ok = os.path.exists(t["bin"]) if "/" in t["bin"] else (shutil.which(t["bin"]) is not None)
        out.append({**t, "installed": ok})
    return out

def run_tool(tool_id, target, push_fn):
    tool = next((t for t in CATALOG if t["id"] == tool_id), None)
    if not tool: return {"ok": False, "output": f"Unknown tool: {tool_id}"}
    safe_t = "".join(c for c in (target or "127.0.0.1") if c.isalnum() or c in ".:/-_")
    argv = shlex.split(tool["cmd"].format(target=safe_t))
    if not (os.path.exists(argv[0]) if "/" in argv[0] else shutil.which(argv[0])):
        return {"ok": False, "output": f"Binary '{argv[0]}' not installed. Install via apt/BlackArch container."}
    t0 = time.perf_counter()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        txt = (p.stdout + ("\n" + p.stderr if p.stderr else "")).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        txt = "Timed out after 30s."
    except Exception as e:
        txt = f"Exec error: {e}"
    us = int((time.perf_counter() - t0) * 1_000_000)
    push_fn(safe_t, 4444, f"BA:{tool_id} {safe_t}")
    sec_engine.log_delta("blackarch_deck", tool_id, f"{safe_t}_{len(txt)}B", us)
    return {"ok": True, "tool": tool_id, "ms": round(us / 1000.0, 1), "output": txt[:8000]}
MSF_MODS = [
    "auxiliary/scanner/caprun/tcp_banner",
    "auxiliary/scanner/caprun/web_fuzz",
    "auxiliary/scanner/caprun/tls_audit",
    "auxiliary/gpu/caprun/wgsl_keyspace",
    "exploit/caprun/seccomp_escape_sim",
]

STATE = {
    "module": "auxiliary/scanner/caprun/tcp_banner",
    "opts": {"RHOSTS": "127.0.0.1", "RPORT": "8095", "PORTS": "22,80,443,8080,8090,8095", "THREADS": "262144", "ROUNDS": "512"},
}

def msf_exec(cmdline, push_fn):
    line = (cmdline or "").strip()
    if not line: return {"prompt": STATE["module"], "output": ""}
    parts = line.split()
    cmd = parts[0].lower()

    if cmd == "help":
        return {"prompt": STATE["module"], "output":
            "Commands:\n  search <term>          List caprun + MSF modules\n  use <module>           Select module (caprun or real MSF path)\n  show options           Display current module options\n  set <KEY> <VAL>        Set RHOSTS, RPORT, PORTS, THREADS, ROUNDS\n  run / exploit          Execute module (logs to graph.db + Cortex)\n  msf <raw_cmd>          Run raw command in native msfconsole"}

    if cmd == "search":
        q = parts[1].lower() if len(parts) > 1 else ""
        hits = [m for m in MSF_MODS if q in m.lower()]
        return {"prompt": STATE["module"], "output": "\n".join(hits) or "No built-in match. You can still 'use <any/msf/module>' if msfconsole is installed."}

    if cmd == "use" and len(parts) > 1:
        STATE["module"] = parts[1]
        return {"prompt": STATE["module"], "output": f"[*] Using {STATE['module']}"}

    if cmd == "show":
        lines = [f"Module: {STATE['module']}"] + [f"  {k:10s} => {v}" for k, v in STATE["opts"].items()]
        return {"prompt": STATE["module"], "output": "\n".join(lines)}

    if cmd == "set" and len(parts) >= 3:
        k, v = parts[1].upper(), " ".join(parts[2:])
        STATE["opts"][k] = v
        return {"prompt": STATE["module"], "output": f"{k} => {v}"}

    if cmd == "msf" and len(parts) > 1:
        if not shutil.which("msfconsole"):
            return {"prompt": STATE["module"], "output": "[-] msfconsole not found on PATH."}
        raw = line[4:].strip()
        p = subprocess.run(["msfconsole", "-q", "-x", f"{raw}; exit"], capture_output=True, text=True, timeout=45)
        sec_engine.log_delta("msf_bridge", "raw_exec", raw[:40], 1000)
        return {"prompt": STATE["module"], "output": (p.stdout + p.stderr)[:8000]}

    if cmd in ("run", "exploit"):
        m, o = STATE["module"], STATE["opts"]
        push_fn(o["RHOSTS"], int(o["RPORT"]) if o["RPORT"].isdigit() else 4444, f"MSF {m}")
        if m == "auxiliary/scanner/caprun/tcp_banner":
            r = sec_engine.scan_target(o["RHOSTS"], o["PORTS"], push_fn)
            lines = [f"[+] {r['host']}:{x['port']} ({x['ms']}ms) {x['banner']} [{x['notes']}]" for x in r["open"]]
            return {"prompt": m, "output": f"[*] Probed {r['scanned']} ports in {r['elapsed_ms']} ms\n" + ("\n".join(lines) or "[-] No open ports.")}
        if m == "auxiliary/scanner/caprun/web_fuzz":
            r = sec_modules.web_fuzz(f"http://{o['RHOSTS']}:{o['RPORT']}", "", push_fn)
            lines = [f"[+] {x['status']} {x['path']} ({x['bytes']}B)" for x in r["found"]]
            return {"prompt": m, "output": f"[*] Fuzzed {r['target']} in {r['ms']} ms\n" + ("\n".join(lines) or "[-] No hits.")}
        if m == "auxiliary/scanner/caprun/tls_audit":
            r = sec_modules.tls_dns_audit(o["RHOSTS"], int(o["RPORT"]) if o["RPORT"].isdigit() else 443)
            return {"prompt": m, "output": str(r)}
        if m == "auxiliary/gpu/caprun/wgsl_keyspace":
            r = sec_engine.gpu_wgsl_audit(int(o["THREADS"]), int(o["ROUNDS"]), int(time.time()) & 0xFFFF, False)
            return {"prompt": m, "output": f"[+] Iris Xe WGSL sweep: {r}"}
        if m == "exploit/caprun/seccomp_escape_sim":
            return {"prompt": m, "output": run_tool("caprun_esc", o["RHOSTS"], push_fn)["output"]}
        if shutil.which("msfconsole"):
            rc = f"use {m}; set RHOSTS {o['RHOSTS']}; set RPORT {o['RPORT']}; run; exit"
            p = subprocess.run(["msfconsole", "-q", "-x", rc], capture_output=True, text=True, timeout=60)
            sec_engine.log_delta("msf_bridge", "module_run", m[:44], 1000)
            return {"prompt": m, "output": (p.stdout + p.stderr)[:8000]}
        return {"prompt": m, "output": f"[-] '{m}' requires msfconsole installed locally. Try 'search caprun' for built-in modules."}

    return {"prompt": STATE["module"], "output": f"Unknown command '{cmd}'. Type 'help'."}
