#!/usr/bin/env python3
import concurrent.futures, datetime, http.client, socket, ssl, subprocess, threading, time, urllib.parse
import sec_engine

DEFAULT_PATHS = [
    "robots.txt", "sitemap.xml", ".env", ".git/HEAD", "admin", "login",
    "api", "api/v1", "swagger.json", "openapi.json", "metrics", "health",
    "status", "debug", "backup.zip", "config.json", "server-status", "wp-login.php"
]

def web_fuzz(base_url, custom_words, push_fn):
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
    u = urllib.parse.urlparse(base_url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    words = [w.strip().lstrip("/") for w in custom_words.split(",") if w.strip()] or DEFAULT_PATHS
    t0 = time.perf_counter()

    def hit(path):
        try:
            cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
            kw = {"timeout": 1.2}
            if u.scheme == "https": kw["context"] = ssl._create_unverified_context()
            conn = cls(host, port, **kw)
            conn.request("GET", "/" + path, headers={"User-Agent": "caprun-audit/1.0"})
            r = conn.getresponse()
            body = r.read(4096)
            conn.close()
            if r.status != 404:
                push_fn(host, port, f"FUZZ {r.status} /{path}")
                return {"path": "/" + path, "status": r.status, "bytes": len(body), "loc": r.getheader("Location") or ""}
        except Exception:
            pass
        return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        for res in ex.map(hit, words[:128]):
            if res: found.append(res)
    us = int((time.perf_counter() - t0) * 1_000_000)
    sec_engine.log_delta("secsuite_fuzz", "web_enum", f"{host}:{port}_found_{len(found)}", us)
    return {"target": f"{u.scheme}://{host}:{port}", "tested": len(words), "ms": round(us / 1000.0, 1), "found": found}

def tls_dns_audit(host, port=443):
    t0 = time.perf_counter()
    out = {"host": host, "port": port, "tls": {}, "dns": {}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.datetime.utcnow()).days
                subj = dict(x[0] for x in cert.get("subject", []))
                iss = dict(x[0] for x in cert.get("issuer", []))
                out["tls"] = {
                    "proto": ss.version(), "cipher": ss.cipher()[0],
                    "cn": subj.get("commonName", ""), "issuer": iss.get("organizationName", ""),
                    "days_left": days, "sans": [v for _, v in cert.get("subjectAltName", [])][:8]
                }
    except Exception as e:
        out["tls"] = {"error": str(e)}
    try:
        out["dns"]["a"] = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})[:6]
        txt = subprocess.check_output(["dig", "+short", "TXT", host], text=True, timeout=2, stderr=subprocess.DEVNULL)
        out["dns"]["spf"] = "v=spf1" in txt.lower()
        dm = subprocess.check_output(["dig", "+short", "TXT", f"_dmarc.{host}"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        out["dns"]["dmarc"] = "v=dmarc1" in dm.lower()
    except Exception:
        pass
    us = int((time.perf_counter() - t0) * 1_000_000)
    sec_engine.log_delta("secsuite_tls", "tls_dns_audit", f"{host}:{port}", us)
    return out
CANARIES = {}
THREATS = {}
THREAT_LOCK = threading.Lock()

BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "redis": b"-NOAUTH Authentication required.\r\n",
    "http": b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Admin\"\r\nContent-Length: 0\r\n\r\n",
}

def record_threat(ip, reason, port):
    with THREAT_LOCK:
        t = THREATS.setdefault(ip, {"ip": ip, "hits": 0, "ports": set(), "last_reason": "", "last_ts": 0})
        t["hits"] += 1
        t["ports"].add(int(port))
        t["last_reason"] = reason
        t["last_ts"] = int(time.time())

def get_threats():
    with THREAT_LOCK:
        rows = []
        for ip, t in sorted(THREATS.items(), key=lambda kv: kv[1]["hits"], reverse=True):
            rows.append({
                "ip": ip, "hits": t["hits"], "ports": sorted(t["ports"])[:10],
                "reason": t["last_reason"],
                "ufw": f"sudo ufw insert 1 deny from {ip} to any",
                "nft": f"sudo nft add rule inet filter input ip saddr {ip} drop"
            })
        return rows

def toggle_canary(port, profile, push_fn):
    port = int(port)
    if port in CANARIES:
        CANARIES[port]["stop"].set()
        del CANARIES[port]
        return {"port": port, "active": False, "active_ports": sorted(CANARIES.keys())}
    stop = threading.Event()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    srv.settimeout(0.5)
    banner = BANNERS.get(profile, BANNERS["ssh"])

    def loop():
        try:
            while not stop.is_set():
                try:
                    c, (rip, _) = srv.accept()
                except socket.timeout:
                    continue
                try:
                    c.settimeout(1.0)
                    c.sendall(banner)
                    data = c.recv(256).decode("utf-8", errors="replace").strip()[:48]
                except Exception:
                    data = ""
                finally:
                    c.close()
                tag = f"CANARY:{profile}:{port} {rip} {data}"
                for _ in range(4): push_fn(rip, port, tag)
                record_threat(rip, f"canary_{profile}:{port}", port)
                sec_engine.log_delta("canary_trap", "intrusion_trip", f"{rip}_p{port}_{profile}", 150)
        finally:
            srv.close()

    CANARIES[port] = {"stop": stop, "profile": profile}
    threading.Thread(target=loop, daemon=True).start()
    sec_engine.log_delta("canary_trap", "trap_armed", f"port_{port}_{profile}", 100)
    return {"port": port, "active": True, "profile": profile, "active_ports": sorted(CANARIES.keys())}
