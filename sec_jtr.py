#!/usr/bin/env python3
import hashlib, math, os, socket, struct, time
import cortex, sec_engine

CHARSETS = {
    "f": "etaoinshrdlcumwfgypbvkjxqz0123456789",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "a": "etaoinshrdlcumwfgypbvkjxqz0123456789!@#$%&*_-",
}

K_SHA256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]

def parse_mask(mask):
    slots = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask) and mask[i + 1] in CHARSETS:
            slots.append(CHARSETS[mask[i + 1]])
            i += 2
        else:
            slots.append(mask[i])
            i += 1
    return slots[:55]

def decode_idx(idx, slots):
    chars = []
    rem = idx
    for cs in slots:
        n = len(cs)
        if n == 1:
            chars.append(cs)
        else:
            chars.append(cs[rem % n])
            rem //= n
    return "".join(chars)

def build_sha256_wgsl(slots, target_hex):
    raw = bytes.fromhex(target_hex)
    t = struct.unpack(">8I", raw)
    m_len = len(slots)
    pack_lines = []
    for pos, cs in enumerate(slots):
        wi = pos >> 2
        sh = (3 - (pos & 3)) * 8
        if len(cs) == 1:
            val = ord(cs)
            pack_lines.append(f"    w[{wi}u] = w[{wi}u] | ({val}u << {sh}u);")
        else:
            n = len(cs)
            arr = ",".join(f"{ord(c)}u" for c in cs)
            pack_lines.append(
                f"    {{ var cs_{pos} = array<u32, {n}>({arr}); "
                f"let ch = cs_{pos}[rem % {n}u]; rem = rem / {n}u; "
                f"w[{wi}u] = w[{wi}u] | (ch << {sh}u); }}"
            )
    term_wi = m_len >> 2
    term_sh = (3 - (m_len & 3)) * 8
    k_str = ",".join(f"0x{x:08x}u" for x in K_SHA256)

    return f"""struct Params {{ seed: u32, count: u32, iters: u32, _pad: u32 }};
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;

fn rotr(x: u32, n: u32) -> u32 {{ return (x >> n) | (x << (32u - n)); }}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {{
    let tid = gid.x;
    if (tid >= params.count) {{ return; }}
    let gidx = params.seed + tid;
    if (gidx >= params.iters) {{ out_buf[tid] = 0.0; return; }}
    var rem = gidx;
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i = i + 1u) {{ w[i] = 0u; }}
{chr(10).join(pack_lines)}
    w[{term_wi}u] = w[{term_wi}u] | (0x80u << {term_sh}u);
    w[15u] = {m_len * 8}u;
    for (var i = 16u; i < 64u; i = i + 1u) {{
        let s0 = rotr(w[i - 15u], 7u) ^ rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        let s1 = rotr(w[i - 2u], 17u) ^ rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }}
    var k_tbl = array<u32, 64>({k_str});
    var a = 0x6a09e667u; var b = 0xbb67ae85u; var c = 0x3c6ef372u; var d = 0xa54ff53au;
    var e = 0x510e527fu; var f = 0x9b05688cu; var g = 0x1f83d9abu; var h = 0x5be0cd19u;
    for (var i = 0u; i < 64u; i = i + 1u) {{
        let S1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
        let ch = (e & f) ^ ((~e) & g);
        let t1 = h + S1 + ch + k_tbl[i] + w[i];
        let S0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }}
    let m0 = (0x6a09e667u + a) == {t[0]}u;
    let m1 = (0xbb67ae85u + b) == {t[1]}u;
    let m2 = (0x3c6ef372u + c) == {t[2]}u;
    let m3 = (0xa54ff53au + d) == {t[3]}u;
    let m4 = (0x510e527fu + e) == {t[4]}u;
    let m5 = (0x9b05688cu + f) == {t[5]}u;
    let m6 = (0x1f83d9abu + g) == {t[6]}u;
    let m7 = (0x5be0cd19u + h) == {t[7]}u;
    out_buf[tid] = select(0.0, 1.0, m0 && m1 && m2 && m3 && m4 && m5 && m6 && m7);
}}"""
def _dispatch_wgsl(_sock, elements, seed, total_ks, wgsl_hex):
    msg = f"WGSL:{elements}:{seed}:{total_ks}:{wgsl_hex}\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(cortex.SOCK)
        sock.sendall(msg)
        buf = b""
        while not buf.endswith(b"\n"):
            ch = sock.recv(4096)
            if not ch: break
            buf += ch
    reply = buf.decode(errors="replace").strip()
    if not reply.startswith("OK:"):
        raise RuntimeError(reply)
    _, cs, us, adapter = reply.split(":", 3)
    return cs, int(us), adapter

def build_hardening(plaintext, mask, target_hex):
    salt = os.urandom(16)
    dk = hashlib.scrypt(plaintext.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    scrypt_phc = f"$scrypt$ln=14,r=8,p=1${salt.hex()}${dk.hex()}"
    has_literal = any(len(s) == 1 for s in parse_mask(mask))
    rules = [
        "1. Replace raw SHA-256 storage with salted Argon2id (m=65536,t=3,p=4) or scrypt.",
        "2. Enforce >= 14-char passphrase floor (65+ bits entropy) to defeat GPU SIMD sweeps.",
    ]
    if has_literal:
        rules.append(f"3. Block predictable dictionary/organizational prefixes in mask '{mask}'.")
    return {"scrypt_replacement": scrypt_phc, "policy_rules": rules}

def gpu_audit_keyspace(target_hex, mask, push_fn, max_candidates=4_194_304):
    target_hex = target_hex.strip().lower()
    if len(target_hex) != 64:
        return {"ok": False, "error": "Provide a 64-char SHA-256 hex digest."}
    slots = parse_mask(mask.strip() or "?f?f?f?f")
    if not slots:
        return {"ok": False, "error": "Invalid mask."}
    total_ks = 1
    for cs in slots:
        total_ks *= len(cs)
    sweep_cap = min(total_ks, max_candidates)
    wgsl_hex = build_sha256_wgsl(slots, target_hex).encode().hex()
    batch_sz = min(262144, sweep_cap)

    t0 = time.perf_counter()
    gpu_us_sum = 0
    adapter = "Vulkan"
    recovered = None
    tested = 0

    zero_cs, _, adapter = _dispatch_wgsl(None, batch_sz, sweep_cap, sweep_cap, wgsl_hex)
    for offset in range(0, sweep_cap, batch_sz):
        cs, us, adapter = _dispatch_wgsl(None, batch_sz, offset, sweep_cap, wgsl_hex)
        gpu_us_sum += us
        end = min(sweep_cap, offset + batch_sz)
        tested = end
        if cs != zero_cs:
            target_b = bytes.fromhex(target_hex)
            for idx in range(offset, end):
                cand = decode_idx(idx, slots)
                if hashlib.sha256(cand.encode()).digest() == target_b:
                    recovered = cand
                    break
            if recovered is not None:
                break

    wall_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    mhps = round(tested / max(1, gpu_us_sum), 2)
    entropy = round(math.log2(max(2, total_ks)), 1)

    if recovered is not None:
        for _ in range(5):
            push_fn("127.0.0.1", 443, f"JTR_RECOVERED mask={mask} ({mhps}MH/s)")
        sec_engine.log_delta("caprun_jtr", "weak_hash_proven", f"mask_{mask}_{mhps}MHps", gpu_us_sum)
        return {
            "ok": True,
            "status": "COMPROMISED_IN_KEYSPACE",
            "adapter": adapter,
            "recovered": recovered,
            "mask": mask,
            "tested": tested,
            "total_keyspace": total_ks,
            "entropy_bits": entropy,
            "gpu_mhps": mhps,
            "wall_ms": wall_ms,
            "defense": build_hardening(recovered, mask, target_hex),
        }

    push_fn("127.0.0.1", 443, f"JTR_RESILIENT mask={mask} ({mhps}MH/s)")
    sec_engine.log_delta("caprun_jtr", "keyspace_resilient", f"mask_{mask}_{tested}_checked", gpu_us_sum)
    return {
        "ok": True,
        "status": "RESILIENT_IN_WINDOW",
        "adapter": adapter,
        "mask": mask,
        "tested": tested,
        "total_keyspace": total_ks,
        "entropy_bits": entropy,
        "gpu_mhps": mhps,
        "wall_ms": wall_ms,
    }
