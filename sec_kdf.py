#!/usr/bin/env python3
import hashlib, math, re, time
import sec_engine

HASH_SIGS = [
    ("argon2", re.compile(r"^\$argon2(id|i|d)\$"), "STRONG", "Memory-hard KDF"),
    ("bcrypt", re.compile(r"^\$2[abxy]\$\d{2}\$"), "STRONG", "Adaptive salted hash"),
    ("scrypt", re.compile(r"^\$scrypt\$"), "STRONG", "Memory-hard KDF"),
    ("sha512crypt", re.compile(r"^\$6\$"), "MODERATE", "Salted SHA-512 rounds"),
    ("sha256_raw", re.compile(r"^[0-9a-fA-F]{64}$"), "WEAK", "Unsalted fast hash - migrate to Argon2id"),
    ("sha1_raw", re.compile(r"^[0-9a-fA-F]{40}$"), "CRITICAL", "Legacy fast hash - immediate migration"),
    ("md5_raw", re.compile(r"^[0-9a-fA-F]{32}$"), "CRITICAL", "Broken fast hash - immediate migration"),
]

def audit_hashes(samples, push_fn):
    t0 = time.perf_counter()
    results = []
    weak_count = 0
    for raw in samples:
        h = raw.strip()
        if not h: continue
        matched = ("unknown", "REVIEW", "Unrecognized format")
        for name, pat, risk, note in HASH_SIGS:
            if pat.match(h):
                matched = (name, risk, note)
                break
        if matched[1] in ("WEAK", "CRITICAL"):
            weak_count += 1
            push_fn("127.0.0.1", 8443, f"KDF_RISK {matched[0]} ({matched[1]})")
        results.append({"sample": h[:16] + "...", "scheme": matched[0], "risk": matched[1], "note": matched[2]})
    us = int((time.perf_counter() - t0) * 1_000_000)
    sec_engine.log_delta("secsuite_kdf", "hash_audit", f"weak_{weak_count}_of_{len(results)}", us)
    return {"checked": len(results), "weak": weak_count, "results": results}

def bench_kdf(gpu_mhps=150.0, mask_len=8, charset_size=36):
    t0 = time.perf_counter()
    hashlib.scrypt(b"caprun-audit-probe", salt=b"0123456789abcdef", n=16384, r=8, p=1, dklen=32)
    scrypt_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    t1 = time.perf_counter()
    hashlib.pbkdf2_hmac("sha256", b"caprun-audit-probe", b"0123456789abcdef", 600000)
    pbkdf2_ms = round((time.perf_counter() - t1) * 1000.0, 2)

    keyspace = charset_size ** max(1, min(16, int(mask_len)))
    fast_hash_sec = round(keyspace / max(1.0, float(gpu_mhps) * 1e6), 4)
    scrypt_years = round((keyspace * (scrypt_ms / 1000.0)) / 31_536_000.0, 2)

    sec_engine.log_delta("secsuite_kdf", "kdf_bench", f"scrypt_{scrypt_ms}ms_pb_{pbkdf2_ms}ms", int(scrypt_ms * 1000))
    return {
        "scrypt_16k_ms": scrypt_ms,
        "pbkdf2_600k_ms": pbkdf2_ms,
        "entropy_bits": round(mask_len * math.log2(max(2, charset_size)), 1),
        "fast_hash_est_sec": fast_hash_sec,
        "scrypt_single_core_years": scrypt_years,
    }
