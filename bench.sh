#!/usr/bin/env bash
set -euo pipefail

RUNS="${1:-5}"
BIN="./target/release/caprun"

if [[ ! -f /tmp/simd_silicon.wasm || ! -f /tmp/cap_demos/hdc_holo.wasm || ! -f /tmp/cap_demos/gpu_vulkan.wasm ]]; then
  ./demo.sh >/dev/null
fi

H_SIMD=$($BIN put /tmp/simd_silicon.wasm | awk '{print $NF}')
H_HDC=$($BIN put /tmp/cap_demos/hdc_holo.wasm | awk '{print $NF}')
H_GPU=$($BIN put /tmp/cap_demos/gpu_vulkan.wasm | awk '{print $NF}')

STARTED_BROKER=0
if ! pgrep -f "caprun broker" >/dev/null 2>&1; then
  $BIN broker >/dev/null 2>&1 &
  BROKER_PID=$!
  STARTED_BROKER=1
  sleep 1
fi
trap '[[ "$STARTED_BROKER" -eq 1 ]] && kill "$BROKER_PID" 2>/dev/null || true' EXIT

# Warm up native .cwasm cache before timing
$BIN run "$H_SIMD" --seed 42 >/dev/null 2>&1
$BIN run "$H_HDC" --seed 77 >/dev/null 2>&1
$BIN run "$H_GPU" --seed 42 --cap vulkan >/dev/null 2>&1

python3 - "$BIN" "$RUNS" "$H_SIMD" "$H_HDC" "$H_GPU" << 'PY'
import re, statistics, subprocess, sys

bin_p, runs, h_simd, h_hdc, h_gpu = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
jobs = [
    ("CPU SIMD128 (80M FLOPs)",        [bin_p, "run", h_simd, "--seed", "42"]),
    ("HDC 10k-Bit (25% Noise Recall)", [bin_p, "run", h_hdc, "--seed", "77"]),
    ("Vulkan Gate (Denied, No Token)", [bin_p, "run", h_gpu, "--seed", "42"]),
    ("Vulkan Iris Xe (134M FLOPs)",    [bin_p, "run", h_gpu, "--seed", "42", "--cap", "vulkan"]),
    ("seccomp-BPF Escape (SIGSYS)",    [bin_p, "run", h_simd, "--test-escape"]),
]
re_tot = re.compile(r"(?:evaporated|SIGSYS\)) in ([0-9.]+) ms")
re_ex  = re.compile(r"Worker exec: ([0-9.]+) ms")
re_gf  = re.compile(r"\(([0-9.]+) GFLOPS\)")

print(f"\n| {'Workload':<32} | {'Min':>7} | {'Median':>7} | {'Max':>7} | {'Detail':<22} |")
print(f"|{'-'*34}|{'-'*9}|{'-'*9}|{'-'*9}|{'-'*24}|")
for name, cmd in jobs:
    tots, exs, gfs = [], [], []
    for _ in range(runs):
        out = subprocess.run(cmd, capture_output=True, text=True)
        txt = out.stdout + "\n" + out.stderr
        if m := re_tot.search(txt): tots.append(float(m.group(1)))
        if m := re_ex.search(txt):  exs.append(float(m.group(1)))
        if m := re_gf.search(txt):  gfs.append(float(m.group(1)))
    if not tots:
        print(f"| {name:<32} | {'ERR':>7} | {'ERR':>7} | {'ERR':>7} | {'failed':<22} |")
        continue
    det = f"GPU {statistics.median(gfs):.1f} GFLOPS" if gfs else (f"exec {statistics.median(exs):.2f} ms" if exs else "kernel SIGSYS kill")
    print(f"| {name:<32} | {min(tots):>7.2f} | {statistics.median(tots):>7.2f} | {max(tots):>7.2f} | {det:<22} |")
PY
