#!/usr/bin/env bash
set -euo pipefail

BIN="./target/release/caprun"
mkdir -p /tmp/cap_demos

if [[ ! -f /tmp/cap_demos/custom_wgsl.wasm ]]; then
  cat << 'RS' > /tmp/cap_demos/custom_wgsl.rs
#[link(wasm_import_module = "cap")]
extern "C" {
    fn emit_delta(ptr: *const u8, len: usize);
    fn gpu_dispatch_wgsl(ptr: *const u8, len: usize, elements: i32, seed: i32, iters: i32) -> i32;
}
const OK_WGSL: &[u8] = br#"
struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if (idx >= params.count) { return; }
    let x = f32(idx % 512u) / 512.0 * 3.0 - 2.0;
    let y = f32(idx / 512u) / 512.0 * 2.4 - 1.2;
    var zr = 0.0; var zi = 0.0; var k = 0u;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        let nr = zr * zr - zi * zi + x;
        zi = 2.0 * zr * zi + y;
        zr = nr;
        if (zr * zr + zi * zi > 4.0) { break; }
        k = k + 1u;
    }
    out_buf[idx] = f32(k);
}
"#;
const BAD_WGSL: &[u8] = b"@compute @workgroup_size(64) fn main() { let broken: f32 = 123u; }";
#[no_mangle]
pub extern "C" fn run(seed: i32) -> i32 {
    let src = if seed < 0 { BAD_WGSL } else { OK_WGSL };
    let cs = unsafe { gpu_dispatch_wgsl(src.as_ptr(), src.len(), 262_144, seed.abs(), 128) };
    if cs < 0 { return cs; }
    let mut buf = [0u8; 160];
    let pre = b"{\"entity\":\"hostile_silicon_demo\",\"relation\":\"iris_xe_custom_wgsl\",\"value\":\"cs_";
    let mut p = pre.len();
    buf[..p].copy_from_slice(pre);
    let mut n = cs as u32; let mut digs = [0u8; 10]; let mut dl = 0;
    if n == 0 { digs[0] = b'0'; dl = 1; } else { while n > 0 { digs[dl] = b'0' + (n % 10) as u8; n /= 10; dl += 1; } }
    for i in (0..dl).rev() { buf[p] = digs[i]; p += 1; }
    buf[p..p + 2].copy_from_slice(b"\"}");
    unsafe { emit_delta(buf.as_ptr(), p + 2); }
    0
}
RS
  rustc --edition 2021 --target wasm32-unknown-unknown --crate-type cdylib -O /tmp/cap_demos/custom_wgsl.rs -o /tmp/cap_demos/custom_wgsl.wasm
fi

STARTED=0
if ! pgrep -f "caprun broker" >/dev/null 2>&1; then
  $BIN broker >/dev/null 2>&1 &
  BPID=$!
  STARTED=1
  sleep 1
fi
trap '[[ "$STARTED" -eq 1 ]] && kill "$BPID" 2>/dev/null || true' EXIT

H_WGSL=$($BIN put /tmp/cap_demos/custom_wgsl.wasm | awk '{print $NF}')
$BIN run "$H_WGSL" --seed 1 --cap vulkan >/dev/null 2>&1

echo ""
echo "========================================================================"
echo "  CAPRUN: THE HOSTILE SILICON DEMO"
echo "  Zero-Install | USER+NET NS + Landlock + seccomp | Warm Iris Xe Broker"
echo "========================================================================"

echo ""
echo "[1/5] ZERO-INSTALL MATERIALIZATION (Immutable BLAKE3 CAS)"
echo "      Hash: $H_WGSL (0 B extracted to filesystem)"

echo ""
echo "[2/5] UNTRUSTED CUSTOM WGSL ON INTEL IRIS Xe (262,144 GPU threads)"
$BIN run "$H_WGSL" --seed 42 --cap vulkan

echo ""
echo "[3/5] LIVE POISONED SHADER ATTACK (Malformed WGSL -> wgpu error scope)"
$BIN run "$H_WGSL" --seed=-1 --cap vulkan || true

echo ""
echo "[4/5] LIVE KERNEL ESCAPE ATTEMPT (Forbidden socket() -> Instant SIGSYS)"
$BIN run "$H_WGSL" --test-escape

echo ""
echo "[5/5] SURVIVAL CHECK & SEMANTIC PROVENANCE AUDIT (~/.cas/graph.db)"
$BIN run "$H_WGSL" --seed 99 --cap vulkan
echo ""
$BIN graph --limit 6
