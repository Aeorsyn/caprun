#!/usr/bin/env bash
set -euo pipefail

BIN="./target/release/caprun"
mkdir -p /tmp/cap_demos

# 1. Hyperdimensional Computing (10,240-bit holographic vector recall under 25% noise)
cat << 'RS' > /tmp/cap_demos/hdc_holo.rs
#[link(wasm_import_module = "cap")]
extern "C" {
    fn emit_delta(ptr: *const u8, len: usize);
}

fn next_rand(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn fill_hv(seed: u64, out: &mut [u64; 160]) {
    let mut s = seed | 1;
    for w in out.iter_mut() {
        *w = next_rand(&mut s);
    }
}

fn hamming_sim_pct(a: &[u64; 160], b: &[u64; 160]) -> u32 {
    let mut diff = 0u32;
    for i in 0..160 {
        diff += (a[i] ^ b[i]).count_ones();
    }
    ((10240 - diff) * 100) / 10240
}

#[no_mangle]
pub extern "C" fn run(seed: i32) -> i32 {
    let mut stone = [0u64; 160];
    let mut lightning = [0u64; 160];
    let mut noise_other = [0u64; 160];
    fill_hv(seed as u64 + 101, &mut stone);
    fill_hv(seed as u64 + 202, &mut lightning);
    fill_hv(seed as u64 + 303, &mut noise_other);

    // Bind STONE ^ LIGHTNING, then corrupt 25% of bits (simulated thermal noise)
    let mut bound = [0u64; 160];
    let mut rng = (seed as u64) ^ 0x9E37_79B9_7F4A_7C15;
    for i in 0..160 {
        let r1 = next_rand(&mut rng);
        let r2 = next_rand(&mut rng);
        let flip_25pct = r1 & r2; // ~25% of bits set to 1
        bound[i] = (stone[i] ^ lightning[i]) ^ flip_25pct;
    }

    // Unbind with LIGHTNING and test holographic recall against STONE vs random
    let mut recalled = [0u64; 160];
    for i in 0..160 {
        recalled[i] = bound[i] ^ lightning[i];
    }
    let sim_stone = hamming_sim_pct(&recalled, &stone);
    let sim_other = hamming_sim_pct(&recalled, &noise_other);

    let mut buf = [0u8; 160];
    let prefix = b"{\"entity\":\"hdc_10k_vector\",\"relation\":\"noisy_25pct_recall\",\"value\":\"match_";
    let mut p = 0;
    buf[..prefix.len()].copy_from_slice(prefix);
    p += prefix.len();
    buf[p] = b'0' + ((sim_stone / 10) % 10) as u8;
    buf[p + 1] = b'0' + (sim_stone % 10) as u8;
    p += 2;
    let mid = b"pct_vs_";
    buf[p..p + mid.len()].copy_from_slice(mid);
    p += mid.len();
    buf[p] = b'0' + ((sim_other / 10) % 10) as u8;
    buf[p + 1] = b'0' + (sim_other % 10) as u8;
    p += 2;
    let suf = b"pct\"}";
    buf[p..p + suf.len()].copy_from_slice(suf);
    p += suf.len();

    unsafe { emit_delta(buf.as_ptr(), p); }
    0
}
RS

# 2. Vulkan GPU Offload Capability (requests 262,144 parallel threads = 134M+ FLOPs)
cat << 'RS' > /tmp/cap_demos/gpu_vulkan.rs
#[link(wasm_import_module = "cap")]
extern "C" {
    fn emit_delta(ptr: *const u8, len: usize);
    fn gpu_dispatch(elements: i32, seed: i32) -> i32;
}

#[no_mangle]
pub extern "C" fn run(seed: i32) -> i32 {
    let checksum = unsafe { gpu_dispatch(262_144, seed) };
    if checksum < 0 {
        return checksum;
    }

    let mut buf = [0u8; 160];
    let prefix = b"{\"entity\":\"intel_iris_xe\",\"relation\":\"vulkan_134M_flops\",\"value\":\"gpu_cs_";
    let mut p = 0;
    buf[..prefix.len()].copy_from_slice(prefix);
    p += prefix.len();

    let mut n = checksum as u32;
    let mut digits = [0u8; 10];
    let mut dlen = 0;
    if n == 0 {
        digits[0] = b'0';
        dlen = 1;
    } else {
        while n > 0 {
            digits[dlen] = b'0' + (n % 10) as u8;
            n /= 10;
            dlen += 1;
        }
    }
    for i in (0..dlen).rev() {
        buf[p] = digits[i];
        p += 1;
    }
    let suf = b"\"}";
    buf[p..p + suf.len()].copy_from_slice(suf);
    p += suf.len();

    unsafe { emit_delta(buf.as_ptr(), p); }
    0
}
RS

rustc --edition 2021 --target wasm32-unknown-unknown --crate-type cdylib -O /tmp/cap_demos/hdc_holo.rs -o /tmp/cap_demos/hdc_holo.wasm
rustc --edition 2021 --target wasm32-unknown-unknown --crate-type cdylib -O /tmp/cap_demos/gpu_vulkan.rs -o /tmp/cap_demos/gpu_vulkan.wasm

H_SIMD="blake3:a56c30e467151f6bb5d808270f11d259ec0b338a6054d60da689bb2113999066"
H_HDC=$($BIN put /tmp/cap_demos/hdc_holo.wasm | awk '{print $NF}')
H_GPU=$($BIN put /tmp/cap_demos/gpu_vulkan.wasm | awk '{print $NF}')

echo ""
echo "========================================================================"
echo "  CAPRUN ZERO-INSTALL MULTI-CAPABILITY SILICON SHOWCASE"
echo "========================================================================"
echo ""
echo "[1/5] CPU NATIVE SIMD128 (80M FLOPs inside dual sandbox)"
$BIN run "$H_SIMD" --seed 42

echo ""
echo "[2/5] HYPERDIMENSIONAL COMPUTING (10,240-bit recall under 25% noise)"
$BIN run "$H_HDC" --seed 77

echo ""
echo "[3/5] VULKAN CAPABILITY GATE — DENIED WITHOUT TOKEN"
$BIN run "$H_GPU" --seed 42 || true

echo ""
echo "[4/5] VULKAN CAPABILITY GATE — AUTHORIZED ON INTEL IRIS Xe (--cap vulkan)"
$BIN run "$H_GPU" --seed 42 --cap vulkan

echo ""
echo "[5/5] LIVE KERNEL SECCOMP-BPF ESCAPE BLOCK (Instant RLIMIT_CORE=0 SIGSYS)"
$BIN run "$H_SIMD" --test-escape

echo ""
echo "========================================================================"
echo "  LIVE LOCAL SEMANTIC OBJECT GRAPH (~/.cas/graph.db)"
echo "========================================================================"
$BIN graph --limit 10
