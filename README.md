# caprun

Zero-install, content-addressed capability runner for bare-metal Linux.

`caprun` executes immutable BLAKE3-addressed WebAssembly capabilities inside a dual Wasmtime + Linux Kernel (Landlock + seccomp-BPF) sandbox, brokers hardware access to CPU SIMD128 and Intel Iris Xe Vulkan compute, and commits structured deltas to a local SQLite semantic object graph (`~/.cas/graph.db`) with zero bytes extracted to disk.

## Architecture

```text
Intent / CLI (or local llama-server via intent.py)
  |
  v
[ Parent Capability Broker (Host Boundary) ]
  - Verifies BLAKE3 digest in ~/.cas/blobs/ (0 B extracted)
  - Caches native x86_64 .cwasm in ~/.cas/cache/
  - Brokers --cap vulkan -> Warm Unix-socket GPU daemon
  - Commits JSON deltas -> ~/.cas/graph.db
  | (stdin)          ^ (stdout)
  v                  |
[ Disposable Sandbox Worker (Zero Ambient Authority) ]
  1. RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 (instant SIGSYS)
  2. PR_SET_NO_NEW_PRIVS + Landlock ABI v4 (0 FS paths)
  3. seccomp-BPF strict allow-list (~24 syscalls)
  4. Wasmtime linear memory + deterministic fuel metering
```

## Verified Benchmarks (HP Envy x360 - Ubuntu 24.04 x86_64)

| Capability Workload | Silicon Target | Pure Compute | Full Lifecycle | Notes |
| :--- | :--- | ---: | ---: | :--- |
| SIMD128 Vector Math (80M FLOPs) | x86_64 CPU (`f32x4`) | 5.78-12.40 ms | 11.30-17.18 ms | ~13.8 GFLOPS single-core; 28M fuel |
| Hyperdimensional Recall (10,240-bit) | x86_64 CPU | 0.06-0.12 ms | 4.77 ms (med) | 25% bit-flip noise (75% vs 49% random) |
| Vulkan Compute (Denied, No Token) | Capability Gate | 0.05 ms | 3.89 ms | Zero-authority denial without `--cap vulkan` |
| Vulkan Compute (134M+ FLOPs, Cold) | Intel Iris Xe (ADL GT2) | 5.35 ms | 58.29 ms | 262,144 threads (25.1 GFLOPS) |
| Vulkan Compute (134M+ FLOPs, Warm) | Intel Iris Xe Daemon | ~3.3 ms | 8.93 ms (med) | 262,144 threads (40.3 GFLOPS median) |
| Live Kernel seccomp-BPF Escape Block | Linux Kernel (`SIGSYS`) | - | 3.65 ms (med) | Instant kill on forbidden `socket()` |

## Quickstart

```bash
cargo build --release
./target/release/caprun broker &
./demo.sh
./bench.sh 5
./target/release/caprun graph --limit 15
```
