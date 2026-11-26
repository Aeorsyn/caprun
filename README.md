# caprun

Zero-install, content-addressed capability runner with Linux kernel isolation and 1 TFLOPS validated Vulkan GPU brokering.

Play the WebGPU showcase: **[Hyperfold 4D](https://YOUR_USERNAME.github.io/caprun/)**

## Why caprun?

- **Zero-install CAS:** Capabilities are verified by BLAKE3 hash (`0 B` extracted to disk).
- **Linux isolation:** `USER+NET` namespaces, `PR_SET_DUMPABLE=0`, Landlock ABI v4, and `seccomp-BPF`.
- **Warm Vulkan broker:** Guests never touch `/dev/dri`. Custom WGSL is validated in `wgpu` error scopes, locked to a 2-binding ABI, and cached by BLAKE3 digest.
- **Provenance:** Every run commits a hash-attributed delta to `~/.cas/graph.db`.

## Verified Benchmarks (Intel Iris Xe ADL GT2, Ubuntu 24.04)

| Workload | Result | Notes |
| :--- | :--- | :--- |
| FP32 Compute (`bench-gpu`) | **1.005 TFLOPS** | 262k threads x 8,192 vec4 FMA (68.36 ms) |
| Custom Guest WGSL (cached) | **8.30 ms** | Verify -> Sandbox -> 262k GPU threads -> Graph |
| Live 3D Raymarching (`FRAME:`) | **1-2 ms / 60 FPS** | 512x512 Hyperfold 4D over Unix socket |
| Kernel Escape (`--test-escape`) | **3.65 ms `SIGSYS`** | Forbidden `socket()` killed by `seccomp-BPF` |
| Poisoned WGSL Shader | **Rejected safely** | Caught by `wgpu` validation scope |

## Quickstart

    cargo build --release
    ./target/release/caprun broker &
    ./showcase.sh
    ./target/release/caprun bench-gpu --iters 8192 --runs 3
    ./hyperfold_shooter.py

## MCP Server (Claude / Cursor / Local LLMs)

`mcp_server.py` exposes `run_wgsl_gpu`, `bench_gpu`, and `query_graph` over standard MCP `stdio` JSON-RPC 2.0.
