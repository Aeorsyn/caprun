# caprun

**Zero-install, kernel-isolated capability runner with a 1 TFLOPS validated Vulkan GPU broker, persistent VRAM neural compute, and an MCP server for AI agents.**

- **Playable WebGPU Demo:** [Hyperfold 4D](https://aeorsyn.github.io/caprun/)
- **Commercial Licensing & Integration:** [COMMERCIAL.md](COMMERCIAL.md) (Dual-licensed: AGPLv3 / Commercial)

![caprun 262,144-neuron predictive spiking cortex at 1.89 ms / 60.1 FPS](docs/cortex.jpg)

## Architecture

- **Linux sandbox:** `USER+NET` namespaces, `PR_SET_DUMPABLE=0`, Landlock ABI v4, and `seccomp-BPF`.
- **Warm Vulkan broker:** Guests never touch `/dev/dri`. Custom WGSL is validated inside `wgpu` error scopes and cached by BLAKE3 hash.
- **Persistent VRAM (`CORTEX:`):** Ping-pong GPU buffers run 262,144+ stateful neurons across frames with zero CPU round-trips.
- **Provenance & MCP:** Logs hash-attributed deltas to `~/.cas/graph.db` and exposes `run_wgsl_gpu`, `bench_gpu`, and `query_graph` via `mcp_server.py`.

## Verified Benchmarks (Intel Iris Xe ADL GT2, Ubuntu 24.04)

| Workload | Result | Notes |
| :--- | :--- | :--- |
| FP32 Compute (`bench-gpu`) | **1.005 TFLOPS** | 262k threads x 8,192 vec4 FMA (68.36 ms) |
| 262k Spiking Cortex (`cortex.py`) | **1.89 ms / 60.1 FPS** | Persistent VRAM LIF + predictive coding |
| Custom Guest WGSL (cached) | **8.30 ms** | Verify -> Sandbox -> 262k GPU threads -> Graph |
| Kernel Escape (`--test-escape`) | **3.65 ms `SIGSYS`** | Forbidden `socket()` killed by `seccomp-BPF` |
| Poisoned WGSL Shader | **Rejected safely** | Caught by `wgpu` validation error scope |

## Quickstart

    cargo build --release
    ./target/release/caprun broker &
    ./showcase.sh
    ./cortex.py
    ./hyperfold_shooter.py

## Licensing

Dual-licensed under **GNU AGPLv3** (`LICENSE`) and **Commercial Licenses** (`COMMERCIAL.md`).
