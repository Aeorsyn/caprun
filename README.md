# caprun

**Stop wasting local silicon. A zero-install, kernel-isolated Rust/Vulkan GPU broker, 262k-neuron persistent VRAM spiking cortex, MCP server, and local-first SecSuite OpsDeck.**

- **Playable WebGPU Demo:** [Hyperfold 4D](https://aeorsyn.github.io/caprun/)
- **Commercial Licensing & Integration:** [COMMERCIAL.md](COMMERCIAL.md) (Dual-licensed: AGPLv3 / Commercial)

![caprun 262,144-neuron predictive spiking cortex at 1.89 ms / 60.1 FPS](docs/cortex.jpg)

Modern compute and security pipelines burn massive cloud/SIEM budgets by treating local hardware as stateless—bouncing data across containers and networks for milliseconds of actual math. `caprun` keeps state hot in VRAM, enforces isolation at the Linux kernel boundary, and talks straight to Vulkan on everyday integrated graphics.

## Core Runtime Architecture

- **Linux Kernel Sandbox:** `USER+NET` namespaces, `PR_SET_DUMPABLE=0`, Landlock ABI v4, and `seccomp-BPF` (3.65 ms `SIGSYS` kill on escape).
- **Warm Vulkan Broker:** Guests never touch `/dev/dri`. Custom WGSL is validated inside `wgpu` error scopes and cached by BLAKE3 hash.
- **Persistent VRAM (`CORTEX:`):** Ping-pong GPU storage buffers run 262,144 stateful predictive-coding LIF neurons across frames with zero CPU round-trips.
- **Provenance & MCP:** Every scan, anomaly, and shader dispatch commits BLAKE3-attributed deltas to `~/.cas/graph.db`; `mcp_server.py` exposes GPU tools over JSON-RPC 2.0 `stdio`.

## Caprun SecSuite OpsDeck (`secsuite.py` -> `http://localhost:8095`)

A localhost cyberdeck uniting offensive auditing and defensive telemetry on top of `caprun`:

- **Live NetSec Spiking Cortex:** Maps live `ss` sockets, `tcpdump` packets, and active scan hits onto the 512x512 VRAM sheet (`X = Source IP`, `Y = Dest Port`), suppressing baseline rhythms while flagging scans and intrusions in 1.89 ms.
- **Recon, Web Fuzz & TLS/DNS Audit:** Multi-threaded TCP/banner scanner, HTTP security header checks, path fuzzer, and cert/SPF/DMARC auditing.
- **Deception Canaries & Threat Rules:** Arm decoy SSH/Redis/HTTP listeners that flare the Cortex on contact and generate ready-to-run `ufw`/`nftables` block rules.
- **BlackArch + Metasploit Deck:** Categorized CLI arsenal + `msfconsole`-style `use / set / run` console bridged to native tools and `caprun` modules.
- **Next-Gen Frequency-Ranked GPU Keyspace + Auto-Hardening:** Compiles JtR-style masks (`?f` English frequency table `etaoin...`, `?l`, `?u`, `?d`, `?a`, literal prefixes) into WGSL SHA-256 kernels, pulses the Cortex per batch, and auto-generates salted `scrypt` replacements + KDF policy benchmarks.

## Verified Benchmarks (Intel Iris Xe ADL GT2, Ubuntu 24.04)

| Workload | Result | Notes |
| :--- | :--- | :--- |
| FP32 Compute (`bench-gpu`) | **1.005 TFLOPS** | 262k threads x 8,192 vec4 FMA (68.36 ms) |
| 262k Spiking Cortex (`cortex.py`) | **1.89 ms / 60.1 FPS** | Persistent VRAM LIF + predictive coding |
| Custom Guest WGSL (cached) | **8.30 ms** | Verify -> Sandbox -> 262k GPU threads -> Graph |
| Kernel Escape (`--test-escape`) | **3.65 ms `SIGSYS`** | Forbidden `socket()` killed by `seccomp-BPF` |
| Poisoned WGSL Shader | **Rejected safely** | Caught by `wgpu` validation error scope |
| Local KDF Posture (`sec_kdf.py`) | **39.88 ms `scrypt`** | vs 110.38 ms `PBKDF2-600k` (defeats GPU sweeps) |

## Quickstart

    cargo build --release
    ./target/release/caprun broker &
    ./showcase.sh
    ./secsuite.py
    # Optional packet-level feed:
    # sudo tcpdump -l -n -q -i any 'not port 8095' 2>/dev/null | ./secsuite.py

## Licensing

Dual-licensed under **GNU AGPLv3** (`LICENSE`) and **Commercial Licenses** (`COMMERCIAL.md`).
