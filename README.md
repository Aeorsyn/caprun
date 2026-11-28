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

<!-- CAPRUN_FEATURES_START -->
## Next-Gen Architecture & Feature Stack

### 1. 10-Tab OpsDeck, Chronovisor & Spiderweb (`src/opsdeck.rs`, `src/spiderweb.rs`, `src/tls_decrypt.rs`)
- **Persistent 10-Tab OpsDeck (`:8095`):** Native eBPF/XDP packet capture (`XDP_NATIVE`) paired with the Vulkan WGSL compute broker (`~/.cas/vulkan.sock`) and local `llama-server` (`:8080`).
- **Chronovisor Packet Lens:** Clickable spectrum waterfall rows open an inline drawer with Shannon entropy classification, ASCII/hex inspection, GPU XOR + YARA sweeps, and 1-click local LLM packet triage (`/api/llm/inspect`).
- **TLS 1.3 Decryption & Media Carving:** Live `SSLKEYLOGFILE` tailing and offline keylog/PCAP decryption (`TlsKeyStore`) with automatic magic-byte carving for PNG, JPEG, GIF, and WebP artifacts.

### 2. Prism Autonomous NDR/EDR Engine (`src/prism.rs`)
- **Process-to-Packet Lineage:** Resolves active sockets to their originating Linux PID, binary path, parent chain (`proc <- parent <- ...`), cached binary SHA-256, and anomaly flags (`/tmp`, `/dev/shm`, `(deleted)` executables).
- **Spectral Traffic DNA:** Sliding-window inter-arrival time (IAT) jitter coefficient of variation, Discrete Fourier Transform (DFT) Peak-to-Average Power Ratio (PAPR), and 0–100 beaconing/exfiltration scoring on opaque TLS 1.3 and QUIC traffic without keys.
- **Shadow-Mode Policy Synthesis:** Local `llama-server` synthesizes containment proposals (`XDP_DROP_TUPLE`, `FREEZE_PID`, `RATE_LIMIT`, `PCAP_RECORD`) that accumulate dry-run shadow hit counters until explicitly **Armed**, with 1-click **Rollback** and PID 1 / self-protection guards.

### 3. Global WireGuard / AmneziaWG VPN Controller (`src/vpn.rs`)
- **Persistent Top-Bar Pill & Slide-Over Drawer:** Live tunnel status, active interface, handshake age, and RX/TX counters visible across all 10 OpsDeck tabs.
- **Easy & Detailed Controls:** Upload or paste `.conf` profiles (`chmod 0600` in `~/.config/caprun/vpn/`), 1-click connect/disconnect, automatic `awg-quick` support for AmneziaWG stealth configs, kill-switch stale-handshake alerting, public Exit IP verification, and live WireGuard peer endpoint hot-swap (`wg set`).
- **Offline SVG QR Generator:** Generates local Curve25519 keypairs (`wg genkey` / `wg pubkey`) and renders scannable SVG QR codes for saved profiles or mobile peer onboarding.

### 4. Rethunk Onion Router & Dark Web Inspector (`src/onion.rs`)
- **Isolated 3-Hop Onion Engine:** Runs an isolated Tor daemon (`127.0.0.1:9150` SOCKS5h, `:9151` ControlPort, `:9153` DNSPort) under `~/.config/caprun/onion/`, supporting standalone Onion mode or **Double-Hop (Tor over WireGuard)**.
- **Custom Exit IP / Country / Fingerprint Control:** Quick-pick country chips (`CH`, `IS`, `NL`, `SE`, `DE`, `JP`, `US`, `Auto`) or explicit IP/CIDR/fingerprint `ExitNodes` with `StrictNodes` and live circuit rotation (`SIGNAL NEWNYM`).
- **Live Exit Relay Directory:** Queries active Tor `Exit` relays via Onionoo (directly or routed through `:9150`) with filters for country, minimum bandwidth (`Mbps`), IP, nickname, and ASN—plus 1-click **Pin** and **+Pool** actions.
- **Zero-DNS-Leak `.onion` v3 Inspector:** Fetches `.onion` v3 and clearnet targets over `socks5h://127.0.0.1:9150` directly in the drawer, visualizes live `Guard -> Middle -> Exit` circuits, and provides an isolated proxy browser launch command.

### Key API Endpoints
| Subsystem | Endpoints |
|---|---|
| **TLS 1.3** | `GET /api/tls/status`, `POST /api/tls/keylog` |
| **Prism NDR/EDR** | `GET /api/prism/status`, `POST /api/prism/inspect`, `POST /api/prism/synthesize`, `POST /api/prism/arm`, `POST /api/prism/rollback` |
| **WireGuard VPN** | `GET /api/vpn/status`, `POST /api/vpn/import`, `POST /api/vpn/delete`, `POST /api/vpn/connect`, `POST /api/vpn/disconnect`, `POST /api/vpn/switch_endpoint`, `POST /api/vpn/qr`, `GET /api/vpn/exit_ip`, `POST /api/vpn/killswitch` |
| **Onion Router** | `GET /api/onion/status`, `POST /api/onion/start`, `POST /api/onion/stop`, `POST /api/onion/exit`, `POST /api/onion/newnym`, `GET /api/onion/exit_ip`, `POST /api/onion/relays`, `POST /api/onion/fetch` |
<!-- CAPRUN_FEATURES_END -->
