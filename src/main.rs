mod cortex_stdp;
mod gpu;
mod ja4;
mod opsdeck;
mod soc_loop;
mod pty_term;
mod spiderweb;
mod tls_decrypt;

use anyhow::{bail, Context, Result};
use blake3::Hasher;
use clap::{Parser, Subcommand};
use landlock::{Access, AccessFs, Ruleset, RulesetAttr, ABI};
use rusqlite::{params, Connection};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wasmtime::{Caller, Config, Engine, Extern, Linker, Module, Store};

#[derive(Parser)]
#[command(name = "caprun", about = "Zero-install BLAKE3 capability runner, Vulkan broker & semantic graph")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Hash a .wasm capability and store it immutably in ~/.cas/blobs/
    Put { path: PathBuf },
    /// Run a capability by BLAKE3 hash inside a locked-down silicon worker
    Run {
        hash: String,
        #[arg(long, default_value_t = 500_000_000)]
        fuel: u64,
        #[arg(long, default_value_t = 42, allow_hyphen_values = true)]
        seed: i32,
        /// Grant explicit hardware capabilities (e.g. --cap vulkan)
        #[arg(long = "cap")]
        caps: Vec<String>,
        /// Trigger a forbidden syscall after lockdown to verify instant SIGSYS kill
        #[arg(long)]
        test_escape: bool,
    },
    /// Start the persistent warm Vulkan GPU capability daemon on ~/.cas/vulkan.sock
    Broker,
    /// Launch unified eBPF/XDP + STDP Cortex + JA4 + Autonomous SOC OpsDeck
    Opsdeck {
        #[arg(long, default_value = "wlo1")]
        iface: String,
        #[arg(long, default_value_t = 8095)]
        port: u16,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        llm: String,
    },
    BenchGpu { #[arg(long, default_value_t = 262_144)] elements: u32, #[arg(long, default_value_t = 4096)] iters: u32, #[arg(long, default_value_t = 3)] runs: usize },
    /// Inspect recent versioned commits in the local semantic object graph
    Graph {
        #[arg(long, default_value_t = 15)]
        limit: usize,
    },
    /// Internal disposable sandbox worker
    #[command(hide = true)]
    Worker {
        #[arg(long)]
        fuel: u64,
        #[arg(long, allow_hyphen_values = true)]
        seed: i32,
        #[arg(long)]
        allow_vulkan: bool,
        #[arg(long)]
        test_escape: bool,
    },
}

#[derive(Deserialize)]
struct DeltaPayload {
    entity: String,
    relation: String,
    value: String,
}

fn make_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.memory_init_cow(false);
    Ok(Engine::new(&config)?)
}

fn cas_root() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let root = PathBuf::from(home).join(".cas");
    fs::create_dir_all(root.join("blobs"))?;
    fs::create_dir_all(root.join("cache"))?;
    Ok(root)
}

fn open_graph() -> Result<Connection> {
    let db_path = cas_root()?.join("graph.db");
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS semantic_deltas (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             ts_unix INTEGER NOT NULL,
             capability_hash TEXT NOT NULL,
             entity TEXT NOT NULL,
             relation TEXT NOT NULL,
             value TEXT NOT NULL,
             latency_us INTEGER NOT NULL
         );",
    )?;
    Ok(conn)
}

fn cmd_put(path: PathBuf) -> Result<()> {
    let bytes = fs::read(&path).with_context(|| format!("Failed to read {:?}", path))?;
    let hash = Hasher::new().update(&bytes).finalize().to_hex().to_string();
    let dest = cas_root()?.join("blobs").join(&hash);
    if !dest.exists() {
        fs::write(&dest, &bytes)?;
    }
    println!("Stored {} bytes -> blake3:{}", bytes.len(), hash);
    Ok(())
}

fn cmd_graph(limit: usize) -> Result<()> {
    let conn = open_graph()?;
    let mut stmt = conn.prepare(
        "SELECT id, capability_hash, entity, relation, value, latency_us
         FROM semantic_deltas ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;

    println!(
        "{:<4} {:<14} {:<20} {:<22} {:<22} {:>10}",
        "ID", "CAP_HASH", "ENTITY", "RELATION", "VALUE", "LATENCY"
    );
    println!("{}", "-".repeat(96));
    for r in rows {
        let (id, hash, entity, rel, val, us) = r?;
        let short_hash = &hash[..12.min(hash.len())];
        println!(
            "{:<4} {:<14} {:<20} {:<22} {:<22} {:>7.2} ms",
            id,
            short_hash,
            entity,
            rel,
            val,
            us as f64 / 1000.0
        );
    }
    Ok(())
}

fn load_or_precompile(hash: &str) -> Result<Vec<u8>> {
    let root = cas_root()?;
    let blob_path = root.join("blobs").join(hash);
    let wasm_bytes = fs::read(&blob_path)
        .with_context(|| format!("Capability hash not found in CAS: {}", hash))?;

    let actual = Hasher::new().update(&wasm_bytes).finalize().to_hex().to_string();
    if actual != hash {
        bail!("CAS corruption detected! Expected {}, got {}", hash, actual);
    }

    let cache_path = root.join("cache").join(format!("{}.cwasm", hash));
    if cache_path.exists() {
        return Ok(fs::read(&cache_path)?);
    }

    let t_jit = Instant::now();
    let engine = make_engine()?;
    let cwasm = engine.precompile_module(&wasm_bytes)?;
    fs::write(&cache_path, &cwasm)?;
    eprintln!(
        "[cas] Precompiled native x86_64 artifact in {:.2} ms (cached)",
        t_jit.elapsed().as_micros() as f64 / 1000.0
    );
    Ok(cwasm)
}

fn cmd_run(
    raw_hash: String,
    fuel: u64,
    seed: i32,
    caps: Vec<String>,
    test_escape: bool,
) -> Result<()> {
    let t_total = Instant::now();
    let allow_vulkan = caps.iter().any(|c| c.eq_ignore_ascii_case("vulkan"));
    let hash = raw_hash.strip_prefix("blake3:").unwrap_or(&raw_hash);
    let cwasm_bytes = load_or_precompile(hash)?;
    let sock_path = cas_root()?.join("vulkan.sock");

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("worker")
        .arg("--fuel")
        .arg(fuel.to_string())
        .arg(format!("--seed={}", seed));
    if allow_vulkan {
        cmd.arg("--allow-vulkan");
    }
    if test_escape {
        cmd.arg("--test-escape");
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn worker")?;

    let mut child_stdin = child.stdin.take().context("Missing child stdin")?;
    let child_stdout = child.stdout.take().context("Missing child stdout")?;

    child_stdin.write_all(&(cwasm_bytes.len() as u64).to_le_bytes())?;
    child_stdin.write_all(&cwasm_bytes)?;
    child_stdin.flush()?;

    let conn = open_graph()?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut committed = 0;

    let reader = BufReader::new(child_stdout);
    for line_res in reader.lines() {
        let line = line_res?;
        if let Some(req) = line.strip_prefix("GPU_REQ:") {
            let parts: Vec<&str> = req.split(':').collect();
            if !allow_vulkan {
                writeln!(child_stdin, "GPU_ERR:denied")?;
                child_stdin.flush()?;
                continue;
            }
            let elements: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let gseed: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let res = match gpu::try_dispatch_via_daemon(&sock_path, elements, gseed, 256) {
                Some(r) => r,
                None => gpu::dispatch_vulkan_compute(elements, gseed, 256),
            };
            match res {
                Ok(r) => {
                    let mode = if r.warm { "WARM DAEMON" } else { "cold inline" };
                    let gflops = (elements as f64 * 512.0) / (r.compute_us.max(1) as f64 * 1000.0);
                    eprintln!(
                        "[vulkan-broker:{}] {} | {} threads (134M+ FLOPs) in {:.2} ms ({:.1} GFLOPS) | checksum={}",
                        mode,
                        r.adapter_name,
                        elements,
                        r.compute_us as f64 / 1000.0,
                        gflops,
                        r.checksum
                    );
                    writeln!(child_stdin, "GPU_RES:{}:{}", r.checksum, r.compute_us)?;
                    child_stdin.flush()?;
                }
                Err(e) => {
                    eprintln!("[vulkan-broker] Error: {}", e);
                    writeln!(child_stdin, "GPU_ERR:failed")?;
                    child_stdin.flush()?;
                }
            }
        } else if let Some(req) = line.strip_prefix("GPU_WGSL:") {
            if !allow_vulkan {
                writeln!(child_stdin, "GPU_ERR:denied")?;
                child_stdin.flush()?;
                continue;
            }
            let p: Vec<&str> = req.splitn(4, ':').collect();
            let elements: u32 = p.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let gseed: u32 = p.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let iters: u32 = p.get(2).and_then(|s| s.parse().ok()).unwrap_or(256);
            let wgsl_res = p.get(3).ok_or_else(|| anyhow::anyhow!("missing wgsl"))
                .and_then(|h| gpu::hex_decode(h))
                .and_then(|b| Ok(String::from_utf8(b)?));
            let res = wgsl_res.and_then(|wgsl| {
                match gpu::try_dispatch_wgsl_via_daemon(&sock_path, &wgsl, elements, gseed, iters) {
                    Some(r) => r,
                    None => gpu::dispatch_vulkan_wgsl(&wgsl, elements, gseed, iters),
                }
            });
            match res {
                Ok(r) => {
                    let mode = if r.warm { "WARM DAEMON" } else { "cold inline" };
                    eprintln!("[vulkan-broker:{}:CUSTOM_WGSL] {} | {} threads in {:.2} ms | checksum={}", mode, r.adapter_name, elements, r.compute_us as f64 / 1000.0, r.checksum);
                    writeln!(child_stdin, "GPU_RES:{}:{}", r.checksum, r.compute_us)?;
                }
                Err(e) => {
                    eprintln!("[vulkan-broker:CUSTOM_WGSL] REJECTED: {}", e);
                    writeln!(child_stdin, "GPU_ERR:rejected")?;
                }
            }
            child_stdin.flush()?;
        } else if let Some(json_str) = line.strip_prefix("DELTA:") {
            let delta: DeltaPayload = serde_json::from_str(json_str)
                .with_context(|| format!("Invalid delta JSON from worker: {}", json_str))?;
            let elapsed_us = t_total.elapsed().as_micros() as i64;
            conn.execute(
                "INSERT INTO semantic_deltas (ts_unix, capability_hash, entity, relation, value, latency_us)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![ts, hash, delta.entity, delta.relation, delta.value, elapsed_us],
            )?;
            committed += 1;
            println!(
                "[graph] Committed ({} --[{}]--> {})",
                delta.entity, delta.relation, delta.value
            );
        }
    }

    drop(child_stdin);
    let status = child.wait()?;
    let total_us = t_total.elapsed().as_micros() as i64;

    if let Some(sig) = status.signal() {
        if sig == libc::SIGSYS {
            println!(
                "[caprun] Worker terminated by kernel seccomp-BPF (SIGSYS) in {:.2} ms - escape blocked.",
                total_us as f64 / 1000.0
            );
            return Ok(());
        }
        bail!("Worker killed by signal {}", sig);
    }
    if !status.success() {
        bail!("Worker exited with status {}", status);
    }

    println!(
        "[caprun] Lifecycle complete: verify -> sandbox -> silicon -> {} delta(s) -> evaporated in {:.2} ms (0 B extracted)",
        committed,
        total_us as f64 / 1000.0
    );
    Ok(())
}

fn lock_down_worker() -> Result<()> {
    // 0. Disable core dumps + apport interception so SIGSYS returns in ~2-3 ms
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    // 1. Prevent privilege escalation
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        bail!("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    // 2. Attempt unprivileged namespaces
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        bail!("unshare(CLONE_NEWUSER|CLONE_NEWNET) failed: {}", std::io::Error::last_os_error());
    }

    // 3. Landlock: zero filesystem access
    let abi = ABI::V4;
    Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .restrict_self()?;

    // 4. seccomp-BPF: strict minimal allow-list
    let mut rules = BTreeMap::new();
    let allowed: &[i64] = &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_ioctl,
        libc::SYS_close,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_sched_yield,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    for &nr in allowed {
        rules.insert(nr, vec![]);
    }

    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()?,
    )?
    .try_into()?;

    seccompiler::apply_filter(&filter)?;
    Ok(())
}

fn cmd_worker(fuel: u64, seed: i32, allow_vulkan: bool, test_escape: bool) -> Result<()> {
    let mut stdin = std::io::stdin();
    let mut len_buf = [0u8; 8];
    stdin.read_exact(&mut len_buf)?;
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut cwasm_bytes = vec![0u8; len];
    stdin.read_exact(&mut cwasm_bytes)?;

    let engine = make_engine()?;
    let module = unsafe { Module::deserialize(&engine, &cwasm_bytes)? };

    lock_down_worker()?;

    if test_escape {
        eprintln!("[worker] Attempting forbidden socket() syscall...");
        unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        }
        bail!("Escape test failed: socket() was not blocked!");
    }

    let mut store = Store::new(&engine, ());
    store.set_fuel(fuel)?;

    let mut linker = Linker::new(&engine);
    linker.func_wrap(
        "cap",
        "emit_delta",
        |mut caller: Caller<'_, ()>, ptr: i32, len: i32| {
            if let Some(Extern::Memory(mem)) = caller.get_export("memory") {
                let mut buf = vec![0u8; len as usize];
                if mem.read(&caller, ptr as usize, &mut buf).is_ok() {
                    if let Ok(s) = std::str::from_utf8(&buf) {
                        println!("DELTA:{}", s);
                        let _ = std::io::stdout().flush();
                    }
                }
            }
        },
    )?;

    linker.func_wrap(
        "cap",
        "gpu_dispatch",
        move |elements: i32, gseed: i32| -> i32 {
            if !allow_vulkan {
                eprintln!("[worker] CAPABILITY DENIED: module requested Vulkan GPU without --cap vulkan");
                return -1;
            }
            println!("GPU_REQ:{}:{}", elements, gseed);
            let _ = std::io::stdout().flush();

            let mut resp = String::new();
            if std::io::stdin().read_line(&mut resp).is_ok() {
                if let Some(rest) = resp.trim().strip_prefix("GPU_RES:") {
                    if let Some(cs) = rest.split(':').next() {
                        if let Ok(val) = cs.parse::<i32>() {
                            return val;
                        }
                    }
                }
            }
            -2
        },
    )?;

    linker.func_wrap(
        "cap",
        "gpu_dispatch_wgsl",
        move |mut caller: Caller<'_, ()>, ptr: i32, len: i32, elements: i32, gseed: i32, iters: i32| -> i32 {
            if !allow_vulkan {
                eprintln!("[worker] CAPABILITY DENIED: custom WGSL requested without --cap vulkan");
                return -1;
            }
            if len <= 0 || len > 32_768 { return -3; }
            let Some(Extern::Memory(mem)) = caller.get_export("memory") else { return -2; };
            let mut buf = vec![0u8; len as usize];
            if mem.read(&caller, ptr as usize, &mut buf).is_err() { return -2; }
            println!("GPU_WGSL:{}:{}:{}:{}", elements, gseed, iters, gpu::hex_encode(&buf));
            let _ = std::io::stdout().flush();
            let mut resp = String::new();
            if std::io::stdin().read_line(&mut resp).is_ok() {
                if let Some(rest) = resp.trim().strip_prefix("GPU_RES:") {
                    if let Some(cs) = rest.split(':').next() {
                        if let Ok(v) = cs.parse::<i32>() { return v; }
                    }
                }
            }
            -2
        },
    )?;

    let t_exec = Instant::now();
    let instance = linker.instantiate(&mut store, &module)?;
    let entry = instance.get_typed_func::<i32, i32>(&mut store, "run")?;
    let result = entry.call(&mut store, seed)?;
    let exec_us = t_exec.elapsed().as_micros();
    let fuel_used = fuel.saturating_sub(store.get_fuel().unwrap_or(0));

    eprintln!(
        "[silicon] Worker exec: {:.2} ms | fuel_used={} | exit={}",
        exec_us as f64 / 1000.0,
        fuel_used,
        result
    );
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Put { path } => cmd_put(path),
        Cmd::Run {
            hash,
            fuel,
            seed,
            caps,
            test_escape,
        } => cmd_run(hash, fuel, seed, caps, test_escape),
        Cmd::Broker => gpu::serve_broker(&cas_root()?.join("vulkan.sock")),
        Cmd::Opsdeck { iface, port, llm } => opsdeck::run_opsdeck(iface, port, llm),
        Cmd::BenchGpu { elements, iters, runs } => gpu::bench_gpu(&cas_root()?.join("vulkan.sock"), elements, iters, runs),
        Cmd::Graph { limit } => cmd_graph(limit),
        Cmd::Worker {
            fuel,
            seed,
            allow_vulkan,
            test_escape,
        } => cmd_worker(fuel, seed, allow_vulkan, test_escape),
    }
}
