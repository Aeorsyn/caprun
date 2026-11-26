use anyhow::{bail, Context, Result};
use bytemuck::{Pod, Zeroable};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Instant;

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
struct GpuParams {
    seed: u32,
    count: u32,
    iters: u32,
    _pad: u32,
}

const DEFAULT_WGSL: &str = r#"
struct Params { seed: u32, count: u32, iters: u32, _pad: u32 };
@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if (idx >= params.count) { return; }
    let iters = select(params.iters, 256u, params.iters == 0u);
    let base = f32((idx ^ params.seed) & 1023u) * 0.001 + 1.0;
    var a = vec4<f32>(base, base + 0.1, base + 0.2, base + 0.3);
    var b = vec4<f32>(base + 0.4, base + 0.5, base + 0.6, base + 0.7);
    var c = vec4<f32>(base + 0.8, base + 0.9, base + 1.0, base + 1.1);
    var d = vec4<f32>(base + 1.2, base + 1.3, base + 1.4, base + 1.5);
    let s0 = vec4<f32>(0.99999, 0.99998, 0.99997, 0.99996);
    let s1 = vec4<f32>(0.99995, 0.99994, 0.99993, 0.99992);
    let b0 = vec4<f32>(0.00002, 0.00003, 0.00004, 0.00005);
    let b1 = vec4<f32>(0.00006, 0.00007, 0.00008, 0.00009);
    for (var i: u32 = 0u; i < iters; i = i + 1u) {
        a = fma(a, s0, b0); b = fma(b, s1, b1);
        c = fma(c, s0, b1); d = fma(d, s1, b0);
    }
    let acc = a + b + c + d;
    out_buf[idx] = (acc.x + acc.y + acc.z + acc.w) * 0.0625;
}
"#;

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        bail!("Invalid hex length");
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).context("Invalid hex byte")?;
        out.push(byte);
    }
    Ok(out)
}

pub struct GpuResult {
    pub adapter_name: String,
    pub checksum: u64,
    pub compute_us: u128,
    pub warm: bool,
}

pub struct VulkanBroker {
    adapter_name: String,
    device: wgpu::Device,
    queue: wgpu::Queue,
    bind_group_layout: wgpu::BindGroupLayout,
    pipeline_layout: wgpu::PipelineLayout,
    default_pipeline: wgpu::ComputePipeline,
    custom_pipelines: HashMap<String, wgpu::ComputePipeline>,
}
impl VulkanBroker {
    pub fn new() -> Result<Self> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::VULKAN,
            ..Default::default()
        });
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))
        .context("No Vulkan GPU adapter available")?;

        let adapter_name = adapter.get_info().name;
        let (device, queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default(), None))?;

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("caprun_bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("caprun_pl"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("default_wgsl"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(DEFAULT_WGSL)),
        });
        let default_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("default_pipe"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

        Ok(Self {
            adapter_name,
            device,
            queue,
            bind_group_layout,
            pipeline_layout,
            default_pipeline,
            custom_pipelines: HashMap::new(),
        })
    }

    fn compile_validated(&self, wgsl: &str) -> Result<wgpu::ComputePipeline> {
        if wgsl.is_empty() || wgsl.len() > 32_768 {
            bail!("WGSL size out of bounds (1..=32768 bytes)");
        }
        if !wgsl.contains("@compute") || !wgsl.contains("fn main") {
            bail!("WGSL must declare @compute and fn main");
        }

        self.device.push_error_scope(wgpu::ErrorFilter::Validation);
        let shader = self.device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("guest_wgsl"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(wgsl)),
        });
        if let Some(err) = pollster::block_on(self.device.pop_error_scope()) {
            bail!("WGSL shader validation failed: {}", err);
        }

        self.device.push_error_scope(wgpu::ErrorFilter::Validation);
        let pipe = self.device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("guest_pipe"),
            layout: Some(&self.pipeline_layout),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });
        if let Some(err) = pollster::block_on(self.device.pop_error_scope()) {
            bail!("WGSL pipeline validation failed: {}", err);
        }
        Ok(pipe)
    }

    fn run_pipeline(
        &self,
        pipe: &wgpu::ComputePipeline,
        elements: u32,
        seed: u32,
        iters: u32,
        warm: bool,
    ) -> Result<GpuResult> {
        if elements == 0 || elements > 1_048_576 {
            bail!("GPU elements out of safe bounds (1..=1048576)");
        }
        if iters == 0 || iters > 65_536 {
            bail!("GPU iters out of safe bounds (1..=65536)");
        }
        let byte_size = (elements as u64) * 4;
        let storage = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("storage_out"),
            size: byte_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging_readback"),
            size: byte_size,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let params = GpuParams { seed, count: elements, iters, _pad: 0 };
        let uniform = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("uniform_params"),
            size: std::mem::size_of::<GpuParams>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        self.queue.write_buffer(&uniform, 0, bytemuck::bytes_of(&params));

        let bg = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("compute_bg"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: storage.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: uniform.as_entire_binding() },
            ],
        });

        let t_gpu = Instant::now();
        let mut enc = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor { label: None, timestamp_writes: None });
            pass.set_pipeline(pipe);
            pass.set_bind_group(0, &bg, &[]);
            pass.dispatch_workgroups(elements.div_ceil(64), 1, 1);
        }
        enc.copy_buffer_to_buffer(&storage, 0, &staging, 0, byte_size);
        self.queue.submit(Some(enc.finish()));

        let slice = staging.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| { let _ = tx.send(r); });
        self.device.poll(wgpu::Maintain::Wait);
        rx.recv()??;

        let compute_us = t_gpu.elapsed().as_micros();
        let data = slice.get_mapped_range();
        let floats: &[f32] = bytemuck::cast_slice(&data);
        let sum: f64 = floats.iter().filter(|v| v.is_finite()).map(|&v| v as f64).sum();
        let checksum = (sum.abs() as u64) % 10_000_000;
        drop(data);
        staging.unmap();

        Ok(GpuResult { adapter_name: self.adapter_name.clone(), checksum, compute_us, warm })
    }

    pub fn dispatch(&self, elements: u32, seed: u32, iters: u32, warm: bool) -> Result<GpuResult> {
        self.run_pipeline(&self.default_pipeline, elements, seed, iters, warm)
    }

    pub fn dispatch_wgsl(&mut self, wgsl: &str, elements: u32, seed: u32, iters: u32, warm: bool) -> Result<GpuResult> {
        let key = blake3::hash(wgsl.as_bytes()).to_hex().to_string();
        if !self.custom_pipelines.contains_key(&key) {
            if self.custom_pipelines.len() >= 64 {
                self.custom_pipelines.clear();
            }
            let pipe = self.compile_validated(wgsl)?;
            self.custom_pipelines.insert(key.clone(), pipe);
        }
        let pipe = &self.custom_pipelines[&key];
        self.run_pipeline(pipe, elements, seed, iters, warm)
    }

    pub fn dispatch_frame(&mut self, wgsl: &str, elements: u32, seed: u32, iters: u32) -> Result<(Vec<u8>, u128)> {
        if elements == 0 || elements > 1_048_576 { bail!("elements out of bounds"); }
        let key = blake3::hash(wgsl.as_bytes()).to_hex().to_string();
        if !self.custom_pipelines.contains_key(&key) {
            if self.custom_pipelines.len() >= 64 { self.custom_pipelines.clear(); }
            let pipe = self.compile_validated(wgsl)?;
            self.custom_pipelines.insert(key.clone(), pipe);
        }
        let pipe = &self.custom_pipelines[&key];
        let byte_size = (elements as u64) * 4;
        let storage = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: None, size: byte_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC, mapped_at_creation: false,
        });
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: None, size: byte_size,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST, mapped_at_creation: false,
        });
        let params = GpuParams { seed, count: elements, iters, _pad: 0 };
        let uniform = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: None, size: std::mem::size_of::<GpuParams>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST, mapped_at_creation: false,
        });
        self.queue.write_buffer(&uniform, 0, bytemuck::bytes_of(&params));
        let bg = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: None, layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: storage.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: uniform.as_entire_binding() },
            ],
        });
        let t_gpu = Instant::now();
        let mut enc = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor { label: None, timestamp_writes: None });
            pass.set_pipeline(pipe);
            pass.set_bind_group(0, &bg, &[]);
            pass.dispatch_workgroups(elements.div_ceil(64), 1, 1);
        }
        enc.copy_buffer_to_buffer(&storage, 0, &staging, 0, byte_size);
        self.queue.submit(Some(enc.finish()));
        let slice = staging.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| { let _ = tx.send(r); });
        self.device.poll(wgpu::Maintain::Wait);
        rx.recv()??;
        let us = t_gpu.elapsed().as_micros();
        let data = slice.get_mapped_range();
        let floats: &[f32] = bytemuck::cast_slice(&data);
        let mut rgb = Vec::with_capacity(floats.len() * 3);
        for &v in floats {
            let c = v.clamp(0.0, 16_777_215.0) as u32;
            rgb.push(((c >> 16) & 0xff) as u8);
            rgb.push(((c >> 8) & 0xff) as u8);
            rgb.push((c & 0xff) as u8);
        }
        drop(data);
        staging.unmap();
        Ok((rgb, us))
    }
}
pub fn dispatch_vulkan_compute(elements: u32, seed: u32, iters: u32) -> Result<GpuResult> {
    VulkanBroker::new()?.dispatch(elements, seed, iters, false)
}

pub fn dispatch_vulkan_wgsl(wgsl: &str, elements: u32, seed: u32, iters: u32) -> Result<GpuResult> {
    VulkanBroker::new()?.dispatch_wgsl(wgsl, elements, seed, iters, false)
}

fn parse_daemon_reply(line: &str) -> Option<Result<GpuResult>> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("OK:") {
        let p: Vec<&str> = rest.splitn(3, ':').collect();
        if p.len() == 3 {
            return Some(Ok(GpuResult {
                checksum: p[0].parse().ok()?,
                compute_us: p[1].parse().ok()?,
                adapter_name: p[2].to_string(),
                warm: true,
            }));
        }
    }
    Some(Err(anyhow::anyhow!("{}", trimmed)))
}

pub fn try_dispatch_via_daemon(sock: &Path, elements: u32, seed: u32, iters: u32) -> Option<Result<GpuResult>> {
    let mut s = UnixStream::connect(sock).ok()?;
    writeln!(s, "{}:{}:{}", elements, seed, iters).ok()?;
    let _ = s.flush();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).ok()?;
    parse_daemon_reply(&line)
}

pub fn try_dispatch_wgsl_via_daemon(sock: &Path, wgsl: &str, elements: u32, seed: u32, iters: u32) -> Option<Result<GpuResult>> {
    let mut s = UnixStream::connect(sock).ok()?;
    writeln!(s, "WGSL:{}:{}:{}:{}", elements, seed, iters, hex_encode(wgsl.as_bytes())).ok()?;
    let _ = s.flush();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).ok()?;
    parse_daemon_reply(&line)
}

pub fn serve_broker(sock_path: &Path) -> Result<()> {
    if sock_path.exists() { let _ = std::fs::remove_file(sock_path); }
    let mut broker = VulkanBroker::new()?;
    let listener = UnixListener::bind(sock_path).with_context(|| format!("Failed to bind {:?}", sock_path))?;
    eprintln!("[vulkan-daemon] {} warm & listening (fixed + custom WGSL) on {:?}", broker.adapter_name, sock_path);

    for conn in listener.incoming().flatten() {
        let mut stream = conn;
        let Ok(cloned) = stream.try_clone() else { continue; };
        let mut line = String::new();
        if BufReader::new(cloned).read_line(&mut line).is_ok() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("FRAME:") {
                let p: Vec<&str> = rest.splitn(4, ':').collect();
                if p.len() == 4 {
                    let el = p[0].parse().unwrap_or(0);
                    let sd = p[1].parse().unwrap_or(0);
                    let it = p[2].parse().unwrap_or(64);
                    let res = hex_decode(p[3])
                        .and_then(|b| Ok(String::from_utf8(b)?))
                        .and_then(|wgsl| broker.dispatch_frame(&wgsl, el, sd, it));
                    match res {
                        Ok((rgb, us)) => {
                            let _ = writeln!(stream, "OK_FRAME:{}:{}", rgb.len(), us);
                            let _ = stream.write_all(&rgb);
                        }
                        Err(e) => { let _ = writeln!(stream, "ERR:{}", e); }
                    }
                    let _ = stream.flush();
                }
                continue;
            }
            let res = if let Some(rest) = trimmed.strip_prefix("WGSL:") {
                let p: Vec<&str> = rest.splitn(4, ':').collect();
                if p.len() == 4 {
                    let el = p[0].parse().unwrap_or(0);
                    let sd = p[1].parse().unwrap_or(0);
                    let it = p[2].parse().unwrap_or(256);
                    match hex_decode(p[3]).and_then(|b| Ok(String::from_utf8(b)?)) {
                        Ok(wgsl) => broker.dispatch_wgsl(&wgsl, el, sd, it, true),
                        Err(e) => Err(e),
                    }
                } else {
                    Err(anyhow::anyhow!("Malformed WGSL request"))
                }
            } else {
                let p: Vec<&str> = trimmed.split(':').collect();
                let el = p.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                let sd = p.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                let it = p.get(2).and_then(|s| s.parse().ok()).unwrap_or(256);
                broker.dispatch(el, sd, it, true)
            };
            match res {
                Ok(r) => { let _ = writeln!(stream, "OK:{}:{}:{}", r.checksum, r.compute_us, r.adapter_name); }
                Err(e) => { let _ = writeln!(stream, "ERR:{}", e); }
            }
            let _ = stream.flush();
        }
    }
    Ok(())
}

pub fn bench_gpu(sock_path: &Path, elements: u32, iters: u32, runs: usize) -> Result<()> {
    let go = || match try_dispatch_via_daemon(sock_path, elements, 42, iters) {
        Some(r) => r,
        None => dispatch_vulkan_compute(elements, 42, iters),
    };
    let w = go()?;
    let total_flops = (elements as f64) * (iters as f64) * 32.0;
    let mode = if w.warm { "WARM DAEMON" } else { "cold inline" };
    println!("[bench-gpu:{}] {} | {}x{} ({:.2} GFLOPs)", mode, w.adapter_name, elements, iters, total_flops / 1e9);
    let mut best = 0.0f64;
    for i in 1..=runs {
        let r = go()?;
        let gf = total_flops / (r.compute_us.max(1) as f64 * 1000.0);
        best = best.max(gf);
        println!("  run {}/{}: {:>7.2} ms | {:>7.1} GFLOPS ({:.3} TFLOPS) | cs={}", i, runs, r.compute_us as f64 / 1000.0, gf, gf / 1000.0, r.checksum);
    }
    println!("  -> Peak: {:.1} GFLOPS ({:.3} TFLOPS)", best, best / 1000.0);
    Ok(())
}
