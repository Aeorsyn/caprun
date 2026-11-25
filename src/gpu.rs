use anyhow::{bail, Context, Result};
use bytemuck::{Pod, Zeroable};
use std::borrow::Cow;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Instant;

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
struct GpuParams {
    seed: u32,
    count: u32,
    _pad0: u32,
    _pad1: u32,
}

const WGSL_COMPUTE: &str = r#"
struct Params {
    seed: u32,
    count: u32,
    _pad0: u32,
    _pad1: u32,
};

@group(0) @binding(0) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(1) var<uniform> params: Params;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if (idx >= params.count) {
        return;
    }
    var x: f32 = f32((idx ^ params.seed) & 1023u) * 0.001 + 1.0;
    let step: f32 = 1.00001;
    let bias: f32 = 0.0001;
    for (var i: u32 = 0u; i < 256u; i = i + 1u) {
        x = fma(x, step, bias);
    }
    out_buf[idx] = x;
}
"#;

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
    pipeline: wgpu::ComputePipeline,
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
        .context("No Vulkan GPU adapter available (check mesa-vulkan-drivers)")?;

        let adapter_name = adapter.get_info().name;
        let (device, queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default(), None))?;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("caprun_vulkan_compute"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(WGSL_COMPUTE)),
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("caprun_compute_pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

        Ok(Self {
            adapter_name,
            device,
            queue,
            pipeline,
        })
    }

    pub fn dispatch(&self, elements: u32, seed: u32, warm: bool) -> Result<GpuResult> {
        if elements == 0 || elements > 1_048_576 {
            bail!("GPU dispatch elements out of safe bounds (1..=1048576)");
        }

        let byte_size = (elements as u64) * std::mem::size_of::<f32>() as u64;
        let storage_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("storage_out"),
            size: byte_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let staging_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging_readback"),
            size: byte_size,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let params = GpuParams {
            seed,
            count: elements,
            _pad0: 0,
            _pad1: 0,
        };
        let uniform_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("uniform_params"),
            size: std::mem::size_of::<GpuParams>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        self.queue
            .write_buffer(&uniform_buf, 0, bytemuck::bytes_of(&params));

        let bind_group_layout = self.pipeline.get_bind_group_layout(0);
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("compute_bg"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: storage_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: uniform_buf.as_entire_binding(),
                },
            ],
        });

        let t_gpu = Instant::now();
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("compute_encoder"),
            });
        {
            let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("compute_pass"),
                timestamp_writes: None,
            });
            cpass.set_pipeline(&self.pipeline);
            cpass.set_bind_group(0, &bind_group, &[]);
            cpass.dispatch_workgroups(elements.div_ceil(64), 1, 1);
        }
        encoder.copy_buffer_to_buffer(&storage_buf, 0, &staging_buf, 0, byte_size);
        self.queue.submit(Some(encoder.finish()));

        let slice = staging_buf.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx.send(res);
        });
        self.device.poll(wgpu::Maintain::Wait);
        rx.recv()??;

        let compute_us = t_gpu.elapsed().as_micros();
        let data = slice.get_mapped_range();
        let floats: &[f32] = bytemuck::cast_slice(&data);
        let sum: f64 = floats.iter().map(|&v| v as f64).sum();
        let checksum = (sum.abs() as u64) % 10_000_000;
        drop(data);
        staging_buf.unmap();

        Ok(GpuResult {
            adapter_name: self.adapter_name.clone(),
            checksum,
            compute_us,
            warm,
        })
    }
}

pub fn dispatch_vulkan_compute(elements: u32, seed: u32) -> Result<GpuResult> {
    let broker = VulkanBroker::new()?;
    broker.dispatch(elements, seed, false)
}

pub fn try_dispatch_via_daemon(
    sock_path: &Path,
    elements: u32,
    seed: u32,
) -> Option<Result<GpuResult>> {
    let mut stream = UnixStream::connect(sock_path).ok()?;
    if writeln!(stream, "{}:{}", elements, seed).is_err() {
        return None;
    }
    let _ = stream.flush();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return None;
    }
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("OK:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() == 3 {
            let checksum = parts[0].parse::<u64>().ok()?;
            let compute_us = parts[1].parse::<u128>().ok()?;
            let adapter_name = parts[2].to_string();
            return Some(Ok(GpuResult {
                adapter_name,
                checksum,
                compute_us,
                warm: true,
            }));
        }
    }
    Some(Err(anyhow::anyhow!("Broker returned: {}", trimmed)))
}

pub fn serve_broker(sock_path: &Path) -> Result<()> {
    if sock_path.exists() {
        let _ = std::fs::remove_file(sock_path);
    }
    let broker = VulkanBroker::new()?;
    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("Failed to bind {:?}", sock_path))?;
    eprintln!(
        "[vulkan-daemon] {} warm & listening on {:?}",
        broker.adapter_name, sock_path
    );

    for conn in listener.incoming() {
        if let Ok(mut stream) = conn {
            let mut reader = BufReader::new(match stream.try_clone() {
                Ok(s) => s,
                Err(_) => continue,
            });
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                let parts: Vec<&str> = line.trim().split(':').collect();
                let elements: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                let seed: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                match broker.dispatch(elements, seed, true) {
                    Ok(res) => {
                        let _ = writeln!(
                            stream,
                            "OK:{}:{}:{}",
                            res.checksum, res.compute_us, res.adapter_name
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(stream, "ERR:{}", e);
                    }
                }
                let _ = stream.flush();
            }
        }
    }
    Ok(())
}
