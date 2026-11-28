use anyhow::{anyhow, Result};
use bytemuck::{Pod, Zeroable};
use std::{borrow::Cow, fs, path::PathBuf, time::Instant};

pub const W: u32 = 512;
pub const H: u32 = 512;
pub const N: usize = (W * H) as usize;

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Params {
    tick: u32,
    stim_count: u32,
    lr: f32,
    decay: f32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Stim {
    pub x: u32,
    pub y: u32,
    pub amp: f32,
    pub _pad: u32,
}

const STDP_WGSL: &str = r#"
struct Params { tick: u32, stim_count: u32, lr: f32, decay: f32 };
struct Stim { x: u32, y: u32, amp: f32, _pad: u32 };

@group(0) @binding(0) var<storage, read_write> mem: array<f32>;
@group(0) @binding(1) var<storage, read_write> weights: array<f32>;
@group(0) @binding(2) var<storage, read_write> frame: array<u32>;
@group(0) @binding(3) var<storage, read> stims: array<Stim>;
@group(0) @binding(4) var<uniform> p: Params;

@compute @workgroup_size(16, 16)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x >= 512u || gid.y >= 512u) { return; }
    let idx = gid.y * 512u + gid.x;
    var inp = 0.0;
    for (var i = 0u; i < p.stim_count; i = i + 1u) {
        let dx = f32(gid.x) - f32(stims[i].x);
        let dy = f32(gid.y) - f32(stims[i].y);
        let d2 = dx * dx + dy * dy;
        if (d2 < 36.0) { inp += stims[i].amp * exp(-d2 * 0.14); }
    }
    var w = weights[idx];
    let pred_err = max(0.0, inp - w);
    var v = mem[idx] * p.decay + pred_err * 1.35;
    let spike = select(0.0, 1.0, v >= 1.0);
    if (spike > 0.5) { v = 0.0; }
    // STDP / Hebbian baseline adaptation: routine input raises weight, silence slowly decays
    if (inp > 0.05) {
        w = min(0.95, w + p.lr * (inp - w));
    } else {
        w = max(0.0, w * 0.9997);
    }
    mem[idx] = v;
    weights[idx] = w;

    let r = u32(clamp(spike * 255.0 + pred_err * 180.0, 0.0, 255.0));
    let g = u32(clamp(v * 220.0 + w * 90.0, 0.0, 255.0));
    let b = u32(clamp(w * 255.0 + 18.0, 0.0, 255.0));
    frame[idx] = r | (g << 8u) | (b << 16u) | (255u << 24u);
}
"#;

pub struct StdpCortex {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipe: wgpu::ComputePipeline,
    bg: wgpu::BindGroup,
    weights_buf: wgpu::Buffer,
    frame_buf: wgpu::Buffer,
    stim_buf: wgpu::Buffer,
    param_buf: wgpu::Buffer,
    stage_u32: wgpu::Buffer,
    stage_f32: wgpu::Buffer,
    pub tick: u32,
    pub adapter_name: String,
}

impl StdpCortex {
    pub fn new() -> Result<Self> {
        let inst = wgpu::Instance::new(wgpu::InstanceDescriptor::default());
        let adapter = pollster::block_on(inst.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))
        .ok_or_else(|| anyhow!("No Vulkan/wgpu adapter found"))?;
        let adapter_name = adapter.get_info().name;
        let (device, queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default(), None))?;

        let sz = (N * 4) as u64;
        let rw = wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC | wgpu::BufferUsages::COPY_DST;
        let mem_buf = device.create_buffer(&wgpu::BufferDescriptor { label: Some("mem"), size: sz, usage: rw, mapped_at_creation: false });
        let weights_buf = device.create_buffer(&wgpu::BufferDescriptor { label: Some("weights"), size: sz, usage: rw, mapped_at_creation: false });
        let frame_buf = device.create_buffer(&wgpu::BufferDescriptor { label: Some("frame"), size: sz, usage: rw, mapped_at_creation: false });
        let stim_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("stims"),
            size: (64 * std::mem::size_of::<Stim>()) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let param_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("params"),
            size: std::mem::size_of::<Params>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let stage_u32 = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("stage_u32"), size: sz,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ, mapped_at_creation: false,
        });
        let stage_f32 = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("stage_f32"), size: sz,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ, mapped_at_creation: false,
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("cortex_stdp"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(STDP_WGSL)),
        });
        let pipe = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("cortex_stdp_pipe"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });
        let bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("cortex_stdp_bg"),
            layout: &pipe.get_bind_group_layout(0),
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: mem_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: weights_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 2, resource: frame_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 3, resource: stim_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 4, resource: param_buf.as_entire_binding() },
            ],
        });

        let mut me = Self {
            device, queue, pipe, bg, weights_buf, frame_buf, stim_buf, param_buf,
            stage_u32, stage_f32, tick: 0, adapter_name,
        };
        let _ = me.load_baseline();
        Ok(me)
    }

    pub fn baseline_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".cas").join("baseline.bin")
    }

    pub fn step(&mut self, stims: &[Stim]) -> (Vec<u8>, u64, u32) {
        let t0 = Instant::now();
        self.tick = self.tick.wrapping_add(1);
        let cnt = stims.len().min(64);
        if cnt > 0 {
            self.queue.write_buffer(&self.stim_buf, 0, bytemuck::cast_slice(&stims[..cnt]));
        }
        let p = Params { tick: self.tick, stim_count: cnt as u32, lr: 0.015, decay: 0.88 };
        self.queue.write_buffer(&self.param_buf, 0, bytemuck::bytes_of(&p));

        let mut enc = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
            pass.set_pipeline(&self.pipe);
            pass.set_bind_group(0, &self.bg, &[]);
            pass.dispatch_workgroups(W / 16, H / 16, 1);
        }
        enc.copy_buffer_to_buffer(&self.frame_buf, 0, &self.stage_u32, 0, (N * 4) as u64);
        self.queue.submit(Some(enc.finish()));

        let slice = self.stage_u32.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| { let _ = tx.send(r); });
        self.device.poll(wgpu::Maintain::Wait);
        let _ = rx.recv();

        let data = slice.get_mapped_range();
        let rgba: Vec<u8> = data.to_vec();
        let mut surprise = 0u32;
        for px in rgba.chunks_exact(4).step_by(8) {
            if px[0] > 180 { surprise += 1; }
        }
        drop(data);
        self.stage_u32.unmap();
        (rgba, t0.elapsed().as_micros() as u64, surprise)
    }

    pub fn read_weights(&self) -> Vec<f32> {
        let mut enc = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
        enc.copy_buffer_to_buffer(&self.weights_buf, 0, &self.stage_f32, 0, (N * 4) as u64);
        self.queue.submit(Some(enc.finish()));
        let slice = self.stage_f32.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| { let _ = tx.send(r); });
        self.device.poll(wgpu::Maintain::Wait);
        let _ = rx.recv();
        let data = slice.get_mapped_range();
        let out: Vec<f32> = bytemuck::cast_slice(&data).to_vec();
        drop(data);
        self.stage_f32.unmap();
        out
    }

    pub fn save_baseline(&self) -> Result<String> {
        let path = Self::baseline_path();
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        let w = self.read_weights();
        fs::write(&path, bytemuck::cast_slice(&w))?;
        Ok(format!("Saved 262,144 STDP weights ({} KB) -> {}", w.len() * 4 / 1024, path.display()))
    }

    pub fn load_baseline(&mut self) -> Result<String> {
        let path = Self::baseline_path();
        let bytes = fs::read(&path)?;
        if bytes.len() != N * 4 { return Err(anyhow!("Invalid baseline size")); }
        self.queue.write_buffer(&self.weights_buf, 0, &bytes);
        Ok(format!("Loaded persistent STDP baseline from {}", path.display()))
    }

    pub fn diff_baseline(&self) -> Result<(f32, usize)> {
        let bytes = fs::read(Self::baseline_path())?;
        if bytes.len() != N * 4 { return Err(anyhow!("No saved baseline to diff")); }
        let base: &[f32] = bytemuck::cast_slice(&bytes);
        let live = self.read_weights();
        let mut max_d = 0.0f32;
        let mut drifted = 0usize;
        for (a, b) in live.iter().zip(base.iter()) {
            let d = (a - b).abs();
            if d > max_d { max_d = d; }
            if d > 0.15 { drifted += 1; }
        }
        Ok((max_d, drifted))
    }
}
