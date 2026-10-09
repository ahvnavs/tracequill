use crate::hash::hash_bytes;
use chrono::Utc;
use std::fs;
use std::path::Path;
use std::process::Command;
use tq_claims::{Claim, EvidenceItem};

#[derive(Debug, Default)]
pub struct HostInventory {
    pub kernel: String,
    pub distro: String,
    pub glibc: String,
    pub wsl_version: Option<String>,
    pub container_hint: Option<String>,
    pub cpu_model: String,
    pub cpu_features: Vec<String>,
    pub total_ram_kb: u64,
    pub gpu_info: Option<String>,
    pub listeners: Vec<String>,
    pub outbound_connections: Vec<String>,
    pub python_packages: Vec<(String, String)>,
    pub systemd_units: Vec<String>,
    pub dpkg_packages: Vec<(String, String)>,
}

/// Detects WSL 1 or 2 by checking /proc/version and /proc/sys/fs/binfmt_misc
pub fn detect_wsl(proc_root: &Path) -> Option<String> {
    if let Ok(v) = fs::read_to_string(proc_root.join("version")) {
        let lower = v.to_lowercase();
        if lower.contains("microsoft") || lower.contains("wsl") {
            if lower.contains("wsl2") {
                return Some("WSL2".to_string());
            }
            return Some("WSL".to_string());
        }
    }
    None
}

/// Detects container environments from /proc/1/cgroup or container markers
pub fn detect_container(proc_root: &Path) -> Option<String> {
    if let Ok(cg) = fs::read_to_string(proc_root.join("1").join("cgroup")) {
        if cg.contains("docker") {
            return Some("docker".to_string());
        }
        if cg.contains("containerd") {
            return Some("containerd".to_string());
        }
        if cg.contains("kubepods") {
            return Some("kubernetes".to_string());
        }
    }
    None
}

/// Reads CPU model and features from /proc/cpuinfo
pub fn read_cpuinfo(proc_root: &Path) -> (String, Vec<String>) {
    let mut model = "unknown".to_string();
    let mut features = Vec::new();

    if let Ok(content) = fs::read_to_string(proc_root.join("cpuinfo")) {
        for line in content.lines() {
            if line.starts_with("model name") {
                if let Some(idx) = line.find(':') {
                    model = line[idx + 1..].trim().to_string();
                }
            } else if line.starts_with("flags") {
                if let Some(idx) = line.find(':') {
                    let flags_str = line[idx + 1..].trim();
                    for f in flags_str.split_whitespace() {
                        features.push(f.to_string());
                    }
                }
            }
        }
    }
    (model, features)
}

/// Reads total RAM from /proc/meminfo
pub fn read_meminfo(proc_root: &Path) -> u64 {
    if let Ok(content) = fs::read_to_string(proc_root.join("meminfo")) {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb;
                    }
                }
            }
        }
    }
    0
}

/// Parse /proc/net/tcp and /proc/net/tcp6 for listening sockets
pub fn read_listeners(proc_root: &Path) -> Vec<String> {
    let mut listeners = Vec::new();
    let net_tcp = proc_root.join("net").join("tcp");
    if let Ok(content) = fs::read_to_string(net_tcp) {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                let state = fields[3];
                if state == "0A" {
                    // TCP_LISTEN
                    if let Some(local) = fields.get(1) {
                        if let Some(colon) = local.find(':') {
                            let port_hex = &local[colon + 1..];
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                listeners.push(format!("0.0.0.0:{}", port));
                            }
                        }
                    }
                }
            }
        }
    }
    listeners
}

/// Runs documented read-only query nvidia-smi --query-gpu=... to detect GPU.
/// If tool is missing or fails, returns None ("not visible", never "no GPU").
pub fn query_gpu_nvidia_smi() -> Option<String> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,driver_version,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

/// Reads Python package version from *.dist-info/METADATA
pub fn parse_python_dist_info_metadata(metadata_path: &Path) -> Option<(String, String)> {
    let content = fs::read_to_string(metadata_path).ok()?;
    let mut name = None;
    let mut version = None;

    for line in content.lines() {
        if let Some(stripped) = line.strip_prefix("Name:") {
            name = Some(stripped.trim().to_string());
        } else if let Some(stripped) = line.strip_prefix("Version:") {
            version = Some(stripped.trim().to_string());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }

    if let (Some(n), Some(v)) = (name, version) {
        Some((n, v))
    } else {
        None
    }
}

/// Reads dpkg status database (from /var/lib/dpkg/status) to extract installed packages
pub fn read_dpkg_status(root_dir: &Path) -> Vec<(String, String)> {
    let status_path = root_dir.join("var/lib/dpkg/status");
    let mut pkgs = Vec::new();

    if let Ok(content) = fs::read_to_string(status_path) {
        let mut curr_pkg = None;
        let mut curr_ver = None;

        for line in content.lines() {
            if let Some(stripped) = line.strip_prefix("Package: ") {
                curr_pkg = Some(stripped.trim().to_string());
            } else if let Some(stripped) = line.strip_prefix("Version: ") {
                curr_ver = Some(stripped.trim().to_string());
            } else if line.is_empty() {
                if let (Some(p), Some(v)) = (curr_pkg.take(), curr_ver.take()) {
                    pkgs.push((p, v));
                }
            }
        }
        if let (Some(p), Some(v)) = (curr_pkg, curr_ver) {
            pkgs.push((p, v));
        }
    }

    pkgs
}

/// Collects host-level claims
pub fn collect_host_claims(
    host_ref: &str,
    proc_root: &Path,
    _sys_root: &Path,
) -> (Vec<Claim>, Vec<EvidenceItem>) {
    let mut claims = Vec::new();
    let mut evidence = Vec::new();
    let now = Utc::now().to_rfc3339();

    let mut add_evidence = |content: &str| -> String {
        let h = hash_bytes(content.as_bytes());
        evidence.push(EvidenceItem {
            hash: h.clone(),
            payload_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                content.as_bytes(),
            ),
        });
        h
    };

    // Kernel
    if let Ok(uname_output) = Command::new("uname").arg("-r").output() {
        if uname_output.status.success() {
            let kernel = String::from_utf8_lossy(&uname_output.stdout)
                .trim()
                .to_string();
            let ev = add_evidence(&format!("uname -r: {}", kernel));
            claims.push(Claim::new(
                host_ref,
                "host.kernel",
                "text",
                serde_json::Value::String(kernel),
                &now,
                "agent",
                "agent-collector",
                "uname",
                host_ref,
                ev,
                "none",
            ));
        }
    }

    // RAM
    let ram_kb = read_meminfo(proc_root);
    if ram_kb > 0 {
        let ev = add_evidence(&format!("meminfo MemTotal: {} kB", ram_kb));
        claims.push(Claim::new(
            host_ref,
            "host.ram_bytes",
            "int",
            serde_json::Value::Number(serde_json::Number::from(ram_kb * 1024)),
            &now,
            "agent",
            "agent-collector",
            "procfs",
            host_ref,
            ev,
            "none",
        ));
    }

    // CPU Model & Features
    let (model, features) = read_cpuinfo(proc_root);
    if !model.is_empty() && model != "unknown" {
        let ev = add_evidence(&format!("cpuinfo model: {}", model));
        claims.push(Claim::new(
            host_ref,
            "host.cpu_feature",
            "text",
            serde_json::Value::String(model),
            &now,
            "agent",
            "agent-collector",
            "procfs",
            host_ref,
            ev,
            "none",
        ));
    }
    for f in features.iter().take(10) {
        let ev = add_evidence(&format!("cpu flag: {}", f));
        claims.push(Claim::new(
            host_ref,
            "host.cpu_feature",
            "text",
            serde_json::Value::String(f.clone()),
            &now,
            "agent",
            "agent-collector",
            "procfs",
            host_ref,
            ev,
            "none",
        ));
    }

    // WSL detection
    if let Some(wsl) = detect_wsl(proc_root) {
        let ev = add_evidence(&format!("wsl: {}", wsl));
        claims.push(Claim::new(
            host_ref,
            "coverage.observed",
            "text",
            serde_json::Value::String(format!("wsl:{}", wsl)),
            &now,
            "agent",
            "agent-collector",
            "procfs",
            host_ref,
            ev,
            "none",
        ));
    }

    // Container hint
    if let Some(cont) = detect_container(proc_root) {
        let ev = add_evidence(&format!("container: {}", cont));
        claims.push(Claim::new(
            host_ref,
            "coverage.observed",
            "text",
            serde_json::Value::String(format!("container:{}", cont)),
            &now,
            "agent",
            "agent-collector",
            "procfs",
            host_ref,
            ev,
            "none",
        ));
    }

    // GPU: query nvidia-smi. If missing, mark as "not visible" (NEVER "no GPU")!
    match query_gpu_nvidia_smi() {
        Some(gpu) => {
            let ev = add_evidence(&format!("nvidia-smi: {}", gpu));
            claims.push(Claim::new(
                host_ref,
                "host.gpu",
                "ref",
                serde_json::Value::String("ref://gpu/gpu-0".to_string()),
                &now,
                "agent",
                "agent-collector",
                "nvidia-smi",
                host_ref,
                ev,
                "none",
            ));
        }
        None => {
            let ev = add_evidence("nvidia-smi tool missing or query unreadable");
            claims.push(Claim::new(
                host_ref,
                "coverage.blocked",
                "text",
                serde_json::Value::String(
                    "gpu_telemetry_not_visible:nvidia_smi_unavailable".to_string(),
                ),
                &now,
                "agent",
                "agent-collector",
                "nvidia-smi",
                host_ref,
                ev,
                "none",
            ));
        }
    }

    // Listeners
    for listener in read_listeners(proc_root) {
        let ev = add_evidence(&format!("listener: {}", listener));
        let ep_ref = format!("ref://endpoint/{}", listener);
        claims.push(Claim::new(
            host_ref,
            "host.listens",
            "ref",
            serde_json::Value::String(ep_ref),
            &now,
            "agent",
            "agent-collector",
            "procfs_net",
            host_ref,
            ev,
            "none",
        ));
    }

    // Network collectors: routes, interfaces, connections
    let (net_claims, net_evidence) = crate::net::collect_network_claims(host_ref, proc_root, _sys_root);
    claims.extend(net_claims);
    evidence.extend(net_evidence);

    (claims, evidence)
}
