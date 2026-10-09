use crate::hash::hash_bytes;
use chrono::Utc;
use std::fs;
use std::path::Path;
use tq_claims::{Claim, EvidenceItem};

/// Capability probe result
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub name: &'static str,
    pub can: bool,
    pub reason: String,
    pub method: String,
    pub raw_evidence: String,
}

/// Linux capability bit definitions (from linux/capability.h)
pub const CAP_SYS_PTRACE: u64 = 1 << 19;
pub const CAP_DAC_OVERRIDE: u64 = 1 << 1;
pub const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
pub const CAP_NET_ADMIN: u64 = 1 << 12;

/// Identity and effective capability probe from /proc/self/status
pub fn probe_effective_caps(proc_root: &Path) -> (u32, u64, String) {
    let default_uid = unsafe { libc::getuid() };
    let status_path = proc_root.join("self/status");
    let (raw_status, cap_eff, uid) = if let Ok(content) = fs::read_to_string(&status_path) {
        let mut c_eff = 0u64;
        let mut u_id = default_uid;
        for line in content.lines() {
            if let Some(stripped) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = stripped.split_whitespace().collect();
                if let Some(first) = parts.first() {
                    if let Ok(u) = first.parse::<u32>() {
                        u_id = u;
                    }
                }
            } else if let Some(stripped) = line.strip_prefix("CapEff:") {
                let trimmed = stripped.trim();
                if let Ok(val) = u64::from_str_radix(trimmed, 16) {
                    c_eff = val;
                }
            }
        }
        (content, c_eff, u_id)
    } else {
        (format!("uid={}", default_uid), 0u64, default_uid)
    };

    (uid, cap_eff, raw_status)
}

/// can_ptrace_children: checks Yama ptrace_scope and CAP_SYS_PTRACE
pub fn probe_ptrace(proc_root: &Path, cap_eff: u64) -> ProbeResult {
    let yama_path = proc_root.join("sys/kernel/yama/ptrace_scope");
    let has_cap = (cap_eff & CAP_SYS_PTRACE) != 0;

    let (scope_val, raw_ev) = match fs::read_to_string(&yama_path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            let raw = format!("yama/ptrace_scope={}; cap_sys_ptrace={}", trimmed, has_cap);
            (trimmed.parse::<i32>().unwrap_or(0), raw)
        }
        Err(e) => (0, format!("yama/ptrace_scope not found ({}); cap_sys_ptrace={}", e, has_cap)),
    };

    // In Linux Yama:
    // 0: classic ptrace permissions
    // 1: restricted ptrace (only parent processes or CAP_SYS_PTRACE)
    // 2: admin-only ptrace (requires CAP_SYS_PTRACE)
    // 3: no attach at all (even root cannot attach)
    let can = match scope_val {
        0 => true,
        1 => true, // agent tracing child spawned by itself is allowed under scope 1
        2 => has_cap,
        3 => false,
        _ => false,
    };

    let reason = if can {
        format!("supported:yama_scope_{}", scope_val)
    } else if scope_val == 3 {
        "blocked:yama_scope_3_locked".to_string()
    } else {
        "denied:requires_cap_sys_ptrace".to_string()
    };

    ProbeResult {
        name: "ptrace",
        can,
        reason,
        method: "procfs_yama_and_capeff".to_string(),
        raw_evidence: raw_ev,
    }
}

/// can_read_proc_other_users: inspects hidepid mount option from /proc/self/mountinfo
pub fn probe_proc_other_users(proc_root: &Path, uid: u32) -> ProbeResult {
    let mountinfo_path = proc_root.join("self/mountinfo");
    let (hidepid, raw_ev) = match fs::read_to_string(&mountinfo_path) {
        Ok(s) => {
            let mut hp = 0;
            for line in s.lines() {
                // Look for proc mount entry: e.g. "113 82 0:61 / /proc rw,... - proc proc rw,hidepid=2"
                if line.contains(" /proc ") || line.contains(" - proc proc ") {
                    if line.contains("hidepid=2") || line.contains("hidepid=invisible") {
                        hp = 2;
                    } else if line.contains("hidepid=1") {
                        hp = 1;
                    }
                }
            }
            (hp, format!("mountinfo hidepid={}", hp))
        }
        Err(e) => (0, format!("mountinfo read failed: {}", e)),
    };

    let can = if uid == 0 {
        true
    } else {
        hidepid == 0
    };

    let reason = if can {
        if uid == 0 {
            "supported:root_bypass".to_string()
        } else {
            "supported:hidepid_0".to_string()
        }
    } else {
        format!("denied:hidepid_{}", hidepid)
    };

    ProbeResult {
        name: "proc_other_users",
        can,
        reason,
        method: "procfs_mountinfo_hidepid".to_string(),
        raw_evidence: raw_ev,
    }
}

/// can_read_conntrack: try opening /proc/net/nf_conntrack read-only
pub fn probe_conntrack(proc_root: &Path) -> ProbeResult {
    let conntrack_path = proc_root.join("net/nf_conntrack");
    match fs::File::open(&conntrack_path) {
        Ok(_) => ProbeResult {
            name: "conntrack",
            can: true,
            reason: "supported".to_string(),
            method: "open_proc_net_nf_conntrack".to_string(),
            raw_evidence: "open_proc_net_nf_conntrack: SUCCESS".to_string(),
        },
        Err(e) => {
            let err_code = match e.raw_os_error() {
                Some(13) => "permission_denied:eacces",
                Some(2) => "not_found:enoent_module_not_loaded",
                _ => "denied_or_missing",
            };
            ProbeResult {
                name: "conntrack",
                can: false,
                reason: format!("{}:{}", err_code, e),
                method: "open_proc_net_nf_conntrack".to_string(),
                raw_evidence: format!("open_proc_net_nf_conntrack: FAILED ({})", e),
            }
        }
    }
}

/// can_read_sysfs_net: probe /sys/class/net directory
pub fn probe_sysfs_net(sys_root: &Path) -> ProbeResult {
    let net_path = sys_root.join("class/net");
    match fs::read_dir(&net_path) {
        Ok(entries) => {
            let mut ifaces = Vec::new();
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    ifaces.push(name);
                }
            }
            ifaces.sort();
            ProbeResult {
                name: "sysfs_net",
                can: true,
                reason: format!("supported:interfaces={}", ifaces.join(",")),
                method: "read_sys_class_net".to_string(),
                raw_evidence: format!("sysfs_net: {:?}", ifaces),
            }
        }
        Err(e) => ProbeResult {
            name: "sysfs_net",
            can: false,
            reason: format!("denied:{}", e),
            method: "read_sys_class_net".to_string(),
            raw_evidence: format!("read_sys_class_net: FAILED ({})", e),
        },
    }
}

/// can_read_dpkg_or_rpm: probe package database availability
pub fn probe_package_db(root_dir: &Path) -> ProbeResult {
    let dpkg_status = root_dir.join("var/lib/dpkg/status");
    let rpm_db = root_dir.join("var/lib/rpm");

    if dpkg_status.exists() {
        match fs::File::open(&dpkg_status) {
            Ok(_) => ProbeResult {
                name: "package_db",
                can: true,
                reason: "supported:dpkg".to_string(),
                method: "open_var_lib_dpkg_status".to_string(),
                raw_evidence: "open dpkg status: SUCCESS".to_string(),
            },
            Err(e) => ProbeResult {
                name: "package_db",
                can: false,
                reason: format!("permission_denied:dpkg_{}", e),
                method: "open_var_lib_dpkg_status".to_string(),
                raw_evidence: format!("open dpkg status: FAILED ({})", e),
            },
        }
    } else if rpm_db.exists() {
        match fs::read_dir(&rpm_db) {
            Ok(_) => ProbeResult {
                name: "package_db",
                can: true,
                reason: "supported:rpm".to_string(),
                method: "read_var_lib_rpm".to_string(),
                raw_evidence: "read rpm db: SUCCESS".to_string(),
            },
            Err(e) => ProbeResult {
                name: "package_db",
                can: false,
                reason: format!("permission_denied:rpm_{}", e),
                method: "read_var_lib_rpm".to_string(),
                raw_evidence: format!("read rpm db: FAILED ({})", e),
            },
        }
    } else {
        ProbeResult {
            name: "package_db",
            can: false,
            reason: "absent:no_dpkg_or_rpm_database".to_string(),
            method: "check_dpkg_and_rpm_paths".to_string(),
            raw_evidence: "neither /var/lib/dpkg/status nor /var/lib/rpm present".to_string(),
        }
    }
}

/// probe_network_namespaces: records that only agent's own net ns is visible, other namespaces are NOT VISIBLE
pub fn probe_net_namespaces(proc_root: &Path) -> (ProbeResult, ProbeResult) {
    let net_ns_path = proc_root.join("self/ns/net");
    let own_ns = match fs::read_link(&net_ns_path) {
        Ok(target) => target.to_string_lossy().to_string(),
        Err(_) => "net:[unknown]".to_string(),
    };

    // 1. Can see own net namespace
    let can_own = ProbeResult {
        name: "net_ns_own",
        can: true,
        reason: format!("supported:{}", own_ns),
        method: "readlink_proc_self_ns_net".to_string(),
        raw_evidence: format!("own net namespace: {}", own_ns),
    };

    // 2. Cannot see other network namespaces (explicit epistemic boundary)
    let cannot_other = ProbeResult {
        name: "net_ns_isolated",
        can: false,
        reason: "other_network_namespaces_not_visible".to_string(),
        method: "probe_isolated_net_namespaces".to_string(),
        raw_evidence: format!("agent confined to single netns {}", own_ns),
    };

    (can_own, cannot_other)
}

/// probe_firewall: explicitly records firewall rules as not modeled
pub fn probe_firewall() -> ProbeResult {
    ProbeResult {
        name: "firewall",
        can: false,
        reason: "firewall_not_modeled".to_string(),
        method: "probe_packet_filter_subsystem".to_string(),
        raw_evidence: "iptables/nftables packet filter inspection not modeled".to_string(),
    }
}

/// Runs full probe suite against given roots and returns claims and evidence items
pub fn run_host_probes(
    host_ref: &str,
    proc_root: &Path,
    sys_root: &Path,
    root_dir: &Path,
) -> (Vec<Claim>, Vec<EvidenceItem>) {
    let mut claims = Vec::new();
    let mut evidence = Vec::new();
    let now = Utc::now().to_rfc3339();

    let mut add_ev = |raw: &str| -> String {
        let h = hash_bytes(raw.as_bytes());
        evidence.push(EvidenceItem {
            hash: h.clone(),
            payload_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                raw.as_bytes(),
            ),
        });
        h
    };

    let (uid, cap_eff, raw_status) = probe_effective_caps(proc_root);
    let ev_status = add_ev(&raw_status);

    // Record agent identity & effective capabilities
    claims.push(Claim::new(
        host_ref,
        "capability.can",
        "text",
        serde_json::Value::String(format!("uid:{}", uid)),
        &now,
        "agent",
        "agent-probe",
        "procfs_status_uid",
        host_ref,
        &ev_status,
        "none",
    ));
    claims.push(Claim::new(
        host_ref,
        "capability.can",
        "text",
        serde_json::Value::String(format!("capeff:0x{:x}", cap_eff)),
        &now,
        "agent",
        "agent-probe",
        "procfs_status_capeff",
        host_ref,
        &ev_status,
        "none",
    ));

    let mut probes = vec![
        probe_ptrace(proc_root, cap_eff),
        probe_proc_other_users(proc_root, uid),
        probe_conntrack(proc_root),
        probe_sysfs_net(sys_root),
        probe_package_db(root_dir),
    ];

    let (ns_own, ns_other) = probe_net_namespaces(proc_root);
    probes.push(ns_own);
    probes.push(ns_other);
    probes.push(probe_firewall());

    for p in probes {
        let ev_hash = add_ev(&p.raw_evidence);
        let pred = if p.can {
            "capability.can"
        } else {
            "capability.cannot"
        };
        let cap_subj = format!("ref://capability/{}", p.name);
        claims.push(Claim::new(
            &cap_subj,
            pred,
            "text",
            serde_json::Value::String(p.reason),
            &now,
            "agent",
            "agent-probe",
            &p.method,
            host_ref,
            &ev_hash,
            "none",
        ));
    }

    // Also collect network interfaces via sysfs if present
    let net_path = sys_root.join("class/net");
    if let Ok(entries) = fs::read_dir(&net_path) {
        for entry in entries.flatten() {
            if let Ok(iface_name) = entry.file_name().into_string() {
                let iface_ref = format!("ref://interface/{}", iface_name);
                let ev_iface = add_ev(&format!("interface {}", iface_name));
                claims.push(Claim::new(
                    host_ref,
                    "host.interface",
                    "ref",
                    serde_json::Value::String(iface_ref.clone()),
                    &now,
                    "agent",
                    "agent-probe",
                    "sysfs_net_interface",
                    host_ref,
                    &ev_iface,
                    "none",
                ));

                // Read operstate if available
                let operstate_path = entry.path().join("operstate");
                let state = match fs::read_to_string(&operstate_path) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => "unknown".to_string(),
                };
                let ev_state = add_ev(&format!("operstate of {}: {}", iface_name, state));
                claims.push(Claim::new(
                    &iface_ref,
                    "interface.state",
                    "text",
                    serde_json::Value::String(state),
                    &now,
                    "agent",
                    "agent-probe",
                    "sysfs_net_operstate",
                    host_ref,
                    &ev_state,
                    "none",
                ));
            }
        }
    }

    (claims, evidence)
}
