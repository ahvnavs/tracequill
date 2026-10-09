use crate::hash::hash_bytes;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use tq_claims::{Claim, EvidenceItem};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub iface: String,
    pub destination_cidr: String,
    pub gateway: String,
    pub metric: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceState {
    pub name: String,
    pub operstate: String,
    pub carrier: Option<String>,
    pub speed: Option<i64>,
    pub duplex: Option<String>,
    pub mtu: Option<i64>,
    pub address: Option<String>,
    pub carrier_changes: Option<i64>,
    pub counters: HashMap<String, i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEntry {
    pub proto: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub inode: u64,
    pub pid: Option<i32>,
}

pub fn parse_ipv4_hex_addr(hex_str: &str) -> Option<Ipv4Addr> {
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    let bytes = val.to_ne_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

pub fn parse_ipv6_hex_addr(hex_str: &str) -> Option<Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut words = [0u32; 4];
    for i in 0..4 {
        words[i] = u32::from_str_radix(&hex_str[i * 8..(i + 1) * 8], 16).ok()?;
    }
    let b0 = words[0].to_ne_bytes();
    let b1 = words[1].to_ne_bytes();
    let b2 = words[2].to_ne_bytes();
    let b3 = words[3].to_ne_bytes();
    Some(Ipv6Addr::new(
        u16::from_be_bytes([b0[0], b0[1]]),
        u16::from_be_bytes([b0[2], b0[3]]),
        u16::from_be_bytes([b1[0], b1[1]]),
        u16::from_be_bytes([b1[2], b1[3]]),
        u16::from_be_bytes([b2[0], b2[1]]),
        u16::from_be_bytes([b2[2], b2[3]]),
        u16::from_be_bytes([b3[0], b3[1]]),
        u16::from_be_bytes([b3[2], b3[3]]),
    ))
}

pub fn parse_proc_net_route(proc_root: &Path) -> Result<Vec<RouteEntry>, String> {
    let path = proc_root.join("net").join("route");
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("read_error:{}:{}", path.display(), e))?;

    let mut routes = Vec::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        let iface = parts[0].to_string();
        let dest_ip = parse_ipv4_hex_addr(parts[1]).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let gw_ip = parse_ipv4_hex_addr(parts[2]).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let mask_val = u32::from_str_radix(parts[7], 16).unwrap_or(0);
        let prefix_len = mask_val.to_be().count_ones();
        let metric = parts[6].parse::<u32>().unwrap_or(0);

        routes.push(RouteEntry {
            iface,
            destination_cidr: format!("{}/{}", dest_ip, prefix_len),
            gateway: gw_ip.to_string(),
            metric,
        });
    }
    Ok(routes)
}

pub fn parse_proc_net_ipv6_route(proc_root: &Path) -> Result<Vec<RouteEntry>, String> {
    let path = proc_root.join("net").join("ipv6_route");
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("read_error:{}:{}", path.display(), e))?;

    let mut routes = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let dest_hex = parts[0];
        let prefix_len = u32::from_str_radix(parts[1], 16).unwrap_or(0);
        let gw_hex = parts[4];
        let metric = u32::from_str_radix(parts[5], 16).unwrap_or(0);
        let iface = parts[9].to_string();

        let dest_ip = parse_ipv6_hex_addr(dest_hex).unwrap_or(Ipv6Addr::UNSPECIFIED);
        let gw_ip = parse_ipv6_hex_addr(gw_hex).unwrap_or(Ipv6Addr::UNSPECIFIED);

        routes.push(RouteEntry {
            iface,
            destination_cidr: format!("{}/{}", dest_ip, prefix_len),
            gateway: gw_ip.to_string(),
            metric,
        });
    }
    Ok(routes)
}

pub fn parse_interfaces(sys_root: &Path) -> Result<Vec<InterfaceState>, String> {
    let net_dir = sys_root.join("class").join("net");
    let entries = fs::read_dir(&net_dir)
        .map_err(|e| format!("read_error:{}:{}", net_dir.display(), e))?;

    let mut ifaces = Vec::new();
    for entry in entries.flatten() {
        let iface_path = entry.path();
        if !iface_path.is_dir() {
            continue;
        }
        let iface_name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let operstate = fs::read_to_string(iface_path.join("operstate"))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        let carrier = fs::read_to_string(iface_path.join("carrier"))
            .ok()
            .map(|s| s.trim().to_string());

        let speed = fs::read_to_string(iface_path.join("speed"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok());

        let duplex = fs::read_to_string(iface_path.join("duplex"))
            .ok()
            .map(|s| s.trim().to_string());

        let mtu = fs::read_to_string(iface_path.join("mtu"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok());

        let address = fs::read_to_string(iface_path.join("address"))
            .ok()
            .map(|s| s.trim().to_string());

        let carrier_changes = fs::read_to_string(iface_path.join("carrier_changes"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok());

        let mut counters = HashMap::new();
        let stats_dir = iface_path.join("statistics");
        if let Ok(stat_entries) = fs::read_dir(&stats_dir) {
            for se in stat_entries.flatten() {
                if let Ok(name) = se.file_name().into_string() {
                    if let Ok(content) = fs::read_to_string(se.path()) {
                        if let Ok(val) = content.trim().parse::<i64>() {
                            counters.insert(name, val);
                        }
                    }
                }
            }
        }

        ifaces.push(InterfaceState {
            name: iface_name,
            operstate,
            carrier,
            speed,
            duplex,
            mtu,
            address,
            carrier_changes,
            counters,
        });
    }

    ifaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ifaces)
}

pub fn build_socket_inode_map(proc_root: &Path) -> (HashMap<u64, i32>, bool) {
    let mut map = HashMap::new();
    let mut readable = false;

    let entries = match fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(_) => return (map, false),
    };

    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let pid: i32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");
        if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
            readable = true;
            for fe in fd_entries.flatten() {
                if let Ok(target) = fs::read_link(fe.path()) {
                    let target_str = target.to_string_lossy();
                    if let Some(inode_str) = target_str.strip_prefix("socket:[") {
                        if let Some(end) = inode_str.strip_suffix(']') {
                            if let Ok(inode) = end.parse::<u64>() {
                                map.insert(inode, pid);
                            }
                        }
                    }
                }
            }
        }
    }

    (map, readable)
}

fn parse_hex_endpoint(raw: &str, is_v6: bool) -> String {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 2 {
        return raw.to_string();
    }
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    if is_v6 {
        let ip = parse_ipv6_hex_addr(parts[0]).unwrap_or(Ipv6Addr::UNSPECIFIED);
        format!("[{}]:{}", ip, port)
    } else {
        let ip = parse_ipv4_hex_addr(parts[0]).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        format!("{}:{}", ip, port)
    }
}

pub fn parse_socket_file(
    proc_root: &Path,
    proto: &str,
    filename: &str,
    is_v6: bool,
    inode_map: &HashMap<u64, i32>,
) -> Result<Vec<ConnectionEntry>, String> {
    let path = proc_root.join("net").join(filename);
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("read_error:{}:{}", path.display(), e))?;

    let mut conns = Vec::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local_addr = parse_hex_endpoint(parts[1], is_v6);
        let remote_addr = parse_hex_endpoint(parts[2], is_v6);
        let state_hex = parts[3];
        let inode: u64 = parts[9].parse().unwrap_or(0);
        let pid = inode_map.get(&inode).copied();

        let state = match state_hex {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => state_hex,
        }
        .to_string();

        conns.push(ConnectionEntry {
            proto: proto.to_string(),
            local_addr,
            remote_addr,
            state,
            inode,
            pid,
        });
    }

    Ok(conns)
}

pub fn collect_network_claims(
    host_ref: &str,
    proc_root: &Path,
    sys_root: &Path,
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

    // 1. Routes (IPv4 & IPv6)
    match parse_proc_net_route(proc_root) {
        Ok(routes) => {
            for r in routes {
                let route_id = format!("{}:{}", r.iface, r.destination_cidr);
                let route_ref = format!("ref://route/{}", route_id);
                let ev = add_evidence(&format!("route4 {} via {} dev {} metric {}", r.destination_cidr, r.gateway, r.iface, r.metric));
                claims.push(Claim::new(
                    host_ref,
                    "host.route",
                    "ref",
                    serde_json::Value::String(route_ref.clone()),
                    &now,
                    "agent",
                    "bokuei-agent",
                    "read:/proc/net/route",
                    host_ref,
                    ev.clone(),
                    "none",
                ));
            }
        }
        Err(err) => {
            let ev = add_evidence(&err);
            claims.push(Claim::new(
                "ref://capability/route_v4",
                "capability.cannot",
                "text",
                serde_json::Value::String(err),
                &now,
                "agent",
                "bokuei-agent",
                "read:/proc/net/route",
                host_ref,
                ev,
                "none",
            ));
        }
    }

    match parse_proc_net_ipv6_route(proc_root) {
        Ok(routes) => {
            for r in routes {
                let route_id = format!("{}:{}", r.iface, r.destination_cidr);
                let route_ref = format!("ref://route/{}", route_id);
                let ev = add_evidence(&format!("route6 {} via {} dev {} metric {}", r.destination_cidr, r.gateway, r.iface, r.metric));
                claims.push(Claim::new(
                    host_ref,
                    "host.route",
                    "ref",
                    serde_json::Value::String(route_ref.clone()),
                    &now,
                    "agent",
                    "bokuei-agent",
                    "read:/proc/net/ipv6_route",
                    host_ref,
                    ev,
                    "none",
                ));
            }
        }
        Err(err) => {
            let ev = add_evidence(&err);
            claims.push(Claim::new(
                "ref://capability/route_v6",
                "capability.cannot",
                "text",
                serde_json::Value::String(err),
                &now,
                "agent",
                "bokuei-agent",
                "read:/proc/net/ipv6_route",
                host_ref,
                ev,
                "none",
            ));
        }
    }

    // 2. Interfaces & State & Counters
    match parse_interfaces(sys_root) {
        Ok(ifaces) => {
            for iface in ifaces {
                let iface_ref = format!("ref://interface/{}", iface.name);
                let ev_iface = add_evidence(&format!("interface {}", iface.name));
                claims.push(Claim::new(
                    host_ref,
                    "host.interface",
                    "ref",
                    serde_json::Value::String(iface_ref.clone()),
                    &now,
                    "agent",
                    "bokuei-agent",
                    "read:/sys/class/net",
                    host_ref,
                    ev_iface,
                    "none",
                ));

                let ev_state = add_evidence(&format!("operstate {}", iface.operstate));
                claims.push(Claim::new(
                    &iface_ref,
                    "interface.state",
                    "text",
                    serde_json::Value::String(iface.operstate.clone()),
                    &now,
                    "agent",
                    "bokuei-agent",
                    "read:/sys/class/net/operstate",
                    host_ref,
                    ev_state,
                    "none",
                ));

                for (cnt_name, cnt_val) in iface.counters {
                    let ev_cnt = add_evidence(&format!("{}: {}", cnt_name, cnt_val));
                    claims.push(Claim::new(
                        &iface_ref,
                        "interface.counter",
                        "int",
                        serde_json::Value::Number(serde_json::Number::from(cnt_val)),
                        &now,
                        "agent",
                        "bokuei-agent",
                        format!("read:/sys/class/net/statistics/{}", cnt_name),
                        host_ref,
                        ev_cnt,
                        "none",
                    ));
                }
            }
        }
        Err(err) => {
            let ev = add_evidence(&err);
            claims.push(Claim::new(
                "ref://capability/sysfs_net",
                "capability.cannot",
                "text",
                serde_json::Value::String(err),
                &now,
                "agent",
                "bokuei-agent",
                "read:/sys/class/net",
                host_ref,
                ev,
                "none",
            ));
        }
    }

    // 3. Connections & Inode Mapping
    let (inode_map, proc_fd_readable) = build_socket_inode_map(proc_root);
    if !proc_fd_readable {
        let ev = add_evidence("socket owner pid not visible: /proc/<pid>/fd unreadable or permission denied");
        claims.push(Claim::new(
            "ref://capability/proc_fd_socket_owner",
            "capability.cannot",
            "text",
            serde_json::Value::String("not_visible:proc_fd_denied".to_string()),
            &now,
            "agent",
            "bokuei-agent",
            "read:/proc/<pid>/fd",
            host_ref,
            ev,
            "none",
        ));
    }

    let socket_files = [
        ("tcp", "tcp", false),
        ("tcp6", "tcp6", true),
        ("udp", "udp", false),
        ("udp6", "udp6", true),
    ];

    for (proto, fname, is_v6) in &socket_files {
        match parse_socket_file(proc_root, proto, fname, *is_v6, &inode_map) {
            Ok(conns) => {
                for c in conns {
                    let conn_ref = if c.remote_addr.is_empty() || c.remote_addr == "0.0.0.0:0" || c.remote_addr == "[::]:0" {
                        format!("ref://endpoint/{}:{}", c.proto, c.local_addr)
                    } else {
                        format!("ref://endpoint/{}:{}->{}", c.proto, c.local_addr, c.remote_addr)
                    };
                    let ev = add_evidence(&format!("conn {} local {} remote {} state {} inode {} pid {:?}", c.proto, c.local_addr, c.remote_addr, c.state, c.inode, c.pid));
                    claims.push(Claim::new(
                        host_ref,
                        "run.connection",
                        "ref",
                        serde_json::Value::String(conn_ref.clone()),
                        &now,
                        "agent",
                        "bokuei-agent",
                        format!("read:/proc/net/{}", fname),
                        host_ref,
                        ev,
                        "none",
                    ));
                }
            }
            Err(err) => {
                let ev = add_evidence(&err);
                claims.push(Claim::new(
                    format!("ref://capability/net_{}", proto),
                    "capability.cannot",
                    "text",
                    serde_json::Value::String(err),
                    &now,
                    "agent",
                    "bokuei-agent",
                    format!("read:/proc/net/{}", fname),
                    host_ref,
                    ev,
                    "none",
                ));
            }
        }
    }

    (claims, evidence)
}
