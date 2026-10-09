use std::fs;
use bokuei_agent::collector::{
    detect_container, detect_wsl, parse_python_dist_info_metadata, read_cpuinfo, read_dpkg_status,
    read_meminfo,
};
use bokuei_agent::config::Config;
use bokuei_agent::env::process_env_map;
use bokuei_agent::hash::{hash_regular_file, HashResult};

#[test]
fn test_proc_cpuinfo_parser() {
    let tmp = tempfile::tempdir().unwrap();
    let cpuinfo_path = tmp.path().join("cpuinfo");
    let content =
        "processor\t: 0\nmodel name\t: Test Virtual CPU\nflags\t\t: fpu vme de avx avx2\n";
    fs::write(&cpuinfo_path, content).unwrap();

    let (model, flags) = read_cpuinfo(tmp.path());
    assert_eq!(model, "Test Virtual CPU");
    assert!(flags.contains(&"avx2".to_string()));
    assert!(flags.contains(&"fpu".to_string()));
}

#[test]
fn test_proc_meminfo_parser() {
    let tmp = tempfile::tempdir().unwrap();
    let meminfo_path = tmp.path().join("meminfo");
    let content = "MemTotal:       16384000 kB\nMemFree:        8192000 kB\n";
    fs::write(&meminfo_path, content).unwrap();

    let total_ram = read_meminfo(tmp.path());
    assert_eq!(total_ram, 16384000);
}

#[test]
fn test_wsl_and_container_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let version_path = tmp.path().join("version");
    fs::write(&version_path, "Linux version 6.8.0-microsoft-standard-WSL2").unwrap();

    let wsl = detect_wsl(tmp.path());
    assert_eq!(wsl, Some("WSL2".to_string()));

    let cg_dir = tmp.path().join("1");
    fs::create_dir_all(&cg_dir).unwrap();
    fs::write(cg_dir.join("cgroup"), "0::/docker/123456").unwrap();
    let cont = detect_container(tmp.path());
    assert_eq!(cont, Some("docker".to_string()));
}

#[test]
fn test_python_dist_info_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let meta_path = tmp.path().join("METADATA");
    let content =
        "Metadata-Version: 2.1\nName: bokuei-test-pkg\nVersion: 1.4.2\nSummary: Test package\n";
    fs::write(&meta_path, content).unwrap();

    let res = parse_python_dist_info_metadata(&meta_path);
    assert_eq!(
        res,
        Some(("bokuei-test-pkg".to_string(), "1.4.2".to_string()))
    );
}

#[test]
fn test_dpkg_status_parser() {
    let tmp = tempfile::tempdir().unwrap();
    let dpkg_dir = tmp.path().join("var/lib/dpkg");
    fs::create_dir_all(&dpkg_dir).unwrap();
    let content = "Package: test-libc\nStatus: install ok installed\nVersion: 2.39-0ubuntu8\n\nPackage: test-ssl\nVersion: 3.0.13\n\n";
    fs::write(dpkg_dir.join("status"), content).unwrap();

    let pkgs = read_dpkg_status(tmp.path());
    assert_eq!(pkgs.len(), 2);
    assert_eq!(
        pkgs[0],
        ("test-libc".to_string(), "2.39-0ubuntu8".to_string())
    );
    assert_eq!(pkgs[1], ("test-ssl".to_string(), "3.0.13".to_string()));
}

#[test]
fn test_hash_cap_not_visible() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("large_file.dat");
    // Write 200 bytes
    fs::write(&file_path, vec![0u8; 200]).unwrap();

    // Cap at 100 bytes
    let res = hash_regular_file(&file_path.to_string_lossy(), 100);
    match res {
        HashResult::NotVisible { reason } => assert_eq!(reason, "size_cap"),
        other => panic!("expected NotVisible size_cap, got {:?}", other),
    }

    // Never hash special fs
    let res_proc = hash_regular_file("/proc/version", 1024);
    assert_eq!(res_proc, HashResult::SkippedSpecialFs);
}

#[test]
fn test_env_allowlist_and_secret_safety() {
    let input_env = vec![
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        (
            "SECRET_KEY".to_string(),
            "super_secret_token_123".to_string(),
        ),
        (
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "AKIASECRET".to_string(),
        ),
        ("LANG".to_string(), "en_US.UTF-8".to_string()),
    ];

    let records = process_env_map(input_env, false, None);

    for r in &records {
        if r.name == "PATH" {
            assert_eq!(r.value_repr, "/usr/bin:/bin");
            assert!(r.is_value_recorded);
        } else if r.name == "LANG" {
            assert_eq!(r.value_repr, "en_US.UTF-8");
            assert!(r.is_value_recorded);
        } else {
            // Secret values MUST NEVER appear
            assert_ne!(r.value_repr, "super_secret_token_123");
            assert_ne!(r.value_repr, "AKIASECRET");
            assert_eq!(r.value_repr, "[VALUE_NOT_RECORDED]");
            assert!(!r.is_value_recorded);
        }
    }
}

#[test]
fn test_env_salted_hash() {
    let input_env = vec![(
        "DATABASE_URL".to_string(),
        "postgres://user:pass@db:5432".to_string(),
    )];

    let records = process_env_map(input_env, true, Some("testsalt"));
    assert_eq!(records.len(), 1);
    assert!(records[0].value_repr.starts_with("salted_sha256:"));
    assert!(!records[0].value_repr.contains("pass"));
}

#[test]
fn test_config_exclusions() {
    let toml_str = r#"
exclusions = ["/tmp/ignored", ".git"]
size_cap_bytes = 1048576
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.is_excluded("/tmp/ignored/foo"));
    assert!(config.is_excluded("/repo/.git/HEAD"));
    assert!(!config.is_excluded("/usr/lib/libc.so"));
}

#[test]
fn test_proc_polling_fallback_never_fabricates_file_claims() {
    let tmp = tempfile::tempdir().unwrap();
    // Simulate child process in /proc
    let pid_dir = tmp.path().join("9999");
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(pid_dir.join("cmdline"), "dummy_proc\0").unwrap();
    fs::write(
        pid_dir.join("maps"),
        "7f000-7f100 r-xp 00000000 08:01 12345 /usr/lib/libtest.so.1\n",
    )
    .unwrap();

    let child = nix::unistd::Pid::from_raw(9999);
    // Directly run polling fallback on mock proc directory
    let res = bokuei_agent::tracer::run_proc_polling(child, tmp.path()).unwrap();
    assert_eq!(res.coverage_mode, "polling");
    assert!(res.ptrace_denied);
    assert_eq!(
        res.file_accesses.len(),
        0,
        "Never fabricate file claims in fallback"
    );
    assert!(res.loaded_libraries.contains("/usr/lib/libtest.so.1"));
}

#[test]
fn test_never_open_environ_check() {
    // Assert that our codebase nowhere opens /proc/*/environ or accesses "environ" files
    let tracer_src = include_str!("../src/tracer.rs");
    let collector_src = include_str!("../src/collector.rs");
    let main_src = include_str!("../src/main.rs");
    let env_src = include_str!("../src/env.rs");

    for s in [tracer_src, collector_src, main_src, env_src] {
        assert!(
            !s.contains("/environ"),
            "CRITICAL SECURITY INVARIANT: agent code must never open /proc/*/environ"
        );
        assert!(
            !s.contains(r#""environ""#),
            "CRITICAL SECURITY INVARIANT: agent code must never open /proc/*/environ"
        );
    }
}

#[test]
fn test_probe_faked_proc_and_sys_unprivileged_vs_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let proc_dir = root.join("proc");
    let sys_dir = root.join("sys");
    fs::create_dir_all(proc_dir.join("self")).unwrap();
    fs::create_dir_all(proc_dir.join("sys/kernel/yama")).unwrap();
    fs::create_dir_all(proc_dir.join("net")).unwrap();
    fs::create_dir_all(proc_dir.join("self/ns")).unwrap();
    fs::create_dir_all(sys_dir.join("class/net/eth0")).unwrap();
    fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();

    // 1. Unprivileged status: uid 1000, CapEff 0
    fs::write(
        proc_dir.join("self/status"),
        "Name:\tbokuei-agent\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n",
    ).unwrap();
    fs::write(proc_dir.join("sys/kernel/yama/ptrace_scope"), "1\n").unwrap();
    fs::write(
        proc_dir.join("self/mountinfo"),
        "113 82 0:61 / /proc rw,nosuid,nodev,noexec,noatime shared:15 - proc proc rw,hidepid=2\n",
    ).unwrap();
    fs::write(proc_dir.join("net/nf_conntrack"), "dummy conntrack\n").unwrap();
    fs::write(root.join("var/lib/dpkg/status"), "Package: curl\nVersion: 7.88.1\n\n").unwrap();
    fs::write(sys_dir.join("class/net/eth0/operstate"), "up\n").unwrap();

    // Unprivileged probe execution
    let (claims_unprivileged, _) = bokuei_agent::probe::run_host_probes(
        "ref://host/test-unpriv",
        &proc_dir,
        &sys_dir,
        root,
    );

    // Verify unprivileged results:
    // - proc_other_users is cannot (hidepid=2 and uid != 0)
    // - ptrace is can (scope 1)
    // - conntrack is can (file exists and readable)
    // - firewall is cannot (not modeled)
    // - net_ns_isolated is cannot
    let mut cannot_preds = Vec::new();
    let mut can_preds = Vec::new();
    for c in &claims_unprivileged {
        if c.predicate == "capability.cannot" {
            cannot_preds.push((c.subject.clone(), c.object.value.as_str().unwrap().to_string()));
        } else if c.predicate == "capability.can" {
            can_preds.push((c.subject.clone(), c.object.value.as_str().unwrap().to_string()));
        }
    }

    assert!(
        cannot_preds.iter().any(|(s, r)| s == "ref://capability/proc_other_users" && r.contains("hidepid_2")),
        "unprivileged with hidepid=2 must emit capability.cannot for proc_other_users"
    );
    assert!(
        cannot_preds.iter().any(|(s, r)| s == "ref://capability/firewall" && r == "firewall_not_modeled"),
        "must emit capability.cannot firewall_not_modeled"
    );
    assert!(
        cannot_preds.iter().any(|(s, _r)| s == "ref://capability/net_ns_isolated"),
        "must emit capability.cannot for isolated network namespaces"
    );

    // 2. Simulated Root status: uid 0, full capabilities (including CAP_SYS_PTRACE = bit 19)
    fs::write(
        proc_dir.join("self/status"),
        "Name:\tbokuei-agent\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n",
    ).unwrap();
    // Yama scope 2 (admin-only)
    fs::write(proc_dir.join("sys/kernel/yama/ptrace_scope"), "2\n").unwrap();

    let (claims_root, _) = bokuei_agent::probe::run_host_probes(
        "ref://host/test-root",
        &proc_dir,
        &sys_dir,
        root,
    );

    let mut root_can = Vec::new();
    for c in &claims_root {
        if c.predicate == "capability.can" {
            root_can.push((c.subject.clone(), c.object.value.as_str().unwrap().to_string()));
        }
    }

    assert!(
        root_can.iter().any(|(s, r)| s == "ref://capability/proc_other_users" && r.contains("root_bypass")),
        "root must have proc_other_users capability.can with root_bypass"
    );
    assert!(
        root_can.iter().any(|(s, _)| s == "ref://capability/ptrace"),
        "root with CAP_SYS_PTRACE under yama scope 2 must have ptrace capability.can"
    );
}

#[test]
fn test_probe_denied_reads_yield_cannot_never_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let proc_dir = root.join("proc");
    let sys_dir = root.join("sys");
    fs::create_dir_all(proc_dir.join("self")).unwrap();
    fs::create_dir_all(proc_dir.join("net")).unwrap();

    // No conntrack file, no package db, no sysfs net
    fs::write(
        proc_dir.join("self/status"),
        "Name:\tbokuei-agent\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n",
    ).unwrap();

    let (claims, _) = bokuei_agent::probe::run_host_probes(
        "ref://host/test-denied",
        &proc_dir,
        &sys_dir,
        root,
    );

    // Conntrack missing or denied must yield capability.cannot, NEVER observed_absent
    for c in &claims {
        assert_ne!(
            c.predicate, "observed_absent",
            "epistemic rule: denied reads or missing observability must never fabricate observed_absent"
        );
    }

    let conntrack_claim = claims.iter().find(|c| c.subject == "ref://capability/conntrack").unwrap();
    assert_eq!(conntrack_claim.predicate, "capability.cannot");
    assert!(conntrack_claim.object.value.as_str().unwrap().contains("not_found") || conntrack_claim.object.value.as_str().unwrap().contains("permission_denied"));
}

#[test]
fn test_network_collectors_routes_interfaces_connections() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let proc_dir = root.join("proc");
    let sys_dir = root.join("sys");
    fs::create_dir_all(proc_dir.join("net")).unwrap();
    fs::create_dir_all(sys_dir.join("class/net/eth0/statistics")).unwrap();

    // 1. Fake /proc/net/route
    fs::write(
        proc_dir.join("net/route"),
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
    ).unwrap();

    // 2. Fake /proc/net/ipv6_route
    fs::write(
        proc_dir.join("net/ipv6_route"),
        "20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n",
    ).unwrap();

    // 3. Fake /sys/class/net/eth0
    let eth0 = sys_dir.join("class/net/eth0");
    fs::write(eth0.join("operstate"), "up\n").unwrap();
    fs::write(eth0.join("mtu"), "1500\n").unwrap();
    fs::write(eth0.join("address"), "02:42:ac:11:00:02\n").unwrap();
    fs::write(eth0.join("statistics/rx_packets"), "12345\n").unwrap();

    // 4. Fake /proc/net/tcp
    fs::write(
        proc_dir.join("net/tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0\n",
    ).unwrap();

    // 5. Fake /proc/<pid>/fd/3 -> socket:[99999]
    let pid_fd = proc_dir.join("1234/fd");
    fs::create_dir_all(&pid_fd).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("socket:[99999]", pid_fd.join("3")).unwrap();

    let (claims, _) = bokuei_agent::net::collect_network_claims("ref://host/net-test", &proc_dir, &sys_dir);

    // Verify claims emitted
    assert!(claims.iter().any(|c| c.predicate == "host.route" && c.object.value.as_str().unwrap().contains("eth0:0.0.0.0/0")));
    assert!(claims.iter().any(|c| c.predicate == "host.route" && c.object.value.as_str().unwrap().contains("eth0:192.168.1.0/24")));
    assert!(claims.iter().any(|c| c.predicate == "host.interface" && c.object.value.as_str().unwrap() == "ref://interface/eth0"));
    assert!(claims.iter().any(|c| c.predicate == "interface.state" && c.object.value.as_str().unwrap() == "up"));
    assert!(claims.iter().any(|c| c.predicate == "interface.counter" && c.object.value.as_i64().unwrap() == 12345));
    assert!(claims.iter().any(|c| c.predicate == "run.connection" && c.object.value.as_str().unwrap().contains("tcp:127.0.0.1:80")));
}


