use chrono::Utc;
use nix::sys::ptrace;
use nix::unistd::{fork, ForkResult};
use std::env;
use std::fs::File;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{exit, Command};
use bokuei_agent::collector::collect_host_claims;
use bokuei_agent::config::Config;
use bokuei_agent::env::{generate_env_salt, process_env_map};
use bokuei_agent::hash::{hash_bytes, hash_regular_file, HashResult};
use bokuei_agent::tracer::{run_ptrace_trace, AccessType};
use tq_claims::{Claim, ClaimBatch, EvidenceItem};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: bokuei-agent <run|collect|probe> [options] [-- <command...>]");
        exit(1);
    }

    match args[1].as_str() {
        "run" => handle_run(&args[2..]),
        "collect" => handle_collect(&args[2..]),
        "probe" => handle_probe(&args[2..]),
        other => {
            eprintln!("Unknown command: {}", other);
            exit(1);
        }
    }
}

fn handle_run(args: &[String]) {
    let mut out_file: Option<String> = None;
    let mut record_args = false;
    let mut hash_env_values = false;
    let mut cmd_args: Vec<String> = Vec::new();
    let mut parsing_cmd = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if parsing_cmd {
            cmd_args.push(arg.clone());
            i += 1;
            continue;
        }

        if arg == "--" {
            parsing_cmd = true;
            i += 1;
            continue;
        }

        if arg == "--out" && i + 1 < args.len() {
            out_file = Some(args[i + 1].clone());
            i += 2;
            continue;
        }

        if let Some(stripped) = arg.strip_prefix("--out=") {
            out_file = Some(stripped.to_string());
            i += 1;
            continue;
        }

        if arg == "--record-args" {
            record_args = true;
            i += 1;
            continue;
        }

        if arg == "--hash-env-values" {
            hash_env_values = true;
            i += 1;
            continue;
        }

        // Positional starts command if no --
        cmd_args.push(arg.clone());
        parsing_cmd = true;
        i += 1;
    }

    if cmd_args.is_empty() {
        eprintln!("Error: no command provided to run");
        exit(1);
    }

    let config = Config::load_or_default("bokuei.toml");
    let proc_root = Path::new("/proc");

    let now_dt = Utc::now();
    let run_id = format!("run-{}", now_dt.format("%Y%m%d%H%M%S%3f"));
    let run_ref = format!("ref://run/{}", run_id);
    let host_name = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let host_ref = format!("ref://host/{}", host_name);

    let mut claims = Vec::new();
    let mut evidence = Vec::new();

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

    // 1. Process environment variables (names only, plus allowlisted values)
    let env_salt = if hash_env_values {
        Some(generate_env_salt())
    } else {
        None
    };

    let env_records = process_env_map(env::vars(), hash_env_values, env_salt.as_deref());
    for r in &env_records {
        let ev = add_evidence(&format!("env {}: {}", r.name, r.value_repr));
        claims.push(Claim::new(
            &run_ref,
            "run.env_name",
            "text",
            serde_json::Value::String(r.name.clone()),
            now_dt.to_rfc3339(),
            "agent",
            format!("agent-{}", host_name),
            "env",
            &host_ref,
            ev,
            if r.is_value_recorded {
                "none"
            } else {
                "redacted"
            },
        ));
    }

    // 2. Command argv claim (redacted unless --record-args)
    let (cmd_display, redaction_status) = if record_args {
        (cmd_args.join(" "), "none")
    } else {
        if cmd_args.len() > 1 {
            (format!("{} [REDACTED]", cmd_args[0]), "redacted")
        } else {
            (cmd_args[0].clone(), "none")
        }
    };

    let ev_cmd = add_evidence(&format!("argv0: {}", cmd_args[0]));
    claims.push(Claim::new(
        &run_ref,
        "run.command",
        "text",
        serde_json::Value::String(cmd_display),
        now_dt.to_rfc3339(),
        "agent",
        format!("agent-{}", host_name),
        "argv",
        &host_ref,
        ev_cmd,
        redaction_status,
    ));

    // 3. ran_on claim
    let ev_ran = add_evidence(&format!("run ran on {}", host_ref));
    claims.push(Claim::new(
        &run_ref,
        "run.ran_on",
        "ref",
        serde_json::Value::String(host_ref.clone()),
        now_dt.to_rfc3339(),
        "agent",
        format!("agent-{}", host_name),
        "runtime",
        &host_ref,
        ev_ran,
        "none",
    ));

    // 4. Spawn child and trace with ptrace (or fallback)
    let trace_result = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Child: request ptrace traceme, then execute command
            let _ = ptrace::traceme();
            unsafe { libc::raise(libc::SIGSTOP) };

            let cmd_path = &cmd_args[0];
            let rest_args = &cmd_args[1..];
            let mut c = Command::new(cmd_path);
            c.args(rest_args);
            let err = c.exec();
            eprintln!("Failed to exec {}: {}", cmd_path, err);
            exit(127);
        }
        Ok(ForkResult::Parent { child }) => run_ptrace_trace(child, proc_root, record_args)
            .unwrap_or_else(|e| {
                eprintln!("Tracing failed: {}", e);
                bokuei_agent::tracer::TraceResult {
                    exit_code: 1,
                    ptrace_denied: true,
                    processes: Vec::new(),
                    file_accesses: Vec::new(),
                    loaded_libraries: std::collections::HashSet::new(),
                    coverage_mode: "polling".to_string(),
                }
            }),
        Err(e) => {
            eprintln!("Fork failed: {}", e);
            exit(1);
        }
    };

    let end_dt = Utc::now();

    // 5. Coverage claims
    if trace_result.ptrace_denied {
        let ev = add_evidence("ptrace attachment failed or denied by kernel");
        claims.push(Claim::new(
            &run_ref,
            "coverage.observed",
            "text",
            serde_json::Value::String("mode=polling".to_string()),
            end_dt.to_rfc3339(),
            "agent",
            format!("agent-{}", host_name),
            "procfs",
            &host_ref,
            ev.clone(),
            "none",
        ));
        claims.push(Claim::new(
            &run_ref,
            "coverage.blocked",
            "text",
            serde_json::Value::String("file_io:ptrace_denied".to_string()),
            end_dt.to_rfc3339(),
            "agent",
            format!("agent-{}", host_name),
            "ptrace",
            &host_ref,
            ev,
            "none",
        ));
    } else {
        let ev = add_evidence("ptrace interception active for child and forks");
        claims.push(Claim::new(
            &run_ref,
            "coverage.observed",
            "text",
            serde_json::Value::String("mode=ptrace".to_string()),
            end_dt.to_rfc3339(),
            "agent",
            format!("agent-{}", host_name),
            "ptrace",
            &host_ref,
            ev,
            "none",
        ));
    }

    // 6. Process tree claims
    for p in &trace_result.processes {
        let proc_ref = format!(
            "ref://process/{}/{}-{}",
            host_name,
            now_dt.format("%s"),
            &p.exe_sha256[..p.exe_sha256.len().min(12)]
        );
        let ev = add_evidence(&format!("process pid {} exe {}", p.pid, p.exe));
        claims.push(Claim::new(
            &proc_ref,
            "artifact.sha256",
            "text",
            serde_json::Value::String(p.exe_sha256.clone()),
            now_dt.to_rfc3339(),
            "agent",
            format!("agent-{}", host_name),
            "procfs",
            &host_ref,
            ev,
            "none",
        ));
    }

    // 7. Loaded libraries claims (from /proc/<pid>/maps)
    let mut hashed_artifacts = std::collections::HashSet::new();
    for lib in &trace_result.loaded_libraries {
        if config.is_excluded(lib) {
            let ev = add_evidence(&format!("excluded lib: {}", lib));
            claims.push(Claim::new(
                &run_ref,
                "coverage.blocked",
                "text",
                serde_json::Value::String(format!("excluded_by_config:{}", lib)),
                end_dt.to_rfc3339(),
                "agent",
                format!("agent-{}", host_name),
                "config",
                &host_ref,
                ev,
                "none",
            ));
            continue;
        }

        let art_ref = format!("ref://artifact/{}", lib.trim_start_matches('/'));
        let ev = add_evidence(&format!("maps loaded: {}", lib));
        claims.push(Claim::new(
            &run_ref,
            "run.loaded",
            "ref",
            serde_json::Value::String(art_ref.clone()),
            end_dt.to_rfc3339(),
            "agent",
            format!("agent-{}", host_name),
            "proc_maps",
            &host_ref,
            ev.clone(),
            "none",
        ));

        // Hash loaded library if regular file up to cap
        match hash_regular_file(lib, config.size_cap_bytes) {
            HashResult::Hash(h) => {
                hashed_artifacts.insert(art_ref.clone());
                claims.push(Claim::new(
                    &art_ref,
                    "artifact.sha256",
                    "text",
                    serde_json::Value::String(h),
                    end_dt.to_rfc3339(),
                    "agent",
                    format!("agent-{}", host_name),
                    "file_hash",
                    &host_ref,
                    ev,
                    "none",
                ));
            }
            HashResult::NotVisible { reason } => {
                claims.push(Claim::new(
                    &art_ref,
                    "coverage.blocked",
                    "text",
                    serde_json::Value::String(format!("content_hash_not_visible:{}", reason)),
                    end_dt.to_rfc3339(),
                    "agent",
                    format!("agent-{}", host_name),
                    "hash_cap",
                    &host_ref,
                    ev,
                    "none",
                ));
            }
            HashResult::SkippedSpecialFs => {}
        }
    }

    // 8. File I/O claims (from ptrace open/openat/openat2/execve)
    for fa in &trace_result.file_accesses {
        if config.is_excluded(&fa.path) {
            let ev = add_evidence(&format!("excluded path: {}", fa.path));
            claims.push(Claim::new(
                &run_ref,
                "coverage.blocked",
                "text",
                serde_json::Value::String(format!("excluded_by_config:{}", fa.path)),
                end_dt.to_rfc3339(),
                "agent",
                format!("agent-{}", host_name),
                "config",
                &host_ref,
                ev,
                "none",
            ));
            continue;
        }

        let art_ref = format!("ref://artifact/{}", fa.path.trim_start_matches('/'));
        let ev = add_evidence(&format!("accessed {} by pid {}", fa.path, fa.pid));

        if fa.access == AccessType::Read || fa.access == AccessType::ReadWrite {
            claims.push(Claim::new(
                &run_ref,
                "run.read",
                "ref",
                serde_json::Value::String(art_ref.clone()),
                end_dt.to_rfc3339(),
                "agent",
                format!("agent-{}", host_name),
                "ptrace",
                &host_ref,
                ev.clone(),
                "none",
            ));
        }

        if fa.access == AccessType::Write || fa.access == AccessType::ReadWrite {
            claims.push(Claim::new(
                &run_ref,
                "run.wrote",
                "ref",
                serde_json::Value::String(art_ref.clone()),
                end_dt.to_rfc3339(),
                "agent",
                format!("agent-{}", host_name),
                "ptrace",
                &host_ref,
                ev.clone(),
                "none",
            ));
        }

        // Hash regular file content up to size cap
        if !hashed_artifacts.contains(&art_ref) {
            match hash_regular_file(&fa.path, config.size_cap_bytes) {
                HashResult::Hash(h) => {
                    hashed_artifacts.insert(art_ref.clone());
                    claims.push(Claim::new(
                        &art_ref,
                        "artifact.sha256",
                        "text",
                        serde_json::Value::String(h),
                        end_dt.to_rfc3339(),
                        "agent",
                        format!("agent-{}", host_name),
                        "file_hash",
                        &host_ref,
                        ev,
                        "none",
                    ));
                }
                HashResult::NotVisible { reason } => {
                    hashed_artifacts.insert(art_ref.clone());
                    claims.push(Claim::new(
                        &art_ref,
                        "coverage.blocked",
                        "text",
                        serde_json::Value::String(format!("content_hash_not_visible:{}", reason)),
                        end_dt.to_rfc3339(),
                        "agent",
                        format!("agent-{}", host_name),
                        "hash_cap",
                        &host_ref,
                        ev,
                        "none",
                    ));
                }
                HashResult::SkippedSpecialFs => {}
            }
        }
    }

    // 9. Exit status claim
    let ev_exit = add_evidence(&format!("exit status: {}", trace_result.exit_code));
    claims.push(Claim::new(
        &run_ref,
        "run.exit_status",
        "int",
        serde_json::Value::Number(trace_result.exit_code.into()),
        end_dt.to_rfc3339(),
        "agent",
        format!("agent-{}", host_name),
        "waitpid",
        &host_ref,
        ev_exit,
        "none",
    ));

    // Emit batch as NDJSON / JSON batch object
    let batch = ClaimBatch {
        batch_id: format!("batch-{}", run_id),
        run_ref: Some(run_ref),
        claims,
        evidence,
        env_salt,
    };

    let batch_json = serde_json::to_string(&batch).unwrap();

    if let Some(path) = out_file {
        if let Ok(mut f) = File::create(&path) {
            let _ = writeln!(f, "{}", batch_json);
        }
    } else {
        println!("{}", batch_json);
    }

    exit(trace_result.exit_code);
}

fn handle_collect(args: &[String]) {
    let mut explain = false;
    let mut out_file: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--explain" {
            explain = true;
        } else if arg == "--out" && i + 1 < args.len() {
            out_file = Some(args[i + 1].clone());
            i += 1;
        } else if let Some(stripped) = arg.strip_prefix("--out=") {
            out_file = Some(stripped.to_string());
        }
        i += 1;
    }

    let host_name = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let host_ref = format!("ref://host/{}", host_name);
    let proc_root = Path::new("/proc");
    let sys_root = Path::new("/");

    let (claims, evidence) = collect_host_claims(&host_ref, proc_root, sys_root);

    let batch = ClaimBatch {
        batch_id: format!("batch-collect-{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
        run_ref: None,
        claims,
        evidence,
        env_salt: None,
    };

    let batch_json = serde_json::to_string(&batch).unwrap();

    if let Some(path) = out_file {
        if let Ok(mut f) = File::create(&path) {
            let _ = writeln!(f, "{}", batch_json);
        }
    } else {
        println!("{}", batch_json);
    }

    if explain {
        eprintln!(
            "Collection complete: {} claims generated for {}",
            batch.claims.len(),
            host_ref
        );
    }
}

fn handle_probe(args: &[String]) {
    let mut explain = false;
    let mut out_file: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--explain" {
            explain = true;
        } else if arg == "--out" && i + 1 < args.len() {
            out_file = Some(args[i + 1].clone());
            i += 1;
        } else if let Some(stripped) = arg.strip_prefix("--out=") {
            out_file = Some(stripped.to_string());
        }
        i += 1;
    }

    let host_name = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let host_ref = format!("ref://host/{}", host_name);
    let proc_root = Path::new("/proc");
    let sys_root = Path::new("/sys");
    let root_dir = Path::new("/");

    let (claims, evidence) = bokuei_agent::probe::run_host_probes(
        &host_ref,
        proc_root,
        sys_root,
        root_dir,
    );

    let batch = ClaimBatch {
        batch_id: format!("batch-probe-{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
        run_ref: None,
        claims,
        evidence,
        env_salt: None,
    };

    let batch_json = serde_json::to_string(&batch).unwrap();

    if let Some(path) = out_file {
        if let Ok(mut f) = File::create(&path) {
            let _ = writeln!(f, "{}", batch_json);
        }
    } else {
        println!("{}", batch_json);
    }

    if explain {
        eprintln!(
            "Probe complete: {} capability/interface claims generated for {}",
            batch.claims.len(),
            host_ref
        );
    }
}
