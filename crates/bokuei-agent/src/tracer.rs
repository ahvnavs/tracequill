use crate::hash::{hash_regular_file, HashResult};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessType {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileAccess {
    pub path: String,
    pub access: AccessType,
    pub pid: i32,
}

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: i32,
    pub ppid: i32,
    pub exe: String,
    pub exe_sha256: String,
    pub cwd: String,
    pub maps_loaded: HashSet<String>,
}

pub struct TraceResult {
    pub exit_code: i32,
    pub ptrace_denied: bool,
    pub processes: Vec<ProcessNode>,
    pub file_accesses: Vec<FileAccess>,
    pub loaded_libraries: HashSet<String>,
    pub coverage_mode: String, // "ptrace" or "polling"
}

/// Reads null-terminated string or bytes from a traced process address space.
pub fn read_process_string(pid: Pid, addr: usize) -> Option<String> {
    let mut bytes = Vec::new();
    let mut curr_addr = addr;
    let word_size = std::mem::size_of::<libc::c_long>();

    while let Ok(word) = ptrace::read(pid, curr_addr as ptrace::AddressType) {
        let word_bytes = word.to_ne_bytes();
        for &b in &word_bytes {
            if b == 0 {
                return String::from_utf8(bytes).ok();
            }
            bytes.push(b);
            if bytes.len() > 4096 {
                return String::from_utf8(bytes).ok();
            }
        }
        curr_addr += word_size;
    }

    if bytes.is_empty() {
        None
    } else {
        String::from_utf8(bytes).ok()
    }
}

/// Resolves a file path against the traced process's current working directory.
pub fn resolve_path(proc_root: &Path, pid: i32, raw_path: &str, dirfd: libc::c_int) -> String {
    if raw_path.starts_with('/') {
        return raw_path.to_string();
    }

    let base_dir = if dirfd == -100
    /* AT_FDCWD */
    {
        let cwd_link = proc_root.join(pid.to_string()).join("cwd");
        fs::read_link(&cwd_link)
            .unwrap_or_else(|_| PathBuf::from("."))
            .to_string_lossy()
            .to_string()
    } else {
        let fd_link = proc_root
            .join(pid.to_string())
            .join("fd")
            .join(dirfd.to_string());
        fs::read_link(&fd_link)
            .unwrap_or_else(|_| PathBuf::from("."))
            .to_string_lossy()
            .to_string()
    };

    let p = Path::new(&base_dir).join(raw_path);
    // Canonicalize if file exists or simplify components
    if let Ok(c) = fs::canonicalize(&p) {
        c.to_string_lossy().to_string()
    } else {
        p.to_string_lossy().to_string()
    }
}

/// Parse /proc/<pid>/maps to discover loaded shared objects and binaries.
pub fn read_maps(proc_root: &Path, pid: i32) -> HashSet<String> {
    let maps_path = proc_root.join(pid.to_string()).join("maps");
    let mut loaded = HashSet::new();

    if let Ok(content) = fs::read_to_string(maps_path) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let pathname = parts[5];
                if pathname.starts_with('/') && !pathname.starts_with("/dev") {
                    loaded.insert(pathname.to_string());
                }
            }
        }
    }

    loaded
}

/// Traces a spawned child using ptrace with fork/clone/vfork/exec tracking.
pub fn run_ptrace_trace(
    child_pid: Pid,
    proc_root: &Path,
    _record_args: bool,
) -> Result<TraceResult, String> {
    // Wait for the child's initial SIGSTOP or ptrace-denied check
    let status = waitpid(child_pid, None).map_err(|e| format!("initial waitpid error: {}", e))?;

    let mut is_denied = false;
    match status {
        WaitStatus::Stopped(_, Signal::SIGSTOP) | WaitStatus::Stopped(_, Signal::SIGTRAP) => {
            // Ptrace success! Configure options: follow fork/vfork/clone/exec
            let options = ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEEXEC;
            if let Err(_e) = ptrace::setoptions(child_pid, options) {
                // ptrace operation not permitted or denied
                is_denied = true;
            }
        }
        _ => {
            is_denied = true;
        }
    }

    if is_denied {
        // Fallback to /proc polling mode!
        return run_proc_polling(child_pid, proc_root);
    }

    // Ptrace syscall loop
    let mut tracked_pids = HashSet::new();
    tracked_pids.insert(child_pid.as_raw());

    let mut in_syscall_entry: HashMap<i32, (i64, libc::user_regs_struct)> = HashMap::new();
    let mut file_accesses = Vec::new();
    let mut processes = HashMap::new();
    let mut loaded_libraries = HashSet::new();
    let mut final_exit_code = 0;

    // Record initial process info
    let exe_path = fs::read_link(proc_root.join(child_pid.to_string()).join("exe"))
        .unwrap_or_else(|_| PathBuf::from("unknown"))
        .to_string_lossy()
        .to_string();
    let exe_hash = match hash_regular_file(&exe_path, 256 * 1024 * 1024) {
        HashResult::Hash(h) => h,
        _ => "unreadable".to_string(),
    };
    let initial_maps = read_maps(proc_root, child_pid.as_raw());
    for lib in &initial_maps {
        loaded_libraries.insert(lib.clone());
    }

    processes.insert(
        child_pid.as_raw(),
        ProcessNode {
            pid: child_pid.as_raw(),
            ppid: std::process::id() as i32,
            exe: exe_path,
            exe_sha256: exe_hash,
            cwd: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            maps_loaded: initial_maps,
        },
    );

    // Resume execution
    let _ = ptrace::syscall(child_pid, None);

    loop {
        let wait_res = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL));
        let ws = match wait_res {
            Ok(s) => s,
            Err(_) => break, // No more children
        };

        match ws {
            WaitStatus::Exited(pid, code) => {
                if pid == child_pid {
                    final_exit_code = code;
                }
                // Record maps at exit
                let exit_maps = read_maps(proc_root, pid.as_raw());
                for lib in exit_maps {
                    loaded_libraries.insert(lib);
                }
                tracked_pids.remove(&pid.as_raw());
                if tracked_pids.is_empty() {
                    break;
                }
            }
            WaitStatus::Signaled(pid, sig, _) => {
                if pid == child_pid {
                    final_exit_code = 128 + sig as i32;
                }
                tracked_pids.remove(&pid.as_raw());
                if tracked_pids.is_empty() {
                    break;
                }
            }
            WaitStatus::PtraceEvent(pid, _, event) => {
                if event == libc::PTRACE_EVENT_FORK
                    || event == libc::PTRACE_EVENT_VFORK
                    || event == libc::PTRACE_EVENT_CLONE
                {
                    if let Ok(new_pid) = ptrace::getevent(pid) {
                        tracked_pids.insert(new_pid as i32);
                        let ppid = pid.as_raw();
                        let exe = fs::read_link(proc_root.join(new_pid.to_string()).join("exe"))
                            .unwrap_or_else(|_| PathBuf::from("unknown"))
                            .to_string_lossy()
                            .to_string();
                        let exe_sha = match hash_regular_file(&exe, 256 * 1024 * 1024) {
                            HashResult::Hash(h) => h,
                            _ => "unknown".to_string(),
                        };
                        let maps = read_maps(proc_root, new_pid as i32);
                        for l in &maps {
                            loaded_libraries.insert(l.clone());
                        }
                        processes.insert(
                            new_pid as i32,
                            ProcessNode {
                                pid: new_pid as i32,
                                ppid,
                                exe,
                                exe_sha256: exe_sha,
                                cwd: "".to_string(),
                                maps_loaded: maps,
                            },
                        );
                    }
                } else if event == libc::PTRACE_EVENT_EXEC {
                    let exe = fs::read_link(proc_root.join(pid.to_string()).join("exe"))
                        .unwrap_or_else(|_| PathBuf::from("unknown"))
                        .to_string_lossy()
                        .to_string();
                    let exe_sha = match hash_regular_file(&exe, 256 * 1024 * 1024) {
                        HashResult::Hash(h) => h,
                        _ => "unknown".to_string(),
                    };
                    let maps = read_maps(proc_root, pid.as_raw());
                    for l in &maps {
                        loaded_libraries.insert(l.clone());
                    }
                    if let Some(node) = processes.get_mut(&pid.as_raw()) {
                        node.exe = exe;
                        node.exe_sha256 = exe_sha;
                        node.maps_loaded = maps;
                    }
                }
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::PtraceSyscall(pid) => {
                #[cfg(target_arch = "x86_64")]
                {
                    if let Ok(regs) = ptrace::getregs(pid) {
                        let orig_rax = regs.orig_rax as i64;
                        let pid_raw = pid.as_raw();

                        if let Some((entry_orig_rax, entry_regs)) =
                            in_syscall_entry.remove(&pid_raw)
                        {
                            // Syscall exit: rax has return value
                            let ret_val = regs.rax as i64;
                            if ret_val >= 0 {
                                // Successful syscall!
                                match entry_orig_rax {
                                    2 /* open */ => {
                                        if let Some(path_str) = read_process_string(pid, entry_regs.rdi as usize) {
                                            let flags = entry_regs.rsi as libc::c_int;
                                            let acc = match flags & libc::O_ACCMODE {
                                                libc::O_WRONLY => AccessType::Write,
                                                libc::O_RDWR => AccessType::ReadWrite,
                                                _ => AccessType::Read,
                                            };
                                            let resolved = resolve_path(proc_root, pid_raw, &path_str, -100);
                                            file_accesses.push(FileAccess { path: resolved, access: acc, pid: pid_raw });
                                        }
                                    }
                                    257 /* openat */ => {
                                        if let Some(path_str) = read_process_string(pid, entry_regs.rsi as usize) {
                                            let dirfd = entry_regs.rdi as libc::c_int;
                                            let flags = entry_regs.rdx as libc::c_int;
                                            let acc = match flags & libc::O_ACCMODE {
                                                libc::O_WRONLY => AccessType::Write,
                                                libc::O_RDWR => AccessType::ReadWrite,
                                                _ => AccessType::Read,
                                            };
                                            let resolved = resolve_path(proc_root, pid_raw, &path_str, dirfd);
                                            file_accesses.push(FileAccess { path: resolved, access: acc, pid: pid_raw });
                                        }
                                    }
                                    437 /* openat2 */ => {
                                        if let Some(path_str) = read_process_string(pid, entry_regs.rsi as usize) {
                                            let dirfd = entry_regs.rdi as libc::c_int;
                                            let resolved = resolve_path(proc_root, pid_raw, &path_str, dirfd);
                                            file_accesses.push(FileAccess { path: resolved, access: AccessType::Read, pid: pid_raw });
                                        }
                                    }
                                    59 /* execve */ | 322 /* execveat */ => {
                                        // Update maps & loaded libraries after execve
                                        let maps = read_maps(proc_root, pid_raw);
                                        for l in maps {
                                            loaded_libraries.insert(l);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            // Syscall entry
                            in_syscall_entry.insert(pid_raw, (orig_rax, regs));
                        }
                    }
                }

                let _ = ptrace::syscall(pid, None);
            }
            _ => {
                let _ = ptrace::syscall(child_pid, None);
            }
        }
    }

    let mut seen_accesses = HashSet::new();
    let deduped_accesses: Vec<FileAccess> = file_accesses
        .into_iter()
        .filter(|fa| seen_accesses.insert(fa.clone()))
        .collect();

    Ok(TraceResult {
        exit_code: final_exit_code,
        ptrace_denied: false,
        processes: processes.into_values().collect(),
        file_accesses: deduped_accesses,
        loaded_libraries,
        coverage_mode: "ptrace".to_string(),
    })
}

/// Fallback when ptrace is denied (e.g. yama ptrace_scope=2 or container sandbox).
/// Polls /proc, captures process tree and maps, but emits coverage.blocked for file I/O.
pub fn run_proc_polling(child_pid: Pid, proc_root: &Path) -> Result<TraceResult, String> {
    let mut processes = Vec::new();
    let mut loaded_libraries = HashSet::new();
    let mut exit_code = 0;

    // Loop polling proc until child exits
    loop {
        let maps = read_maps(proc_root, child_pid.as_raw());
        for l in &maps {
            loaded_libraries.insert(l.clone());
        }

        let exe_link = proc_root.join(child_pid.to_string()).join("exe");
        let (exe_str, exe_sha) = if let Ok(target) = fs::read_link(&exe_link) {
            let s = target.to_string_lossy().to_string();
            let sha = match hash_regular_file(&s, 256 * 1024 * 1024) {
                HashResult::Hash(h) => h,
                _ => "unknown".to_string(),
            };
            (s, sha)
        } else {
            ("mock_process".to_string(), "unknown".to_string())
        };

        if processes.is_empty()
            && (!maps.is_empty() || proc_root.join(child_pid.to_string()).exists())
        {
            processes.push(ProcessNode {
                pid: child_pid.as_raw(),
                ppid: std::process::id() as i32,
                exe: exe_str,
                exe_sha256: exe_sha,
                cwd: "".to_string(),
                maps_loaded: maps,
            });
        }

        match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                exit_code = code;
                break;
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                exit_code = 128 + sig as i32;
                break;
            }
            Ok(WaitStatus::StillAlive) => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(_) => {
                break;
            }
            _ => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }

    Ok(TraceResult {
        exit_code,
        ptrace_denied: true,
        processes,
        file_accesses: Vec::new(), // Never fabricate file claims in fallback!
        loaded_libraries,
        coverage_mode: "polling".to_string(),
    })
}
