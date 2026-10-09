use crate::hash::hash_bytes;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;

/// Default allowlisted environment variable names whose values may be recorded.
pub const ALLOWLISTED_ENV_NAMES: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "OMP_NUM_THREADS",
    "CUDA_VISIBLE_DEVICES",
    "PYTHONHASHSEED",
    "VIRTUAL_ENV",
];

#[derive(Debug, Clone)]
pub struct EnvRecord {
    pub name: String,
    pub value_repr: String, // allowlisted plain value, salted hash, or redacted placeholder
    pub is_value_recorded: bool,
}

pub fn generate_env_salt() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut bytes);
    }
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Capture environment variables adhering to the strict security rules:
/// - Never open process procfs env files directly
/// - Environment variables: names only, plus values for documented allowlist
/// - If hash_values is true with a salt, non-allowlisted values are salted hashed
pub fn process_env_map(
    env_vars: impl IntoIterator<Item = (String, String)>,
    hash_values: bool,
    salt: Option<&str>,
) -> Vec<EnvRecord> {
    let allowlist: HashSet<&str> = ALLOWLISTED_ENV_NAMES.iter().copied().collect();
    let mut records = Vec::new();

    for (name, val) in env_vars {
        if allowlist.contains(name.as_str()) {
            records.push(EnvRecord {
                name,
                value_repr: val,
                is_value_recorded: true,
            });
        } else if hash_values {
            if let Some(s) = salt {
                let salted = format!("{}:{}", s, val);
                records.push(EnvRecord {
                    name,
                    value_repr: format!("salted_sha256:{}", hash_bytes(salted.as_bytes())),
                    is_value_recorded: true,
                });
            } else {
                records.push(EnvRecord {
                    name,
                    value_repr: "[VALUE_NOT_RECORDED]".to_string(),
                    is_value_recorded: false,
                });
            }
        } else {
            records.push(EnvRecord {
                name,
                value_repr: "[VALUE_NOT_RECORDED]".to_string(),
                is_value_recorded: false,
            });
        }
    }

    records.sort_by(|a, b| a.name.cmp(&b.name));
    records
}
