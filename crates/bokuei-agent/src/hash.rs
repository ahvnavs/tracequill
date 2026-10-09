use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum HashResult {
    Hash(String),
    NotVisible { reason: String },
    SkippedSpecialFs,
}

/// Compute SHA-256 for regular file up to size_cap.
/// Files in /proc, /sys, /dev are strictly never hashed.
pub fn hash_regular_file(path_str: &str, size_cap: u64) -> HashResult {
    if path_str.starts_with("/proc") || path_str.starts_with("/sys") || path_str.starts_with("/dev")
    {
        return HashResult::SkippedSpecialFs;
    }

    let path = Path::new(path_str);
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => {
            return HashResult::NotVisible {
                reason: "unreadable_metadata".to_string(),
            }
        }
    };

    if !metadata.is_file() {
        return HashResult::NotVisible {
            reason: "not_regular_file".to_string(),
        };
    }

    if metadata.len() > size_cap {
        return HashResult::NotVisible {
            reason: "size_cap".to_string(),
        };
    }

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return HashResult::NotVisible {
                reason: "permission_denied".to_string(),
            }
        }
    };

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => {
                return HashResult::NotVisible {
                    reason: "read_error".to_string(),
                }
            }
        }
    }

    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        hex.push_str(&format!("{:02x}", b));
    }
    HashResult::Hash(hex)
}

pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}
