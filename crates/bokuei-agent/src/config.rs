use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default = "default_size_cap")]
    pub size_cap_bytes: u64,
}

fn default_size_cap() -> u64 {
    256 * 1024 * 1024 // 256 MiB
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exclusions: vec![],
            size_cap_bytes: default_size_cap(),
        }
    }
}

impl Config {
    pub fn load_or_default(path: impl AsRef<Path>) -> Self {
        if let Ok(content) = std::fs::read_to_string(path) {
            toml::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn is_excluded(&self, path: &str) -> bool {
        for pattern in &self.exclusions {
            if path.contains(pattern) || path.starts_with(pattern) {
                return true;
            }
        }
        false
    }
}
