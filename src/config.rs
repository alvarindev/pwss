// SPDX-License-Identifier: GPL-3.0-or-later
//! PWSS configuration (`/etc/pwss/config.toml`).
//!
//! Everything is optional: without a file, PWSS detects the environment by
//! itself. A future `pwss setup` will write this file from the user's answers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_PATH: &str = "/etc/pwss/config.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub discovery: Discovery,
    pub scan: ScanCfg,
    /// Sites declared by hand, for installations that are not detected automatically.
    #[serde(rename = "site")]
    pub sites: Vec<ManualSite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Discovery {
    /// Paths to search. Empty = paths of the detected panel + generic paths.
    pub roots: Vec<PathBuf>,
    /// Paths to ignore completely (prefixes).
    pub exclude: Vec<PathBuf>,
    /// Maximum depth below each root.
    pub max_depth: usize,
    /// Folder names that are never traversed when looking for sites.
    pub skip_dirs: Vec<String>,
}

impl Default for Discovery {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            exclude: Vec::new(),
            max_depth: 9,
            skip_dirs: [
                "wp-content",
                "wp-admin",
                "wp-includes",
                "node_modules",
                ".git",
                ".svn",
                "cache",
                ".cache",
                "logs",
                "tmp",
                "mail",
                "Maildir",
                ".trash",
                ".Trash",
                "cgi-bin",
                ".well-known",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

/// Scan exceptions and limits (`[scan]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanCfg {
    /// Path prefixes that are not analysed.
    pub ignore_paths: Vec<PathBuf>,
    /// Rule identifiers to ignore (e.g. `persist.mu-plugin`).
    pub ignore_rules: Vec<String>,
    /// SHA-256 of files that were reviewed and accepted.
    pub allow_sha256: Vec<String>,
    /// Maximum bytes read from each file (the rest is skipped).
    pub max_file_bytes: u64,
}

impl Default for ScanCfg {
    fn default() -> Self {
        Self {
            ignore_paths: Vec::new(),
            ignore_rules: Vec::new(),
            allow_sha256: Vec::new(),
            max_file_bytes: 4 << 20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualSite {
    /// Core folder (the one containing `wp-includes`).
    pub path: PathBuf,
    pub db_name: Option<String>,
    pub table_prefix: Option<String>,
    pub label: Option<String>,
}

impl Config {
    /// Loads the configuration. If `path` is not given and the default file
    /// does not exist, returns the default configuration.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let (p, required) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (PathBuf::from(DEFAULT_PATH), false),
        };
        if !p.exists() {
            if required {
                anyhow::bail!("configuration file {} does not exist", p.display());
            }
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&p)
            .with_context(|| format!("could not read {}", p.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid configuration in {}", p.display()))
    }
}
