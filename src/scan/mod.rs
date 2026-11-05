// SPDX-License-Identifier: GPL-3.0-or-later
//! `pwss scan`: looks for persistence and suspicious code in every site.
//!
//! Two levels:
//!
//! * **normal** (default): only checks the zones where malware hides to
//!   survive a cleanup: mu-plugins, drop-ins, `languages/`, `upgrade/`,
//!   `uploads/`, hidden folders, theme entry files, `wp-config.php`, the
//!   WordPress root, `.htaccess` and `.user.ini`.
//! * **`--deep`**: also analyses all PHP in plugins, themes and core. Slower
//!   and with more false positives (compensated by lower severities outside
//!   the persistence zones).
//!
//! Read-only. Never follows symlinks and limits what it reads.

pub mod rules;
mod walk;

use crate::config::Config;
use crate::discovery::Site;
use rules::{Hit, Severity};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

pub struct Options {
    pub deep: bool,
    pub threads: usize,
    pub min_severity: Severity,
    /// Only sites whose name or path contains this text.
    pub filter: Option<String>,
    /// Show progress on stderr.
    pub progress: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            deep: false,
            threads: 2,
            min_severity: Severity::Medium,
            filter: None,
            progress: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub site: String,
    pub severity: Severity,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub size: u64,
    /// Modification time (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
    pub reasons: Vec<Hit>,
}

#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub dirs: AtomicU64,
    pub files: AtomicU64,
    pub analysed: AtomicU64,
    pub bytes: AtomicU64,
    pub unreadable: AtomicU64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub sites: usize,
    pub dirs: u64,
    pub files: u64,
    pub analysed: u64,
    pub bytes_read: u64,
    pub unreadable: u64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub deep: bool,
    pub min_severity: Severity,
    pub findings: Vec<Finding>,
    /// Findings below `min_severity` that are not shown.
    pub hidden_below_min: usize,
    pub stats: Stats,
}

impl Report {
    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

pub fn run(sites: &[Site], cfg: &Config, opts: &Options) -> Report {
    let started = Instant::now();
    let selected: Vec<&Site> = sites
        .iter()
        .filter(|s| match &opts.filter {
            Some(f) => {
                let f = f.to_lowercase();
                s.display_name().to_lowercase().contains(&f)
                    || s.core_dir.display().to_string().to_lowercase().contains(&f)
            }
            None => true,
        })
        .collect();

    let others: Vec<PathBuf> = sites.iter().map(|s| s.core_dir.clone()).collect();
    let counters = Counters::default();
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
    let done = AtomicUsize::new(0);
    let threads = opts.threads.clamp(1, 64).min(selected.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(site) = selected.get(i) else { break };
                    let found = walk::scan_site(site, &others, cfg, opts.deep, &counters);
                    if !found.is_empty() {
                        out.lock().unwrap().extend(found);
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if opts.progress {
                        eprint!("\r  scanned {n}/{} sites...   ", selected.len());
                    }
                }
            });
        }
    });
    if opts.progress {
        eprintln!("\r{}", " ".repeat(40));
    }

    let mut all = out.into_inner().unwrap();
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.site.cmp(&b.site))
            .then_with(|| a.path.cmp(&b.path))
    });
    let total = all.len();
    all.retain(|f| f.severity >= opts.min_severity);
    let hidden_below_min = total - all.len();

    Report {
        deep: opts.deep,
        min_severity: opts.min_severity,
        findings: all,
        hidden_below_min,
        stats: Stats {
            sites: selected.len(),
            dirs: counters.dirs.load(Ordering::Relaxed),
            files: counters.files.load(Ordering::Relaxed),
            analysed: counters.analysed.load(Ordering::Relaxed),
            bytes_read: counters.bytes.load(Ordering::Relaxed),
            unreadable: counters.unreadable.load(Ordering::Relaxed),
            elapsed_ms: started.elapsed().as_millis(),
        },
    }
}
