// SPDX-License-Identifier: GPL-3.0-or-later
//! `pwss hunt`: looks for an indicator of compromise (hash, text or file
//! name) across every site on the server.
//!
//! It answers "is this malware anywhere else?" after finding it in one place.
//! Read-only; never follows symlinks.

use crate::discovery::Site;
use crate::util;
use aho_corasick::AhoCorasick;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub enum Needle {
    /// SHA-256 of a whole file (hexadecimal).
    Sha256(String),
    /// Text contained in a file.
    Text(String),
    /// File name (supports `*` and `?`).
    Name(String),
}

pub struct Options {
    pub threads: usize,
    pub ignore_case: bool,
    /// `None` = every file.
    pub exts: Option<Vec<String>>,
    /// Maximum size of files whose content is read.
    pub max_size: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            threads: 2,
            ignore_case: false,
            exts: Some(default_exts()),
            max_size: 8 << 20,
        }
    }
}

pub fn default_exts() -> Vec<String> {
    [
        "php", "php3", "php4", "php5", "php7", "php8", "phtml", "pht", "phar", "phps", "inc", "js",
        "mjs", "html", "htm", "txt", "ico", "ini", "json", "sh", "pl", "py", "cgi", "htaccess",
        "sql", "xml", "log",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub site: String,
    pub path: PathBuf,
    /// Which indicators match.
    pub matched: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub size: u64,
    pub modified: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub roots: usize,
    pub files: u64,
    pub read: u64,
    pub bytes_read: u64,
    pub skipped_large: u64,
    pub unreadable: u64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub matches: Vec<Match>,
    pub stats: Stats,
}

/// Normalises and validates a SHA-256 typed by the user.
pub fn parse_sha256(s: &str) -> Option<String> {
    let t = s.trim().to_lowercase();
    (t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())).then_some(t)
}

fn site_for<'a>(sites: &'a [Site], path: &Path) -> Option<&'a Site> {
    sites
        .iter()
        .filter(|s| {
            path.starts_with(&s.core_dir)
                || path.starts_with(&s.web_root)
                || path.starts_with(&s.content_dir)
        })
        .max_by_key(|s| {
            let a = if path.starts_with(&s.core_dir) {
                s.core_dir.components().count()
            } else {
                0
            };
            let b = if path.starts_with(&s.web_root) {
                s.web_root.components().count()
            } else {
                0
            };
            a.max(b)
        })
}

fn texty(name: &str, exts: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    match lower.rsplit_once('.') {
        Some(("", rest)) => exts.iter().any(|e| e == rest), // .htaccess
        Some((_, ext)) => exts.iter().any(|e| e == ext),
        None => false,
    }
}

pub fn run(sites: &[Site], needles: &[Needle], opts: &Options) -> Report {
    let started = Instant::now();

    // Search roots: the web folder of every site that is not inside another.
    let mut roots: Vec<PathBuf> = Vec::new();
    for s in sites.iter().filter(|s| s.nested_in.is_none()) {
        roots.push(s.web_root.clone());
        if !s.content_dir.starts_with(&s.web_root) {
            roots.push(s.content_dir.clone());
        }
    }
    roots.sort();
    roots.dedup();
    let all = roots.clone();
    roots.retain(|r| !all.iter().any(|o| o != r && r.starts_with(o)));

    let shas: HashSet<String> = needles
        .iter()
        .filter_map(|n| {
            if let Needle::Sha256(h) = n {
                Some(h.clone())
            } else {
                None
            }
        })
        .collect();
    let texts: Vec<&str> = needles
        .iter()
        .filter_map(|n| {
            if let Needle::Text(t) = n {
                Some(t.as_str())
            } else {
                None
            }
        })
        .collect();
    let names: Vec<&str> = needles
        .iter()
        .filter_map(|n| {
            if let Needle::Name(t) = n {
                Some(t.as_str())
            } else {
                None
            }
        })
        .collect();
    let ac = (!texts.is_empty()).then(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(opts.ignore_case)
            .build(&texts)
            .expect("valid patterns")
    });
    let need_content = !shas.is_empty() || ac.is_some();

    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Match>> = Mutex::new(Vec::new());
    let (files, read, bytes, large, unread) = (
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    );
    let threads = opts.threads.clamp(1, 64).min(roots.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(root) = roots.get(i) else { break };
                    let it = WalkDir::new(root).follow_links(false).into_iter();
                    for e in it {
                        let Ok(e) = e else {
                            unread.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        if !e.file_type().is_file() {
                            continue;
                        }
                        files.fetch_add(1, Ordering::Relaxed);
                        let name = e.file_name().to_string_lossy().into_owned();
                        let mut matched: Vec<String> = Vec::new();
                        for n in &names {
                            let (pat, txt) = if opts.ignore_case {
                                (n.to_lowercase(), name.to_lowercase())
                            } else {
                                (n.to_string(), name.clone())
                            };
                            if util::wildcard(&pat, &txt) {
                                matched.push(format!("name {n}"));
                            }
                        }
                        let mut sha: Option<String> = None;
                        let mut evidence = None;
                        let mut size = 0u64;
                        let mut modified = 0i64;

                        let wanted =
                            need_content && opts.exts.as_ref().is_none_or(|x| texty(&name, x));
                        if wanted {
                            match util::read_limited(e.path(), opts.max_size) {
                                Ok(d) if d.truncated => {
                                    large.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(d) => {
                                    read.fetch_add(1, Ordering::Relaxed);
                                    bytes.fetch_add(d.bytes.len() as u64, Ordering::Relaxed);
                                    size = d.size;
                                    modified = d.mtime;
                                    if !shas.is_empty() {
                                        let h = util::sha256_bytes(&d.bytes);
                                        if shas.contains(&h) {
                                            matched.push(format!("sha256 {}...", &h[..16]));
                                        }
                                        sha = Some(h);
                                    }
                                    if let Some(ac) = &ac {
                                        let mut seen = BTreeSet::new();
                                        let mut first = None;
                                        for m in ac.find_overlapping_iter(&d.bytes) {
                                            if seen.insert(m.pattern().as_usize())
                                                && first.is_none()
                                            {
                                                first = Some((m.start(), m.end()));
                                            }
                                            if seen.len() == texts.len() {
                                                break;
                                            }
                                        }
                                        for id in &seen {
                                            matched.push(format!(
                                                "text \"{}\"",
                                                util::sanitize(texts[*id])
                                            ));
                                        }
                                        if let Some((s, en)) = first {
                                            evidence = Some(util::snippet(&d.bytes, s, en, 110));
                                        }
                                    }
                                }
                                Err(err) => {
                                    if err.kind() == std::io::ErrorKind::PermissionDenied {
                                        unread.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        if matched.is_empty() {
                            continue;
                        }
                        if (size == 0 || modified == 0)
                            && let Ok(m) = std::fs::symlink_metadata(e.path())
                        {
                            use std::os::unix::fs::MetadataExt;
                            size = m.len();
                            modified = m.mtime();
                        }
                        if sha.is_none() {
                            sha = util::sha256_file(e.path(), 64 << 20);
                        }
                        let site = site_for(sites, e.path())
                            .map(|s| util::sanitize(&s.display_name()))
                            .unwrap_or_else(|| "?".into());
                        out.lock().unwrap().push(Match {
                            site,
                            path: e.path().to_path_buf(),
                            matched,
                            sha256: sha,
                            size,
                            modified,
                            evidence,
                        });
                    }
                }
            });
        }
    });

    let mut matches = out.into_inner().unwrap();
    matches.sort_by(|a, b| a.site.cmp(&b.site).then_with(|| a.path.cmp(&b.path)));
    Report {
        matches,
        stats: Stats {
            roots: roots.len(),
            files: files.load(Ordering::Relaxed),
            read: read.load(Ordering::Relaxed),
            bytes_read: bytes.load(Ordering::Relaxed),
            skipped_large: large.load(Ordering::Relaxed),
            unreadable: unread.load(Ordering::Relaxed),
            elapsed_ms: started.elapsed().as_millis(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_parsing() {
        assert!(parse_sha256(&"A".repeat(64)).is_some());
        assert!(parse_sha256("abc").is_none());
        assert!(parse_sha256(&"g".repeat(64)).is_none());
    }

    #[test]
    fn extension_filter() {
        let e = default_exts();
        assert!(texty("a.PHP", &e));
        assert!(texty(".htaccess", &e));
        assert!(!texty("a.jpg", &e));
        assert!(!texty("Makefile", &e));
    }
}
