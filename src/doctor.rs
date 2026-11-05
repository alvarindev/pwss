// SPDX-License-Identifier: GPL-3.0-or-later
//! `pwss doctor`: checks whether this server is compatible and what will work.
//!
//! It changes nothing. Every check returns OK, WARN or FAIL with an
//! explanation and, when needed, what to do about it.

use crate::discovery::Discovery;
use serde::Serialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Info,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub group: &'static str,
    pub name: String,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
    /// Recommended threads for scanning without affecting production.
    pub recommended_threads: usize,
}

impl Report {
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }
}

struct B<'a>(&'a mut Vec<Check>, &'static str);
impl B<'_> {
    fn add(
        &mut self,
        status: Status,
        name: impl Into<String>,
        detail: impl Into<String>,
        fix: Option<&str>,
    ) {
        self.0.push(Check {
            group: self.1,
            name: name.into(),
            status,
            detail: detail.into(),
            fix: fix.map(str::to_string),
        });
    }
}

/// Recommended threads for scanning without affecting production: a third of
/// the cores, and never more than are free.
pub fn recommended_threads() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let load = loadavg().unwrap_or(0.0);
    let free = (cores as f64 - load).max(1.0).floor() as usize;
    (cores / 3).max(1).min(free).max(1)
}

pub fn run(disc: &Discovery) -> Report {
    let mut checks = Vec::new();

    // --- System -----------------------------------------------------------
    let mut b = B(&mut checks, "System");
    let os = os_name().unwrap_or_else(|| "unknown".into());
    let arch = std::env::consts::ARCH;
    let arch_ok = matches!(arch, "x86_64" | "aarch64");
    b.add(
        if arch_ok { Status::Ok } else { Status::Warn },
        "Operating system",
        format!("{os}, {arch}, kernel {}", kernel().unwrap_or_default()),
        (!arch_ok).then_some("Untested architecture: build PWSS from source."),
    );
    let root = is_root();
    b.add(
        if root { Status::Ok } else { Status::Warn },
        "Permissions",
        if root {
            "running as root: can read every site".to_string()
        } else {
            "not root: only files this user can read will be visible".to_string()
        },
        (!root).then_some(
            "Run with sudo, or use the PWSS service (planned), which reads without being able to write.",
        ),
    );
    let systemd = Path::new("/run/systemd/system").is_dir();
    b.add(
        if systemd { Status::Ok } else { Status::Warn },
        "systemd",
        if systemd {
            "available for scheduling scans"
        } else {
            "not detected"
        },
        (!systemd).then_some("Without systemd, scans will have to be scheduled with cron."),
    );

    // --- Resources --------------------------------------------------------
    let mut b = B(&mut checks, "Resources");
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let load = loadavg().unwrap_or(0.0);
    let mem = mem_available_mb();
    let free_cores = (cores as f64 - load).max(1.0);
    let recommended = ((cores / 3).max(1)).min(free_cores.floor() as usize).max(1);
    let busy = load > cores as f64 * 0.7;
    b.add(
        if busy { Status::Warn } else { Status::Ok },
        "CPU",
        format!(
            "{cores} cores, load average {load:.2}; {recommended} threads will be used by default"
        ),
        busy.then_some("Heavily loaded server: schedule scans during low-traffic hours."),
    );
    if let Some(mb) = mem {
        let low = mb < 512;
        b.add(
            if low { Status::Warn } else { Status::Ok },
            "Available memory",
            format!("{} MB", mb),
            low.then_some("Little free memory: malware scanning will be slower."),
        );
    }

    // --- Sites ------------------------------------------------------------
    let mut b = B(&mut checks, "WordPress");
    let panels = if disc.panels.is_empty() {
        "none (manually configured server)".to_string()
    } else {
        disc.panels
            .iter()
            .map(|p| p.name())
            .collect::<Vec<_>>()
            .join(", ")
    };
    b.add(Status::Info, "Panel", panels, None);
    b.add(
        if disc.roots.is_empty() {
            Status::Fail
        } else {
            Status::Ok
        },
        "Search paths",
        if disc.roots.is_empty() {
            "no search path exists".to_string()
        } else {
            disc.roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
        disc.roots
            .is_empty()
            .then_some("Give the paths with --root or in [discovery] roots."),
    );
    let n = disc.sites.len();
    b.add(
        if n == 0 { Status::Fail } else { Status::Ok },
        "Installations found",
        format!("{n} ({} folders checked)", disc.dirs_visited),
        (n == 0).then_some(
            "If WordPress lives elsewhere, add the path with --root or in the configuration.",
        ),
    );
    let no_db: Vec<_> = disc.sites.iter().filter(|s| !s.db_ready()).collect();
    if n > 0 {
        b.add(
            if no_db.is_empty() { Status::Ok } else { Status::Warn },
            "Database configuration",
            if no_db.is_empty() {
                "read for every site".to_string()
            } else {
                format!(
                    "missing for {}: {}",
                    no_db.len(),
                    no_db.iter().take(5).map(|s| s.core_dir.display().to_string()).collect::<Vec<_>>().join(", ")
                )
            },
            (!no_db.is_empty()).then_some(
                "With the PWSS MySQL user (planned) they will be located by content; you can also declare them in [[site]].",
            ),
        );
    }
    let nested = disc.sites.iter().filter(|s| s.nested_in.is_some()).count();
    if nested > 0 {
        b.add(Status::Info, "Nested copies", format!("{nested} WordPress installs inside another site (development, testing...): they are scanned too"), None);
    }
    let atypical = disc
        .sites
        .iter()
        .filter(|s| !matches!(s.layout, crate::discovery::Layout::Standard))
        .count();
    if atypical > 0 {
        b.add(
            Status::Info,
            "Non-standard layouts",
            format!("{atypical} sites"),
            None,
        );
    }
    if !disc.orphan_configs.is_empty() {
        b.add(
            Status::Warn,
            "wp-config.php without WordPress",
            format!(
                "{} files: leftovers of installations or configurations that could not be linked",
                disc.orphan_configs.len()
            ),
            Some("Review them with `pwss sites --verbose`."),
        );
    }
    if disc.unreadable > 0 {
        b.add(
            Status::Warn,
            "Unreadable folders",
            format!("{}", disc.unreadable),
            Some("Run as root to check them all."),
        );
    }

    // --- Database ---------------------------------------------------------
    let mut b = B(&mut checks, "Database");
    let socket = [
        "/run/mysqld/mysqld.sock",
        "/var/run/mysqld/mysqld.sock",
        "/var/lib/mysql/mysql.sock",
        "/tmp/mysql.sock",
        "/var/run/mysql/mysql.sock",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists());
    let engine = db_engine();
    b.add(
        if engine.is_some() {
            Status::Ok
        } else {
            Status::Warn
        },
        "Engine",
        engine
            .clone()
            .unwrap_or_else(|| "no mysql/mariadb client found".into()),
        engine.is_none().then_some(
            "If the database is on another server, it will be configured over TCP (planned).",
        ),
    );
    b.add(
        if socket.is_some() {
            Status::Ok
        } else {
            Status::Warn
        },
        "Local socket",
        socket
            .map(str::to_string)
            .unwrap_or_else(|| "not found".into()),
        socket
            .is_none()
            .then_some("Without a local socket, TCP with user and password will be used."),
    );
    let remote = disc
        .sites
        .iter()
        .filter_map(|s| s.db_host.as_deref())
        .filter(|h| !is_local_host(h))
        .count();
    if remote > 0 {
        b.add(
            Status::Warn,
            "Remote databases",
            format!("{remote} sites use another database server"),
            Some("They can be scanned over TCP with a read-only user on that server."),
        );
    }

    // --- Mail -------------------------------------------------------------
    let mut b = B(&mut checks, "Mail");
    let sendmail = [
        "/usr/sbin/sendmail",
        "/usr/bin/sendmail",
        "/usr/lib/sendmail",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists());
    b.add(
        if sendmail.is_some() {
            Status::Ok
        } else {
            Status::Info
        },
        "Local sendmail",
        sendmail
            .map(|p| format!("available at {p}"))
            .unwrap_or_else(|| "not available; SMTP will be used".into()),
        None,
    );

    // --- Other tools ------------------------------------------------------
    let mut b = B(&mut checks, "Other security tools");
    for (name, path) in [
        ("Linux Malware Detect", "/usr/local/maldetect"),
        ("ClamAV", "/usr/bin/clamscan"),
        ("chkrootkit", "/usr/sbin/chkrootkit"),
        ("Imunify360", "/usr/bin/imunify360-agent"),
        ("ImunifyAV", "/usr/bin/imunify-antivirus"),
        ("rkhunter", "/usr/bin/rkhunter"),
    ] {
        if Path::new(path).exists() {
            b.add(
                Status::Info,
                name,
                "installed: avoid overlapping scan schedules",
                None,
            );
        }
    }

    checks.extend(crate::health::run(&crate::health::Env::default()));

    Report {
        checks,
        recommended_threads: recommended,
    }
}

fn is_local_host(h: &str) -> bool {
    let h = h.split(':').next().unwrap_or(h);
    matches!(h, "localhost" | "127.0.0.1" | "::1" | "") || h.starts_with("localhost")
}

fn os_name() -> Option<String> {
    let t = std::fs::read_to_string("/etc/os-release").ok()?;
    t.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
}

fn kernel() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

pub(crate) fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|s| s == "0"))
        })
        .unwrap_or(false)
}

fn loadavg() -> Option<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn mem_available_mb() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = t
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb / 1024)
}

fn db_engine() -> Option<String> {
    for bin in ["mariadbd", "mysqld", "mariadb", "mysql"] {
        for dir in [
            "/usr/sbin",
            "/usr/bin",
            "/usr/local/bin",
            "/usr/local/mysql/bin",
        ] {
            let p = Path::new(dir).join(bin);
            if !p.exists() {
                continue;
            }
            if let Ok(o) = Command::new(&p).arg("--version").output() {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !s.is_empty() {
                    let kind = if s.to_lowercase().contains("mariadb") {
                        "MariaDB"
                    } else {
                        "MySQL"
                    };
                    let words: Vec<&str> = s.split_whitespace().collect();
                    let ver = words
                        .iter()
                        .position(|w| *w == "Distrib")
                        .and_then(|i| words.get(i + 1).copied())
                        .or_else(|| {
                            words.iter().copied().find(|w| {
                                w.chars().next().is_some_and(|c| c.is_ascii_digit())
                                    && w.contains('.')
                            })
                        })
                        .unwrap_or("")
                        .trim_end_matches(',');
                    let ver = ver.split("-MariaDB").next().unwrap_or(ver);
                    return Some(format!("{kind} {ver}"));
                }
            }
        }
    }
    None
}
