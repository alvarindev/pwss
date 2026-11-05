// SPDX-License-Identifier: GPL-3.0-or-later
//! PHP per version, Apache and memory capacity.
//!
//! Everything is deduced from the running processes (`/proc`) and their
//! configuration files; neither PHP nor Apache is executed.
//!
//! What is checked:
//!
//! * running PHP versions and whether they still receive security fixes;
//! * `session.upload_progress.enabled` per pool and SAPI (mitigation for the
//!   PHP advisory CVE-2026-115560, 2026-10-23);
//! * whether Apache loads `mod_php`, which MPM it uses and how many
//!   processes it allows;
//! * worst-case memory: if every Apache and PHP-FPM worker filled up at the
//!   same time, would it fit in RAM? (the incident: Apache 150 workers of
//!   ~90 MB + PHP-FPM, against 24 GB).

use crate::doctor::{Check, Status};
use crate::util::{self, fmt_mb};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cmdline: String,
    pub exe: Option<PathBuf>,
    /// Proportional memory in kB (Pss when readable, otherwise RSS).
    pub pss_kb: u64,
}

fn kb_field(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

pub fn read_procs(proc_root: &Path) -> Vec<ProcInfo> {
    let Ok(rd) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let d = e.path();
        let Ok(status) = std::fs::read_to_string(d.join("status")) else {
            continue;
        };
        let comm = status
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let ppid = kb_field(&status, "PPid:").unwrap_or(0) as u32;
        let rss = kb_field(&status, "VmRSS:").unwrap_or(0);
        let pss = std::fs::read_to_string(d.join("smaps_rollup"))
            .ok()
            .and_then(|t| kb_field(&t, "Pss:"))
            .unwrap_or(rss);
        let cmdline = std::fs::read(d.join("cmdline"))
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .replace('\0', " ")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default();
        let exe = std::fs::read_link(d.join("exe")).ok();
        out.push(ProcInfo {
            pid,
            ppid,
            comm,
            cmdline,
            exe,
            pss_kb: pss,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// PHP versions
// ---------------------------------------------------------------------------

/// Branch (major, minor) deduced from a path or name.
pub fn parse_branch(s: &str) -> Option<(u8, u8)> {
    use std::sync::OnceLock;
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    let rs = R.get_or_init(|| {
        [
            r"php-?fpm-?(\d)\.(\d)",
            r"/php/(\d)\.(\d)",
            r"php[-_]?(\d)\.(\d)",
            r"php[-_]?(\d)(\d)(?:[^\d]|$)",
        ]
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect()
    });
    let s = s.to_lowercase();
    rs.iter().find_map(|r| {
        r.captures(&s)
            .map(|c| (c[1].parse().unwrap_or(0), c[2].parse().unwrap_or(0)))
    })
}

/// End of security support of each branch according to php.net/supported-versions.
#[allow(clippy::type_complexity)]
const PHP_SECURITY_END: &[((u8, u8), (i64, u32, u32))] = &[
    ((7, 4), (2022, 11, 28)),
    ((8, 0), (2023, 11, 26)),
    ((8, 1), (2025, 12, 31)),
    ((8, 2), (2026, 12, 31)),
    ((8, 3), (2027, 12, 31)),
    ((8, 4), (2028, 12, 31)),
    ((8, 5), (2029, 12, 31)),
];

#[derive(Debug, PartialEq, Eq)]
pub enum Support {
    /// No longer receives security fixes.
    Ended(Option<(i64, u32, u32)>),
    /// Stops receiving them within a few days.
    EndsSoon(i64, (i64, u32, u32)),
    Supported((i64, u32, u32)),
    Unknown,
}

pub fn support(branch: (u8, u8), today: (i64, u32, u32)) -> Support {
    if branch.0 < 7 || (branch.0 == 7 && branch.1 < 4) {
        return Support::Ended(None);
    }
    let Some((_, end)) = PHP_SECURITY_END.iter().find(|(b, _)| *b == branch) else {
        return Support::Unknown;
    };
    let left = util::days_from_civil(end.0, end.1, end.2)
        - util::days_from_civil(today.0, today.1, today.2);
    if left < 0 {
        Support::Ended(Some(*end))
    } else if left <= 90 {
        Support::EndsSoon(left, *end)
    } else {
        Support::Supported(*end)
    }
}

fn date_s(d: (i64, u32, u32)) -> String {
    format!("{:04}-{:02}-{:02}", d.0, d.1, d.2)
}

// ---------------------------------------------------------------------------
// PHP configuration
// ---------------------------------------------------------------------------

/// Reads a simple php.ini (`key = value`).
pub fn parse_ini(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with(';') || l.starts_with('#') || l.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let v = v
                .split(" ;")
                .next()
                .unwrap_or(v)
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            m.insert(k.trim().to_lowercase(), v.to_string());
        }
    }
    m
}

pub fn truthy(v: &str) -> bool {
    match v.trim().to_lowercase().as_str() {
        "" | "0" | "off" | "false" | "no" | "none" | "null" => false,
        "1" | "on" | "true" | "yes" => true,
        other => other.parse::<i64>().map(|n| n != 0).unwrap_or(true),
    }
}

#[derive(Debug, Clone)]
pub struct Pool {
    pub name: String,
    pub max_children: Option<u32>,
    pub settings: BTreeMap<String, String>,
}

/// Reads a PHP-FPM configuration and the files it includes.
pub fn parse_fpm_conf(path: &Path) -> Vec<Pool> {
    let mut pools: Vec<Pool> = Vec::new();
    let mut visited = HashSet::new();
    fpm_walk(path, 0, &mut visited, &mut pools);
    pools
}

fn fpm_walk(path: &Path, depth: usize, visited: &mut HashSet<PathBuf>, pools: &mut Vec<Pool>) {
    if depth > 6 || !visited.insert(path.to_path_buf()) {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let setting = Regex::new(r"(?i)^php_(?:admin_)?(?:value|flag)\[([^\]]+)\]$").unwrap();
    let mut section = String::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with(';') || l.starts_with('#') {
            continue;
        }
        if l.starts_with('[') && l.ends_with(']') {
            section = l[1..l.len() - 1].trim().to_string();
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let (k, v) = (
            k.trim(),
            v.split(" ;").next().unwrap_or(v).trim().trim_matches('"'),
        );
        if k.eq_ignore_ascii_case("include") {
            let base = path.parent().unwrap_or(Path::new("/"));
            let pat = if v.starts_with('/') {
                v.to_string()
            } else {
                format!("{}/{v}", base.display())
            };
            for f in util::glob(Path::new("/"), &pat) {
                fpm_walk(&f, depth + 1, visited, pools);
            }
            continue;
        }
        if section.is_empty() || section.eq_ignore_ascii_case("global") {
            continue;
        }
        let idx = match pools.iter().position(|p| p.name == section) {
            Some(i) => i,
            None => {
                pools.push(Pool {
                    name: section.clone(),
                    max_children: None,
                    settings: BTreeMap::new(),
                });
                pools.len() - 1
            }
        };
        if k.eq_ignore_ascii_case("pm.max_children") {
            pools[idx].max_children = v.parse().ok();
        } else if let Some(c) = setting.captures(k) {
            pools[idx]
                .settings
                .insert(c[1].to_lowercase(), v.to_string());
        }
    }
}

/// Effective php.ini + conf.d values for a configuration.
fn read_ini_set(dirs: &[PathBuf]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for d in dirs {
        let ini = d.join("php.ini");
        if let Ok(t) = std::fs::read_to_string(&ini) {
            out.extend(parse_ini(&t));
            break;
        }
    }
    for d in dirs {
        for sub in ["conf.d", "php.d"] {
            for f in util::glob(Path::new("/"), &format!("{}/{sub}/*.ini", d.display())) {
                if let Ok(t) = std::fs::read_to_string(&f) {
                    out.extend(parse_ini(&t));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Apache
// ---------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApacheInfo {
    pub mpm: Option<String>,
    pub mod_php: Vec<String>,
    pub max_workers: Option<u32>,
}

pub fn apache_info(fs_root: &Path) -> Option<ApacheInfo> {
    let rb = |p: &str| crate::panel::rebase(fs_root, p);
    let mut info = ApacheInfo::default();
    let max_re = Regex::new(r"(?im)^\s*(?:MaxRequestWorkers|MaxClients)\s+(\d+)").unwrap();

    let enabled = rb("/etc/apache2/mods-enabled");
    if enabled.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&enabled)
            .ok()?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for n in &names {
            if let Some(m) = n.strip_prefix("mpm_").and_then(|r| r.strip_suffix(".load")) {
                info.mpm = Some(m.to_string());
            }
            if let Some(v) = n.strip_prefix("php").and_then(|r| r.strip_suffix(".load")) {
                info.mod_php.push(v.to_string());
            }
        }
        let mut files: Vec<PathBuf> = Vec::new();
        if let Some(m) = &info.mpm {
            files.push(enabled.join(format!("mpm_{m}.conf")));
            files.push(enabled.join("mpm_prefork.conf"));
        }
        files.push(rb("/etc/apache2/apache2.conf"));
        for f in files {
            if let Some(c) = std::fs::read_to_string(&f)
                .ok()
                .and_then(|t| max_re.captures(&t).map(|c| c[1].to_string()))
            {
                info.max_workers = c.parse().ok();
                break;
            }
        }
        return Some(info);
    }

    let httpd = rb("/etc/httpd");
    if httpd.is_dir() {
        let mods = util::glob(fs_root, "/etc/httpd/conf.modules.d/*.conf");
        let load =
            Regex::new(r"(?m)^\s*LoadModule\s+(mpm_\w+?)_module|^\s*LoadModule\s+(php\d?)_module")
                .unwrap();
        for f in mods {
            if let Ok(t) = std::fs::read_to_string(&f) {
                for c in load.captures_iter(&t) {
                    if let Some(m) = c.get(1) {
                        info.mpm = Some(m.as_str().trim_start_matches("mpm_").to_string());
                    }
                    if let Some(p) = c.get(2) {
                        info.mod_php.push(p.as_str().to_string());
                    }
                }
            }
        }
        let mut files = vec![rb("/etc/httpd/conf/httpd.conf")];
        files.extend(util::glob(fs_root, "/etc/httpd/conf.d/*.conf"));
        for f in files {
            if let Some(c) = std::fs::read_to_string(&f)
                .ok()
                .and_then(|t| max_re.captures(&t).map(|c| c[1].to_string()))
            {
                info.max_workers = c.parse().ok();
                break;
            }
        }
        return Some(info);
    }
    None
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

pub struct Inputs {
    pub procs: Vec<ProcInfo>,
    pub fs_root: PathBuf,
    pub mem_total_mb: f64,
    pub today: (i64, u32, u32),
}

/// Estimated memory per worker when none is running.
const DEFAULT_WORKER_MB: f64 = 64.0;
/// Floor for a mod_php Apache worker: an idle worker is small, but one that
/// is serving PHP grows to tens of MB, so an idle average underestimates it.
const MOD_PHP_WORKER_FLOOR_MB: f64 = 64.0;

struct FpmMaster {
    branch: Option<(u8, u8)>,
    conf: PathBuf,
    pools: Vec<Pool>,
    workers: Vec<u64>,
    ini: BTreeMap<String, String>,
}

fn fpm_masters(inp: &Inputs) -> Vec<FpmMaster> {
    let re = Regex::new(r"master process \(([^)]+)\)").unwrap();
    let mut out = Vec::new();
    for m in inp
        .procs
        .iter()
        .filter(|p| p.cmdline.starts_with("php-fpm: master"))
    {
        let Some(c) = re.captures(&m.cmdline) else {
            continue;
        };
        let conf = PathBuf::from(&c[1]);
        let hay = format!(
            "{} {}",
            conf.display(),
            m.exe
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
        let dir = conf.parent().unwrap_or(Path::new("/")).to_path_buf();
        let parent = dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| dir.clone());
        out.push(FpmMaster {
            branch: parse_branch(&hay),
            pools: parse_fpm_conf(&conf),
            workers: inp
                .procs
                .iter()
                .filter(|p| p.ppid == m.pid && p.cmdline.starts_with("php-fpm: pool"))
                .map(|p| p.pss_kb)
                .collect(),
            ini: read_ini_set(&[dir, parent]),
            conf,
        });
    }
    out.sort_by(|a, b| a.branch.cmp(&b.branch).then_with(|| a.conf.cmp(&b.conf)));
    out
}

pub fn evaluate(inp: &Inputs) -> Vec<Check> {
    let mut v: Vec<Check> = Vec::new();
    let masters = fpm_masters(inp);
    let apache = apache_info(&inp.fs_root);
    let label = |b: Option<(u8, u8)>| {
        b.map(|(a, c)| format!("{a}.{c}"))
            .unwrap_or_else(|| "?".into())
    };

    // --- PHP-FPM -----------------------------------------------------------
    for m in &masters {
        let name = format!("PHP {} (FPM)", label(m.branch));
        let total_children: u32 = m.pools.iter().filter_map(|p| p.max_children).sum();
        let avg_mb = if m.workers.is_empty() {
            None
        } else {
            Some(m.workers.iter().sum::<u64>() as f64 / m.workers.len() as f64 / 1024.0)
        };
        v.push(Check {
            group: "PHP",
            name: name.clone(),
            status: Status::Info,
            detail: format!(
                "{} pools, up to {} processes, {} active{}; configuration {}",
                m.pools.len(),
                total_children,
                m.workers.len(),
                avg_mb
                    .map(|a| format!(" (~{} each)", fmt_mb(a)))
                    .unwrap_or_default(),
                util::path_display(&m.conf)
            ),
            fix: None,
        });

        if let Some(b) = m.branch {
            v.push(support_check(&name, b, inp.today));
        }

        // session.upload_progress.enabled per pool.
        let global = m
            .ini
            .get("session.upload_progress.enabled")
            .map(String::as_str)
            .unwrap_or("1");
        let pools_on: Vec<&Pool> = m
            .pools
            .iter()
            .filter(|p| {
                truthy(
                    p.settings
                        .get("session.upload_progress.enabled")
                        .map(String::as_str)
                        .unwrap_or(global),
                )
            })
            .collect();
        if !m.pools.is_empty() {
            v.push(upload_progress_check(&name, pools_on.len(), m.pools.len()));
        }
    }
    if masters.is_empty() && !inp.procs.is_empty() {
        v.push(Check {
            group: "PHP",
            name: "PHP-FPM".into(),
            status: Status::Info,
            detail: "no php-fpm processes running (or they cannot be seen without root)".into(),
            fix: None,
        });
    }

    // --- Apache mod_php ----------------------------------------------------
    if let Some(a) = &apache {
        for ver in &a.mod_php {
            let branch = parse_branch(&format!("php{ver}"));
            let name = format!("PHP {} (mod_php)", label(branch));
            if let Some(b) = branch {
                v.push(support_check(&name, b, inp.today));
            }
            let dir = crate::panel::rebase(&inp.fs_root, &format!("/etc/php/{ver}/apache2"));
            let ini = read_ini_set(&[dir]);
            let on = truthy(
                ini.get("session.upload_progress.enabled")
                    .map(String::as_str)
                    .unwrap_or("1"),
            );
            v.push(upload_progress_check(&name, on as usize, 1));
        }
    }

    // --- Apache ------------------------------------------------------------
    let apache_procs: Vec<&ProcInfo> = inp
        .procs
        .iter()
        .filter(|p| p.comm == "apache2" || p.comm == "httpd")
        .collect();
    if let Some(a) = &apache {
        let pids: BTreeSet<u32> = apache_procs.iter().map(|p| p.pid).collect();
        let workers: Vec<&&ProcInfo> = apache_procs
            .iter()
            .filter(|p| pids.contains(&p.ppid))
            .collect();
        let avg = if workers.is_empty() {
            None
        } else {
            Some(
                workers.iter().map(|p| p.pss_kb).sum::<u64>() as f64
                    / workers.len() as f64
                    / 1024.0,
            )
        };
        let mut notes = Vec::new();
        if let Some(m) = &a.mpm {
            notes.push(format!("MPM {m}"));
        }
        if !a.mod_php.is_empty() {
            notes.push("with mod_php (every Apache process carries PHP inside)".into());
        }
        if let Some(n) = a.max_workers {
            notes.push(format!("up to {n} processes"));
        }
        notes.push(format!("{} running", workers.len()));
        if let Some(av) = avg {
            notes.push(format!("~{} each", fmt_mb(av)));
        }
        v.push(Check {
            group: "Memory",
            name: "Apache".into(),
            status: Status::Info,
            detail: notes.join(", "),
            fix: None,
        });
    }

    // --- Capacity ----------------------------------------------------------
    let mut parts: Vec<(String, f64)> = Vec::new();
    if let Some(a) = &apache
        && let Some(max) = a.max_workers
    {
        let pids: BTreeSet<u32> = apache_procs.iter().map(|p| p.pid).collect();
        let w: Vec<f64> = apache_procs
            .iter()
            .filter(|p| pids.contains(&p.ppid))
            .map(|p| p.pss_kb as f64 / 1024.0)
            .collect();
        let mut avg = if w.is_empty() {
            DEFAULT_WORKER_MB
        } else {
            w.iter().sum::<f64>() / w.len() as f64
        };
        if !a.mod_php.is_empty() {
            // With mod_php every worker can grow like a PHP process.
            let seen_max = w.iter().cloned().fold(0.0, f64::max);
            avg = avg.max(seen_max).max(MOD_PHP_WORKER_FLOOR_MB);
        }
        parts.push((format!("Apache {max} × {}", fmt_mb(avg)), max as f64 * avg));
    }
    for m in &masters {
        let total: u32 = m.pools.iter().filter_map(|p| p.max_children).sum();
        if total == 0 {
            continue;
        }
        let avg = if m.workers.is_empty() {
            DEFAULT_WORKER_MB
        } else {
            m.workers.iter().sum::<u64>() as f64 / m.workers.len() as f64 / 1024.0
        };
        parts.push((
            format!("PHP {} {total} × {}", label(m.branch), fmt_mb(avg)),
            total as f64 * avg,
        ));
    }
    let db_mb: f64 = inp
        .procs
        .iter()
        .filter(|p| matches!(p.comm.as_str(), "mariadbd" | "mysqld" | "mysqld_safe"))
        .map(|p| p.pss_kb as f64 / 1024.0)
        .sum();
    if db_mb > 0.0 {
        parts.push((format!("database {}", fmt_mb(db_mb)), db_mb));
    }
    if !parts.is_empty() && inp.mem_total_mb > 0.0 {
        let worst: f64 = parts.iter().map(|(_, m)| m).sum();
        let ratio = worst / inp.mem_total_mb;
        let detail = format!(
            "worst case ~ {} against {} of RAM ({:.0}%): {}",
            fmt_mb(worst),
            fmt_mb(inp.mem_total_mb),
            ratio * 100.0,
            parts
                .iter()
                .map(|(n, m)| format!("{n} = {}", fmt_mb(*m)))
                .collect::<Vec<_>>()
                .join(" + ")
        );
        let (status, fix) = if ratio >= 1.0 {
            (
                Status::Warn,
                Some(
                    "If every process fills up at once, the kernel kills processes (sometimes MariaDB, even if it is not the culprit). \
                     Lower MaxRequestWorkers / pm.max_children, or move from mod_php to per-site PHP-FPM."
                        .to_string(),
                ),
            )
        } else if ratio >= 0.8 {
            (
                Status::Warn,
                Some("Narrow margin: any spike can exhaust memory.".to_string()),
            )
        } else {
            (Status::Ok, None)
        };
        v.push(Check {
            group: "Memory",
            name: "Capacity (worst case)".into(),
            status,
            detail,
            fix,
        });
    }
    v
}

fn support_check(name: &str, b: (u8, u8), today: (i64, u32, u32)) -> Check {
    let g = "PHP";
    let n = format!("{name}: support");
    match support(b, today) {
        Support::Ended(d) => Check {
            group: g,
            name: n,
            status: Status::Fail,
            detail: format!(
                "PHP {}.{} is running and no longer receives security fixes{}",
                b.0,
                b.1,
                d.map(|d| format!(" (since {})", date_s(d))).unwrap_or_default()
            ),
            fix: Some(
                "Disable that service or migrate the sites to a supported branch. If a panel re-enables it by itself, check the panel services.".into(),
            ),
        },
        Support::EndsSoon(days, d) => Check {
            group: g,
            name: n,
            status: Status::Warn,
            detail: format!("PHP {}.{}: security support ends on {} (in {days} days)", b.0, b.1, date_s(d)),
            fix: Some("Plan the migration to a newer branch.".into()),
        },
        Support::Supported(d) => Check {
            group: g,
            name: n,
            status: Status::Ok,
            detail: format!("security fixes until {}", date_s(d)),
            fix: None,
        },
        Support::Unknown => Check {
            group: g,
            name: n,
            status: Status::Info,
            detail: format!("PHP {}.{}: branch unknown to PWSS; check php.net/supported-versions", b.0, b.1),
            fix: None,
        },
    }
}

fn upload_progress_check(name: &str, on: usize, total: usize) -> Check {
    let n = format!("{name}: session.upload_progress");
    if on == 0 {
        return Check {
            group: "PHP",
            name: n,
            status: Status::Ok,
            detail: "session.upload_progress.enabled is off".into(),
            fix: None,
        };
    }
    Check {
        group: "PHP",
        name: n,
        status: Status::Warn,
        detail: format!(
            "session.upload_progress.enabled is on in {on} of {total} pools. PHP recommends turning it off (CVE-2026-115560, advisory of 2026-10-23) until the next release; the affected versions have not been published"
        ),
        fix: Some(
            "In each pool: php_admin_value[session.upload_progress.enabled] = 0. Keeping it on is only safe if no application changes session.serialize_handler at runtime. A panel may overwrite these files: check that the change persists.".into(),
        ),
    }
}

pub fn run(fs_root: &Path, proc_root: &Path, live: bool) -> Vec<Check> {
    if !live {
        return Vec::new();
    }
    let procs = read_procs(proc_root);
    let mem_total_mb = std::fs::read_to_string(proc_root.join("meminfo"))
        .ok()
        .and_then(|t| kb_field(&t, "MemTotal:"))
        .map(|kb| kb as f64 / 1024.0)
        .unwrap_or(0.0);
    let (y, m, d, _, _) = util::civil(util::now_secs());
    evaluate(&Inputs {
        procs,
        fs_root: fs_root.to_path_buf(),
        mem_total_mb,
        today: (y, m, d),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const TODAY: (i64, u32, u32) = (2026, 11, 5);

    #[test]
    fn branches_from_paths() {
        for (s, b) in [
            ("/etc/php/8.3/fpm/php-fpm.conf", (8, 3)),
            ("/opt/php84/etc/php-fpm.conf", (8, 4)),
            ("/usr/sbin/php-fpm8.5", (8, 5)),
            ("fp2-php74-fpm", (7, 4)),
            ("/usr/local/fastpanel2/php-7.4/sbin/php-fpm", (7, 4)),
        ] {
            assert_eq!(parse_branch(s), Some(b), "{s}");
        }
        assert_eq!(parse_branch("/etc/nginx/nginx.conf"), None);
    }

    #[test]
    fn support_dates() {
        assert!(matches!(
            support((7, 4), TODAY),
            Support::Ended(Some((2022, 11, 28)))
        ));
        assert!(matches!(
            support((8, 1), TODAY),
            Support::Ended(Some((2025, 12, 31)))
        ));
        assert!(matches!(
            support((8, 2), TODAY),
            Support::EndsSoon(56, (2026, 12, 31))
        ));
        assert!(matches!(support((8, 3), TODAY), Support::Supported(_)));
        assert!(matches!(support((5, 6), TODAY), Support::Ended(None)));
        assert_eq!(support((9, 9), TODAY), Support::Unknown);
    }

    #[test]
    fn ini_and_truthy() {
        let m = parse_ini(
            "; c\n[PHP]\nsession.upload_progress.enabled = Off ; x\nmemory_limit=\"256M\"\n",
        );
        assert_eq!(m["session.upload_progress.enabled"], "Off");
        assert_eq!(m["memory_limit"], "256M");
        assert!(!truthy("Off") && !truthy("0") && !truthy("") && truthy("1") && truthy("On"));
    }

    fn fpm_tree(upload: Option<&str>) -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("etc/php/8.3/fpm");
        fs::create_dir_all(d.join("pool.d")).unwrap();
        fs::write(
            d.join("php-fpm.conf"),
            format!(
                "[global]\npid=/run/x.pid\ninclude={}/pool.d/*.conf\n",
                d.display()
            ),
        )
        .unwrap();
        let extra = upload
            .map(|u| format!("php_admin_value[session.upload_progress.enabled] = {u}\n"))
            .unwrap_or_default();
        fs::write(
            d.join("pool.d/a.conf"),
            format!("[a]\npm = dynamic\npm.max_children = 20\n{extra}"),
        )
        .unwrap();
        fs::write(d.join("pool.d/b.conf"), "[b]\npm.max_children = 10\n").unwrap();
        fs::write(d.join("php.ini"), "session.upload_progress.enabled = 1\n").unwrap();
        let conf = d.join("php-fpm.conf");
        (t, conf)
    }

    #[test]
    fn fpm_conf_with_includes_and_overrides() {
        let (_t, conf) = fpm_tree(Some("0"));
        let pools = parse_fpm_conf(&conf);
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].max_children, Some(20));
        assert_eq!(pools[0].settings["session.upload_progress.enabled"], "0");
        assert!(pools[1].settings.is_empty());
    }

    fn proc(pid: u32, ppid: u32, comm: &str, cmdline: &str, mb: u64) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            comm: comm.into(),
            cmdline: cmdline.into(),
            exe: None,
            pss_kb: mb * 1024,
        }
    }

    #[test]
    fn evaluates_php_and_capacity() {
        let (t, conf) = fpm_tree(Some("0"));
        let mut procs = vec![
            proc(
                10,
                1,
                "php-fpm8.3",
                &format!("php-fpm: master process ({})", conf.display()),
                20,
            ),
            proc(11, 10, "php-fpm8.3", "php-fpm: pool a", 80),
            proc(12, 10, "php-fpm8.3", "php-fpm: pool b", 120),
            proc(20, 1, "mariadbd", "/usr/sbin/mariadbd", 1000),
        ];
        // Apache prefork with at most 150 workers and 4 running at 100 MB each.
        let ap = t.path().join("etc/apache2/mods-enabled");
        fs::create_dir_all(&ap).unwrap();
        fs::write(ap.join("mpm_itk.load"), "LoadModule mpm_itk_module x\n").unwrap();
        fs::write(
            ap.join("mpm_prefork.conf"),
            "<IfModule mpm_prefork_module>\n  MaxRequestWorkers 150\n</IfModule>\n",
        )
        .unwrap();
        fs::write(ap.join("php8.3.load"), "LoadModule php_module x\n").unwrap();
        procs.push(proc(30, 1, "apache2", "/usr/sbin/apache2", 10));
        for i in 0..4 {
            procs.push(proc(31 + i, 30, "apache2", "/usr/sbin/apache2", 100));
        }
        let checks = evaluate(&Inputs {
            procs,
            fs_root: t.path().to_path_buf(),
            mem_total_mb: 24.0 * 1024.0,
            today: TODAY,
        });
        let get = |n: &str| {
            checks
                .iter()
                .find(|c| c.name.contains(n))
                .unwrap_or_else(|| panic!("missing {n}: {checks:#?}"))
        };

        let fpm = get("PHP 8.3 (FPM)");
        assert!(
            fpm.detail.contains("2 pools") && fpm.detail.contains("up to 30"),
            "{}",
            fpm.detail
        );
        // Pool "a" turns it off; pool "b" inherits php.ini (on).
        let up = checks
            .iter()
            .find(|c| c.name == "PHP 8.3 (FPM): session.upload_progress")
            .unwrap();
        assert_eq!(up.status, Status::Warn);
        assert!(up.detail.contains("1 of 2"), "{}", up.detail);
        assert!(up.detail.contains("CVE-2026-115560"));

        // mod_php: no php.ini -> default value, on.
        assert!(
            checks
                .iter()
                .any(|c| c.name == "PHP 8.3 (mod_php): session.upload_progress"
                    && c.status == Status::Warn)
        );

        let ap = get("Apache");
        assert!(
            ap.detail.contains("MPM itk")
                && ap.detail.contains("mod_php")
                && ap.detail.contains("up to 150"),
            "{}",
            ap.detail
        );

        // Worst case: 150x100 MB (14.6 GB) + 30x100 MB (2.9 GB) + 1000 MB (~1 GB) ~ 18.5 GB of 24 GB = 77%.
        let cap = get("Capacity");
        assert!(cap.detail.contains("Apache 150 × 100 MB"), "{}", cap.detail);
        assert!(cap.detail.contains("PHP 8.3 30 × 100 MB"), "{}", cap.detail);
        assert_eq!(cap.status, Status::Ok, "{}", cap.detail);
    }

    #[test]
    fn capacity_warns_when_worst_case_exceeds_ram() {
        let t = tempfile::tempdir().unwrap();
        let ap = t.path().join("etc/apache2/mods-enabled");
        fs::create_dir_all(&ap).unwrap();
        fs::write(ap.join("mpm_prefork.load"), "x").unwrap();
        fs::write(ap.join("mpm_prefork.conf"), "MaxRequestWorkers 150\n").unwrap();
        let mut procs = vec![proc(30, 1, "apache2", "/usr/sbin/apache2", 10)];
        for i in 0..160 {
            procs.push(proc(31 + i, 30, "apache2", "/usr/sbin/apache2", 93));
        }
        let c = evaluate(&Inputs {
            procs,
            fs_root: t.path().to_path_buf(),
            mem_total_mb: 8.0 * 1024.0,
            today: TODAY,
        });
        let cap = c.iter().find(|c| c.name.contains("Capacity")).unwrap();
        assert_eq!(cap.status, Status::Warn);
        assert!(cap.fix.as_deref().unwrap().contains("PHP-FPM"));
    }

    #[test]
    fn eol_php_running_is_fail() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("opt/php74/etc");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("php-fpm.conf"), "[www]\npm.max_children=5\n").unwrap();
        let procs = vec![proc(
            10,
            1,
            "php-fpm",
            &format!("php-fpm: master process ({}/php-fpm.conf)", d.display()),
            20,
        )];
        let c = evaluate(&Inputs {
            procs,
            fs_root: t.path().to_path_buf(),
            mem_total_mb: 1000.0,
            today: TODAY,
        });
        let s = c.iter().find(|c| c.name.contains("support")).unwrap();
        assert_eq!(s.status, Status::Fail);
        assert!(s.detail.contains("2022-11-28"));
    }

    #[test]
    fn reads_fake_proc_tree() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("1234");
        fs::create_dir_all(&p).unwrap();
        fs::write(
            p.join("status"),
            "Name:\tapache2\nPPid:\t1\nVmRSS:\t  2048 kB\n",
        )
        .unwrap();
        fs::write(p.join("smaps_rollup"), "Pss:                1024 kB\n").unwrap();
        fs::write(p.join("cmdline"), b"/usr/sbin/apache2\0-k\0start\0").unwrap();
        fs::write(t.path().join("meminfo"), "MemTotal:       24000000 kB\n").unwrap();
        let v = read_procs(t.path());
        assert_eq!(v.len(), 1);
        assert_eq!(
            (v[0].pid, v[0].ppid, v[0].comm.as_str(), v[0].pss_kb),
            (1234, 1, "apache2", 1024)
        );
        assert_eq!(v[0].cmdline, "/usr/sbin/apache2 -k start");
    }
}
