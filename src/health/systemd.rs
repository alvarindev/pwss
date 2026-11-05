// SPDX-License-Identifier: GPL-3.0-or-later
//! Checks based on systemd and the kernel journal.
//!
//! * units in `failed` state (in the incident, `maldet.service` had been
//!   failing without anyone noticing);
//! * processes killed for lack of memory (OOM);
//! * enabled services that were not in the baseline.

use crate::doctor::{Check, Status};
use crate::util;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const G: &str = "Services";

/// Failed units from `systemctl --failed --plain --no-legend`.
pub fn parse_failed(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim_start_matches(|c: char| c == '●' || c == '*' || c.is_whitespace());
            let unit = t.split_whitespace().next()?;
            let ok = [
                ".service", ".timer", ".socket", ".mount", ".path", ".target",
            ]
            .iter()
            .any(|s| unit.ends_with(s));
            ok.then(|| unit.to_string())
        })
        .collect()
}

/// Enabled units from `systemctl list-unit-files --state=enabled`.
pub fn parse_enabled(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let unit = it.next()?;
            let state = it.next()?;
            (state.starts_with("enabled") && unit.contains('.')).then(|| unit.to_string())
        })
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct OomSummary {
    pub total: usize,
    pub by_process: BTreeMap<String, usize>,
    pub first: Option<String>,
    pub last: Option<String>,
}

/// Processes killed by the OOM killer from `journalctl -k -o short-iso`.
pub fn parse_oom(text: &str) -> OomSummary {
    let re = Regex::new(r"Killed process \d+ \(([^)]+)\)").unwrap();
    let mut s = OomSummary::default();
    for line in text.lines() {
        let Some(c) = re.captures(line) else { continue };
        s.total += 1;
        *s.by_process.entry(util::sanitize(&c[1])).or_insert(0) += 1;
        let ts: String = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .chars()
            .take(16)
            .collect();
        if ts.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            let ts = ts.replace('T', " ");
            if s.first.is_none() {
                s.first = Some(ts.clone());
            }
            s.last = Some(ts);
        }
    }
    s
}

pub fn failed_units() -> Option<Vec<String>> {
    let o = util::run_cmd(
        "systemctl",
        &["--failed", "--plain", "--no-legend", "--no-pager"],
        Duration::from_secs(15),
    )?;
    if !o.ok && o.stdout.is_empty() {
        return None; // no systemd, or no permission
    }
    Some(parse_failed(&o.stdout))
}

pub fn enabled_units() -> Option<BTreeSet<String>> {
    let o = util::run_cmd(
        "systemctl",
        &[
            "list-unit-files",
            "--type=service,timer",
            "--state=enabled",
            "--plain",
            "--no-legend",
            "--no-pager",
        ],
        Duration::from_secs(20),
    )?;
    if !o.ok {
        return None;
    }
    Some(parse_enabled(&o.stdout))
}

/// `None` = the kernel journal could not be read.
pub fn oom_events(days: u32) -> Option<OomSummary> {
    let since = format!("{days} days ago");
    let o = util::run_cmd(
        "journalctl",
        &[
            "-k",
            "--no-pager",
            "-q",
            "-o",
            "short-iso",
            "--since",
            &since,
            "-g",
            "Killed process",
        ],
        Duration::from_secs(40),
    )?;
    if !o.stdout.trim().is_empty() {
        return Some(parse_oom(&o.stdout));
    }
    let e = o.stderr.to_lowercase();
    if e.contains("unrecognized option") || e.contains("invalid option") {
        let o = util::run_cmd(
            "journalctl",
            &[
                "-k",
                "--no-pager",
                "-q",
                "-o",
                "short-iso",
                "--since",
                &since,
            ],
            Duration::from_secs(60),
        )?;
        return Some(parse_oom(&o.stdout));
    }
    if e.contains("permission")
        || e.contains("not seen")
        || e.contains("no journal")
        || e.contains("failed to")
    {
        return None;
    }
    Some(OomSummary::default())
}

pub fn run(live: bool) -> Vec<Check> {
    let mut v = Vec::new();
    if !live {
        return v;
    }

    if let Some(failed) = failed_units() {
        if failed.is_empty() {
            v.push(Check {
                group: G,
                name: "Failed units".into(),
                status: Status::Ok,
                detail: "none".into(),
                fix: None,
            });
        } else {
            v.push(Check {
                group: G,
                name: "Failed units".into(),
                status: Status::Warn,
                detail: format!("{}: {}", failed.len(), util::sanitize(&failed.join(", "))),
                fix: Some(
                    "Inspect each one with `systemctl status <unit>` and `journalctl -u <unit>`."
                        .into(),
                ),
            });
        }
    }

    match oom_events(30) {
        Some(o) if o.total == 0 => v.push(Check {
            group: G,
            name: "Out of memory (OOM)".into(),
            status: Status::Ok,
            detail: "no process killed in the last 30 days".into(),
            fix: None,
        }),
        Some(o) => {
            let mut procs: Vec<(&String, &usize)> = o.by_process.iter().collect();
            procs.sort_by(|a, b| b.1.cmp(a.1));
            let list: Vec<String> = procs
                .iter()
                .take(6)
                .map(|(n, c)| format!("{n} ×{c}"))
                .collect();
            v.push(Check {
                group: G,
                name: "Out of memory (OOM)".into(),
                status: Status::Warn,
                detail: format!(
                    "{} processes killed by the kernel in 30 days ({}); last: {}",
                    o.total,
                    list.join(", "),
                    o.last.as_deref().unwrap_or("?")
                ),
                fix: Some(
                    "The process that dies is not necessarily the one using the memory. See the memory capacity check.".into(),
                ),
            });
        }
        None => v.push(Check {
            group: G,
            name: "Out of memory (OOM)".into(),
            status: Status::Info,
            detail: "could not read the kernel journal (not root?)".into(),
            fix: None,
        }),
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_units() {
        let t = "● maldet.service loaded failed failed Linux Malware Detect\n  fastpanel2-apps.service loaded failed failed X\n";
        assert_eq!(
            parse_failed(t),
            vec!["maldet.service", "fastpanel2-apps.service"]
        );
        assert!(parse_failed("").is_empty());
        assert!(parse_failed("0 loaded units listed.").is_empty());
    }

    #[test]
    fn parses_enabled_units() {
        let t = "nginx.service enabled enabled\nmaldet.timer enabled-runtime disabled\nfoo.service disabled enabled\n";
        let e = parse_enabled(t);
        assert!(e.contains("nginx.service") && e.contains("maldet.timer"));
        assert!(!e.contains("foo.service"));
    }

    #[test]
    fn parses_oom_journal() {
        let t = "\
2026-11-04T03:12:01+0100 srv kernel: Out of memory: Killed process 1584 (mariadbd) total-vm:9000kB, anon-rss:1kB
2026-11-04T03:12:09+0100 srv kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null)
2026-11-04T05:50:11+0100 srv kernel: Out of memory: Killed process 77 (apache2) total-vm:1kB
2026-11-04T05:51:00+0100 srv kernel: Out of memory: Killed process 78 (apache2) total-vm:1kB
";
        let o = parse_oom(t);
        assert_eq!(o.total, 3);
        assert_eq!(o.by_process["apache2"], 2);
        assert_eq!(o.by_process["mariadbd"], 1);
        assert_eq!(o.first.as_deref(), Some("2026-11-04 03:12"));
        assert_eq!(o.last.as_deref(), Some("2026-11-04 05:51"));
        assert_eq!(parse_oom(""), OomSummary::default());
    }
}
