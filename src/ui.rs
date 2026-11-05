// SPDX-License-Identifier: GPL-3.0-or-later
//! Human-readable output.

use crate::discovery::{Discovery, Site};
use crate::doctor::{Report, Status};
use std::io::IsTerminal;

fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(code: &str, s: &str) -> String {
    if color() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn print_sites(d: &Discovery, verbose: bool) {
    println!(
        "{} {} WordPress installations in {}",
        paint("1", "PWSS"),
        d.sites.len(),
        d.roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();
    let w = d
        .sites
        .iter()
        .map(|s| s.display_name().chars().count())
        .max()
        .unwrap_or(10)
        .clamp(10, 40);
    println!(
        "{:<3} {:<w$}  {:<8}  {:<18}  {:<22}  Warnings",
        "#",
        "Site",
        "Version",
        "Layout",
        "Database",
        w = w
    );
    for (i, s) in d.sites.iter().enumerate() {
        let db = match (&s.db_name, &s.table_prefix) {
            (Some(n), Some(p)) => format!("{n} ({p})"),
            (Some(n), None) => format!("{n} (prefix?)"),
            _ => "—".into(),
        };
        let mut layout = s.layout.label().to_string();
        if s.nested_in.is_some() {
            layout.push_str(", nested");
        }
        if s.git_repo.is_some() {
            layout.push_str(", git");
        }
        let warn = if s.warnings.is_empty() {
            paint("32", "—")
        } else {
            paint("33", &s.warnings.len().to_string())
        };
        println!(
            "{:<3} {:<w$}  {:<8}  {:<18}  {:<22}  {}",
            i + 1,
            truncate(&s.display_name(), w),
            s.version.as_deref().unwrap_or("?"),
            layout,
            truncate(&db, 22),
            warn,
            w = w
        );
        if verbose {
            print_site_detail(s);
        }
    }
    if verbose && !d.orphan_configs.is_empty() {
        println!();
        println!("wp-config.php without an associated WordPress:");
        for c in &d.orphan_configs {
            println!("  {}", c.display());
        }
    }
    if !verbose {
        println!();
        println!("Per-site detail: pwss sites --verbose   |   For scripts: pwss sites --json");
    }
}

fn print_site_detail(s: &Site) {
    let dim = |t: &str| paint("2", t);
    println!("    {} {}", dim("core:     "), s.core_dir.display());
    if s.web_root != s.core_dir {
        println!("    {} {}", dim("web:      "), s.web_root.display());
    }
    println!("    {} {}", dim("plugins:  "), s.plugins_dir.display());
    if let Some(o) = &s.owner {
        println!("    {} {}", dim("user:     "), o);
    }
    for (i, f) in s.config_files.iter().enumerate() {
        let label = if i == 0 { "config:   " } else { "  includes:" };
        println!("    {} {}", dim(label), f.display());
    }
    if let Some(n) = &s.nested_in {
        println!("    {} {}", dim("inside:   "), n.display());
    }
    for w in &s.warnings {
        println!("    {} {}", paint("33", "warning:  "), w);
    }
    println!();
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

pub fn print_doctor(r: &Report) {
    let mut group = "";
    for c in &r.checks {
        if c.group != group {
            group = c.group;
            println!();
            println!("{}", paint("1", group));
        }
        let mark = match c.status {
            Status::Ok => paint("32", "  OK   "),
            Status::Warn => paint("33", "  WARN "),
            Status::Fail => paint("31", "  FAIL "),
            Status::Info => paint("36", "  INFO "),
        };
        println!("{mark}  {}: {}", c.name, c.detail);
        if let Some(f) = &c.fix {
            println!("         → {f}");
        }
    }
    println!();
    let fails = r.checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = r.checks.iter().filter(|c| c.status == Status::Warn).count();
    if fails == 0 {
        println!(
            "{} Compatible server ({} warnings).",
            paint("32", "✔"),
            warns
        );
    } else {
        println!(
            "{} {fails} failed checks: review the items marked FAIL.",
            paint("31", "✘")
        );
    }
}

// ---------------------------------------------------------------------------
// pwss scan
// ---------------------------------------------------------------------------

use crate::scan::rules::Severity;
use crate::scan::{Finding, Report as ScanReport};
use crate::util;

fn sev_paint(s: Severity) -> String {
    let label = format!("{:<8}", s.label().to_uppercase());
    match s {
        Severity::Critical => paint("1;31", &label),
        Severity::High => paint("31", &label),
        Severity::Medium => paint("33", &label),
        Severity::Low => paint("36", &label),
        Severity::Info => paint("2", &label),
    }
}

pub fn print_scan(r: &ScanReport) {
    let st = &r.stats;
    println!(
        "{} {} scan · {} sites · {} files checked · {} analysed ({}) · {:.1} s",
        paint("1", "PWSS"),
        if r.deep { "deep" } else { "normal" },
        st.sites,
        st.files,
        st.analysed,
        util::fmt_size(st.bytes_read),
        st.elapsed_ms as f64 / 1000.0
    );
    if st.unreadable > 0 {
        println!(
            "{}",
            paint(
                "33",
                &format!(
                    "warning: {} folders or files could not be read (run with sudo)",
                    st.unreadable
                )
            )
        );
    }
    println!();

    if r.findings.is_empty() {
        println!(
            "{} No findings of severity {} or higher.",
            paint("32", "✔"),
            r.min_severity.label()
        );
        if r.hidden_below_min > 0 {
            println!(
                "  ({} minor findings hidden: use --min-severity low to see them)",
                r.hidden_below_min
            );
        }
        if !r.deep {
            println!("  A normal scan only checks persistence zones; --deep analyses all PHP.");
        }
        return;
    }

    // Group by site, most severe first.
    let mut sites: Vec<(String, Vec<&Finding>)> = Vec::new();
    for f in &r.findings {
        match sites.iter_mut().find(|(n, _)| *n == f.site) {
            Some((_, v)) => v.push(f),
            None => sites.push((f.site.clone(), vec![f])),
        }
    }
    for (name, list) in &sites {
        let mut counts: Vec<String> = Vec::new();
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let n = list.iter().filter(|f| f.severity == s).count();
            if n > 0 {
                counts.push(format!("{n} {}", s.label()));
            }
        }
        println!(
            "{} {}   {}",
            paint("1", "▌"),
            paint("1", name),
            paint("2", &counts.join(" · "))
        );
        for f in list {
            println!(
                "  {} {}",
                sev_paint(f.severity),
                util::path_display(&f.path)
            );
            let mut meta: Vec<String> = Vec::new();
            if let Some(m) = f.modified {
                meta.push(format!("modified {}", util::fmt_ts(m)));
            }
            if f.size > 0 {
                meta.push(util::fmt_size(f.size));
            }
            if let Some(h) = &f.sha256 {
                meta.push(format!("sha256 {}...", &h[..16]));
            }
            if !meta.is_empty() {
                println!("          {}", paint("2", &meta.join(" · ")));
            }
            for h in &f.reasons {
                println!(
                    "          · {} {}",
                    util::sanitize(&h.message),
                    paint("2", &format!("[{}]", h.rule))
                );
                if let Some(e) = &h.evidence {
                    println!("              {} {}", paint("2", "»"), paint("2", e));
                }
            }
        }
        println!();
    }

    let total = r.findings.len();
    let summary: Vec<String> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .iter()
    .filter_map(|s| {
        let n = r.count(*s);
        (n > 0).then(|| format!("{n} {}", s.label()))
    })
    .collect();
    println!(
        "{} {} files with findings ({}).",
        paint("1", "Summary:"),
        total,
        summary.join(", ")
    );
    if r.hidden_below_min > 0 {
        println!(
            "  {} minor findings hidden (--min-severity low to see them).",
            r.hidden_below_min
        );
    }
    println!("  Review every file before deleting anything: PWSS never modifies or moves files.");
    println!(
        "  To accept a legitimate file, add its sha256 to [scan] allow_sha256 in the configuration."
    );
}

// ---------------------------------------------------------------------------
// pwss hunt
// ---------------------------------------------------------------------------

pub fn print_hunt(r: &crate::hunt::Report) {
    let st = &r.stats;
    println!(
        "{} search · {} folders · {} files walked · {} read ({}) · {:.1} s",
        paint("1", "PWSS"),
        st.roots,
        st.files,
        st.read,
        util::fmt_size(st.bytes_read),
        st.elapsed_ms as f64 / 1000.0
    );
    if st.skipped_large > 0 {
        println!(
            "  {} files larger than the limit were not read (--max-size).",
            st.skipped_large
        );
    }
    if st.unreadable > 0 {
        println!(
            "{}",
            paint(
                "33",
                &format!(
                    "warning: {} could not be read (run with sudo)",
                    st.unreadable
                )
            )
        );
    }
    println!();
    if r.matches.is_empty() {
        println!("{} No matches.", paint("32", "✔"));
        return;
    }
    let mut last = "";
    for m in &r.matches {
        if m.site != last {
            println!("{} {}", paint("1", "▌"), paint("1", &m.site));
            last = &m.site;
        }
        println!("  {}", util::path_display(&m.path));
        let mut meta = vec![
            format!("modified {}", util::fmt_ts(m.modified)),
            util::fmt_size(m.size),
        ];
        if let Some(h) = &m.sha256 {
            meta.push(format!("sha256 {}...", &h[..16]));
        }
        println!("      {}", paint("2", &meta.join(" · ")));
        println!("      matches: {}", m.matched.join(", "));
        if let Some(e) = &m.evidence {
            println!("      {} {}", paint("2", "»"), paint("2", e));
        }
    }
    println!();
    println!(
        "{} {} files in {} sites.",
        paint("1", "Summary:"),
        r.matches.len(),
        {
            let mut s: Vec<&str> = r.matches.iter().map(|m| m.site.as_str()).collect();
            s.dedup();
            s.len()
        }
    );
}
