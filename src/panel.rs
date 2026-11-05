// SPDX-License-Identifier: GPL-3.0-or-later
//! Hosting panel detection and the paths where sites usually live.
//!
//! The panel only provides default paths. The real discovery is generic (it
//! looks for the WordPress core), so a hand-configured server or a panel not
//! listed here works the same way: just give the paths.

use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Panel {
    FastPanel,
    Plesk,
    CPanel,
    HestiaCp,
    CloudPanel,
    AaPanel,
    Ispconfig,
    RunCloud,
    None,
}

impl Panel {
    pub fn name(self) -> &'static str {
        match self {
            Panel::FastPanel => "FastPanel",
            Panel::Plesk => "Plesk",
            Panel::CPanel => "cPanel",
            Panel::HestiaCp => "HestiaCP",
            Panel::CloudPanel => "CloudPanel",
            Panel::AaPanel => "aaPanel",
            Panel::Ispconfig => "ISPConfig",
            Panel::RunCloud => "RunCloud",
            Panel::None => "none (manually configured server)",
        }
    }

    /// Typical site path patterns. `*` stands for any single level.
    pub fn site_patterns(self) -> &'static [&'static str] {
        match self {
            Panel::FastPanel => &["/var/www/*/data/www"],
            Panel::Plesk => &["/var/www/vhosts"],
            Panel::CPanel => &["/home/*/public_html", "/home/*"],
            Panel::HestiaCp => &["/home/*/web"],
            Panel::CloudPanel => &["/home/*/htdocs"],
            Panel::AaPanel => &["/www/wwwroot"],
            Panel::Ispconfig => &["/var/www/clients"],
            Panel::RunCloud => &["/home/*/webapps"],
            Panel::None => &[],
        }
    }
}

/// On-disk markers of each panel.
const MARKERS: &[(Panel, &[&str])] = &[
    (
        Panel::FastPanel,
        &["/usr/local/fastpanel2", "/usr/local/fastpanel"],
    ),
    (Panel::Plesk, &["/usr/local/psa", "/opt/psa"]),
    (Panel::CPanel, &["/usr/local/cpanel"]),
    (Panel::HestiaCp, &["/usr/local/hestia", "/usr/local/vesta"]),
    (Panel::CloudPanel, &["/usr/local/bin/clpctl", "/home/clp"]),
    (Panel::AaPanel, &["/www/server/panel"]),
    (Panel::Ispconfig, &["/usr/local/ispconfig"]),
    (Panel::RunCloud, &["/etc/runcloud", "/RunCloud"]),
];

/// Generic paths that are always checked, with or without a panel.
pub const GENERIC_ROOTS: &[&str] = &[
    "/var/www",
    "/srv/www",
    "/srv/http",
    "/home",
    "/usr/share/nginx/html",
];

pub fn detect_with_root(fs_root: &Path) -> Vec<Panel> {
    MARKERS
        .iter()
        .filter(|(_, paths)| paths.iter().any(|p| rebase(fs_root, p).exists()))
        .map(|(panel, _)| *panel)
        .collect()
}

pub fn detect() -> Vec<Panel> {
    detect_with_root(Path::new("/"))
}

/// Joins an absolute path to an alternative root (for tests with a fake tree).
pub fn rebase(fs_root: &Path, abs: &str) -> PathBuf {
    if fs_root == Path::new("/") {
        PathBuf::from(abs)
    } else {
        fs_root.join(abs.trim_start_matches('/'))
    }
}

/// Expands a pattern containing `*` to the existing folders.
pub fn expand_pattern(fs_root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut current = vec![rebase(fs_root, "/")];
    for seg in pattern.trim_start_matches('/').split('/') {
        let mut next = Vec::new();
        for dir in &current {
            if seg == "*" {
                if let Ok(rd) = std::fs::read_dir(dir) {
                    let mut kids: Vec<PathBuf> = rd
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| p.is_dir())
                        .collect();
                    kids.sort();
                    next.extend(kids);
                }
            } else {
                let p = dir.join(seg);
                if p.is_dir() {
                    next.push(p);
                }
            }
        }
        current = next;
    }
    current
}
