// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-site traversal and zone classification of files.

use super::rules::{self, Hit, Severity, Zone};
use super::{Counters, Finding};
use crate::config::{Config, ScanCfg};
use crate::discovery::Site;
use crate::util;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;
use walkdir::WalkDir;

const DROPINS: &[&str] = &[
    "advanced-cache.php",
    "db.php",
    "db-error.php",
    "install.php",
    "maintenance.php",
    "object-cache.php",
    "php-error.php",
    "fatal-error-handler.php",
    "sunrise.php",
    "blog-deleted.php",
    "blog-inactive.php",
    "blog-suspended.php",
];

const CORE_ROOT_FILES: &[&str] = &[
    "index.php",
    "wp-activate.php",
    "wp-blog-header.php",
    "wp-comments-post.php",
    "wp-config.php",
    "wp-config-sample.php",
    "wp-cron.php",
    "wp-links-opml.php",
    "wp-load.php",
    "wp-login.php",
    "wp-mail.php",
    "wp-settings.php",
    "wp-signup.php",
    "wp-trackback.php",
    "xmlrpc.php",
];

const THEME_ENTRY: &[&str] = &[
    "functions.php",
    "header.php",
    "footer.php",
    "index.php",
    "404.php",
];

/// Common hidden folders that are not suspicious.
const BENIGN_HIDDEN: &[&str] = &[
    ".git",
    ".github",
    ".gitlab",
    ".svn",
    ".idea",
    ".vscode",
    ".wordpress-org",
    ".circleci",
    ".husky",
    ".well-known",
    ".tmb",
    ".quarantine",
    ".trash",
    ".config",
    ".npm",
    ".cache",
    ".storybook",
];

const SKIP_DIRS: &[&str] = &[".git", ".svn", "node_modules"];

/// Symlink targets that should never be reachable from a website.
const SENSITIVE_TARGETS: &[&str] = &[
    "/etc", "/root", "/proc", "/sys", "/var/log", "/home", "/boot", "/dev",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Php,
    Htaccess,
    Ini,
    /// Judged by name only; the file is not opened.
    NameOnly,
}

struct Scanner<'a> {
    site: &'a Site,
    scfg: &'a ScanCfg,
    others: Vec<&'a Path>,
    counters: &'a Counters,
    seen: HashSet<PathBuf>,
    findings: Vec<Finding>,
    name: String,
    /// Hidden folders already reported (children are not reported again).
    hidden_reported: Vec<PathBuf>,
}

pub fn scan_site(
    site: &Site,
    all_cores: &[PathBuf],
    cfg: &Config,
    deep: bool,
    counters: &Counters,
) -> Vec<Finding> {
    let others: Vec<&Path> = all_cores
        .iter()
        .map(PathBuf::as_path)
        .filter(|c| *c != site.core_dir && !site.core_dir.starts_with(c))
        .collect();
    let mut s = Scanner {
        site,
        scfg: &cfg.scan,
        others,
        counters,
        seen: HashSet::new(),
        findings: Vec::new(),
        name: util::sanitize(&site.display_name()),
        hidden_reported: Vec::new(),
    };
    s.scan_roots();
    s.walk_content(deep);
    if deep {
        s.walk_core();
        if !site.plugins_dir.starts_with(&site.content_dir) {
            let pd = site.plugins_dir.clone();
            s.walk_plain(&pd);
        }
    }
    s.findings
}

impl Scanner<'_> {
    fn ignored(&self, path: &Path) -> bool {
        self.scfg.ignore_paths.iter().any(|p| path.starts_with(p))
    }

    // ----- root and configuration files -------------------------------------

    fn scan_roots(&mut self) {
        let site = self.site;
        let mut dirs: Vec<PathBuf> = vec![site.core_dir.clone()];
        if site.web_root != site.core_dir {
            dirs.push(site.web_root.clone());
        }
        for c in &site.config_files {
            if let Some(d) = c.parent() {
                let d = d.to_path_buf();
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
        for dir in dirs {
            let is_core = dir == site.core_dir;
            let Ok(rd) = std::fs::read_dir(&dir) else {
                self.counters.unreadable.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let mut names: Vec<(String, PathBuf)> = rd
                .flatten()
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
                .collect();
            names.sort();
            for (name, path) in names {
                self.counters.files.fetch_add(1, Ordering::Relaxed);
                let is_config = site.config_files.contains(&path) || name == "wp-config.php";
                let zone = if is_config {
                    Zone::Config
                } else {
                    Zone::CoreRoot
                };
                if rules::is_php_ext(&name) {
                    let mut name_hits = Vec::new();
                    if is_core && !CORE_ROOT_FILES.contains(&name.as_str()) && !is_config {
                        name_hits.push(hit_name(
                            "core.unexpected-root-php",
                            Severity::Medium,
                            "PHP file in the site root that does not belong to WordPress",
                        ));
                    }
                    self.examine(&path, zone, Kind::Php, name_hits);
                } else if let Some(k) = special_kind(&name) {
                    self.examine(&path, Zone::Other, k, Vec::new());
                }
            }
        }
    }

    // ----- wp-content --------------------------------------------------------

    fn walk_content(&mut self, deep: bool) {
        let root = self.site.content_dir.clone();
        if !root.is_dir() {
            return;
        }
        let others = self.others.clone();
        let it = WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                if !e.file_type().is_dir() {
                    return true;
                }
                let n = e.file_name().to_string_lossy();
                !SKIP_DIRS.contains(&n.as_ref()) && !others.iter().any(|o| e.path() == *o)
            });
        for entry in it {
            let Ok(entry) = entry else {
                self.counters.unreadable.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if entry.depth() == 0 {
                continue;
            }
            let path = entry.path();
            let ft = entry.file_type();
            let rel = path.strip_prefix(&root).unwrap_or(path);
            if ft.is_dir() {
                self.counters.dirs.fetch_add(1, Ordering::Relaxed);
                let n = entry.file_name().to_string_lossy();
                if n.starts_with('.')
                    && !BENIGN_HIDDEN.contains(&n.as_ref())
                    && !self.ignored(path)
                    && !self.hidden_reported.iter().any(|h| path.starts_with(h))
                {
                    self.hidden_reported.push(path.to_path_buf());
                    let in_plugins = matches!(
                        rel.components().next().and_then(|c| c.as_os_str().to_str()),
                        Some("plugins" | "themes")
                    );
                    if in_plugins {
                        self.push_simple(
                            path,
                            "persist.hidden-dir",
                            Severity::Medium,
                            "hidden folder inside plugins/themes: WordPress never creates these; usually a leftover or an unlisted copy of a plugin (files inside are still analysed)",
                        );
                    } else {
                        self.push_simple(
                            path,
                            "persist.hidden-dir",
                            Severity::Low,
                            "hidden folder inside wp-content",
                        );
                    }
                }
                continue;
            }
            if ft.is_symlink() {
                self.check_symlink(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            self.counters.files.fetch_add(1, Ordering::Relaxed);
            let name = entry.file_name().to_string_lossy().into_owned();
            let (zone, scope) = classify(rel);
            let Some((kind, name_hits)) = decide(zone, scope, &name, deep) else {
                continue;
            };
            self.examine(path, zone, kind, name_hits);
        }
    }

    // ----- --deep traversals -------------------------------------------------

    fn walk_core(&mut self) {
        let root = self.site.core_dir.clone();
        let content = self.site.content_dir.clone();
        let others = self.others.clone();
        let it = WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 || !e.file_type().is_dir() {
                    return true;
                }
                let n = e.file_name().to_string_lossy();
                !SKIP_DIRS.contains(&n.as_ref())
                    && e.path() != content
                    && !others.iter().any(|o| e.path() == *o)
            });
        self.walk_deep_iter(it, &root, false);
    }

    fn walk_plain(&mut self, root: &Path) {
        let it = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0
                    || !e.file_type().is_dir()
                    || !SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref())
            });
        self.walk_deep_iter(it, root, true);
    }

    fn walk_deep_iter(
        &mut self,
        it: impl Iterator<Item = walkdir::Result<walkdir::DirEntry>>,
        root: &Path,
        plugin_root: bool,
    ) {
        for entry in it {
            let Ok(entry) = entry else {
                self.counters.unreadable.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if entry.depth() == 0 {
                continue;
            }
            let ft = entry.file_type();
            if ft.is_dir() {
                self.counters.dirs.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if ft.is_symlink() {
                self.check_symlink(entry.path());
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            self.counters.files.fetch_add(1, Ordering::Relaxed);
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
            let scope = hidden_scope(rel, plugin_root);
            if rules::is_php_ext(&name) {
                let mut hits = Vec::new();
                if matches!(scope, HiddenScope::Dir | HiddenScope::File) {
                    hits.push(hit_name(
                        "persist.php-in-hidden-dir",
                        Severity::High,
                        "PHP inside a hidden folder (or with a hidden file name)",
                    ));
                }
                self.examine(entry.path(), Zone::Other, Kind::Php, hits);
            } else if let Some(k) = special_kind(&name) {
                self.examine(entry.path(), Zone::Other, k, Vec::new());
            }
        }
    }

    // ----- single-file analysis ----------------------------------------------

    fn examine(&mut self, path: &Path, zone: Zone, kind: Kind, mut hits: Vec<Hit>) {
        if self.ignored(path) || !self.seen.insert(path.to_path_buf()) {
            return;
        }
        let mut size = 0u64;
        let mut modified = None;
        let mut sha: Option<String> = None;

        if kind != Kind::NameOnly {
            match util::read_limited(path, self.scfg.max_file_bytes) {
                Ok(d) => {
                    self.counters.analysed.fetch_add(1, Ordering::Relaxed);
                    self.counters
                        .bytes
                        .fetch_add(d.bytes.len() as u64, Ordering::Relaxed);
                    size = d.size;
                    modified = Some(d.mtime);
                    match kind {
                        Kind::Php => {
                            if rules::is_silence_is_golden(&d.bytes) {
                                return;
                            }
                            let name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            if zone == Zone::Languages && rules::is_legit_l10n(&name, &d.bytes) {
                                hits.retain(|h| h.rule != "persist.php-in-languages");
                            }
                            hits.extend(rules::analyze_php(&d.bytes, zone));
                        }
                        Kind::Htaccess => hits.extend(rules::analyze_htaccess(&d.bytes, zone)),
                        Kind::Ini => hits.extend(rules::analyze_ini(&d.bytes)),
                        Kind::NameOnly => {}
                    }
                }
                Err(e) => {
                    if e.kind() == ErrorKind::PermissionDenied {
                        self.counters.unreadable.fetch_add(1, Ordering::Relaxed);
                    }
                    // Symlinks, FIFOs and similar: ignored.
                    if hits.is_empty() {
                        return;
                    }
                }
            }
        } else if let Ok(m) = std::fs::symlink_metadata(path) {
            use std::os::unix::fs::MetadataExt;
            size = m.len();
            modified = Some(m.mtime());
        }

        hits.retain(|h| !self.scfg.ignore_rules.iter().any(|r| r == h.rule));
        if hits.is_empty() {
            return;
        }
        if !self.scfg.allow_sha256.is_empty() || kind != Kind::NameOnly {
            sha = util::sha256_file(path, 64 << 20);
        }
        if let Some(h) = &sha
            && self
                .scfg
                .allow_sha256
                .iter()
                .any(|a| a.eq_ignore_ascii_case(h))
        {
            return;
        }
        let severity = hits
            .iter()
            .map(|h| h.severity)
            .max()
            .unwrap_or(Severity::Info);
        hits.sort_by_key(|h| std::cmp::Reverse(h.severity));
        self.findings.push(Finding {
            site: self.name.clone(),
            severity,
            path: path.to_path_buf(),
            sha256: sha,
            size,
            modified,
            reasons: hits,
        });
    }

    fn push_simple(&mut self, path: &Path, rule: &'static str, sev: Severity, msg: &str) {
        if self.scfg.ignore_rules.iter().any(|r| r == rule) {
            return;
        }
        self.findings.push(Finding {
            site: self.name.clone(),
            severity: sev,
            path: path.to_path_buf(),
            sha256: None,
            size: 0,
            modified: std::fs::symlink_metadata(path).ok().map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.mtime()
            }),
            reasons: vec![hit_name(rule, sev, msg)],
        });
    }

    fn check_symlink(&mut self, path: &Path) {
        let Ok(target) = std::fs::read_link(path) else {
            return;
        };
        let abs = lexical_normalize(&if target.is_absolute() {
            target.clone()
        } else {
            path.parent().unwrap_or(Path::new("/")).join(&target)
        });
        let site_roots = [
            &self.site.core_dir,
            &self.site.web_root,
            &self.site.content_dir,
        ];
        if site_roots.iter().any(|r| abs.starts_with(r)) {
            return;
        }
        let (sev, why) = if SENSITIVE_TARGETS.iter().any(|s| abs.starts_with(s))
            && !abs.starts_with("/home/clp")
        {
            (Severity::High, "points to a sensitive system location")
        } else if self.others.iter().any(|o| abs.starts_with(o)) {
            (
                Severity::Medium,
                "points to another site on this server (possible cross-site access)",
            )
        } else {
            (Severity::Low, "points outside the site")
        };
        let msg = format!("symlink that {why}: {}", util::path_display(&abs));
        self.push_simple(path, "persist.symlink-out", sev, &msg);
    }
}

fn hit_name(rule: &'static str, severity: Severity, message: &str) -> Hit {
    Hit {
        rule,
        severity,
        message: message.to_string(),
        evidence: None,
    }
}

fn special_kind(name: &str) -> Option<Kind> {
    match name {
        ".htaccess" => Some(Kind::Htaccess),
        ".user.ini" | "php.ini" | ".php.ini" => Some(Kind::Ini),
        _ => None,
    }
}

/// Removes `.` and `..` from a path without touching the disk.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Where a hidden path component sits, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HiddenScope {
    Clean,
    /// The PHP file itself is hidden (`.x.php`).
    File,
    /// A hidden folder inside a plugin or theme folder. WordPress never
    /// creates these, but legitimate leftovers are common, so the folder is
    /// reported once and its files only matter if their code is suspicious.
    DirInPlugin,
    /// A hidden folder anywhere else (wp-content root, uploads, core...).
    Dir,
}

fn hidden_scope(rel: &Path, plugin_root: bool) -> HiddenScope {
    let comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some((last, dirs)) = comps.split_last() else {
        return HiddenScope::Clean;
    };
    let first = dirs
        .iter()
        .position(|c| c.starts_with('.') && !BENIGN_HIDDEN.contains(&c.as_str()));
    match first {
        Some(i) => {
            let in_plugin =
                plugin_root || (i >= 1 && matches!(comps[0].as_str(), "plugins" | "themes"));
            if in_plugin {
                HiddenScope::DirInPlugin
            } else {
                HiddenScope::Dir
            }
        }
        None if last.starts_with('.') && rules::is_php_ext(last) => HiddenScope::File,
        None => HiddenScope::Clean,
    }
}

/// Zone of a file from its path relative to `wp-content`.
fn classify(rel: &Path) -> (Zone, HiddenScope) {
    let comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let scope = hidden_scope(rel, false);
    let hidden = matches!(scope, HiddenScope::Dir | HiddenScope::File);
    let top = comps.first().map(String::as_str).unwrap_or("");
    let zone = if top == "mu-plugins" {
        Zone::MuPlugin
    } else if comps.len() == 1 {
        let n = comps[0].as_str();
        if DROPINS.contains(&n) {
            Zone::DropIn
        } else {
            Zone::ContentRoot
        }
    } else if top == "uploads" {
        Zone::Uploads
    } else if top == "languages" {
        Zone::Languages
    } else if top == "upgrade" || top == "upgrade-temp-backup" {
        Zone::Upgrade
    } else if hidden {
        Zone::Hidden
    } else if top == "themes" && comps.len() == 3 && THEME_ENTRY.contains(&comps[2].as_str()) {
        Zone::ThemeEntry
    } else {
        Zone::Other
    };
    (zone, scope)
}

/// Decides what to do with a `wp-content` file: how to analyse it and which
/// findings come from its name or location alone.
fn decide(zone: Zone, scope: HiddenScope, name: &str, deep: bool) -> Option<(Kind, Vec<Hit>)> {
    let is_php = rules::is_php_ext(name);
    let special = special_kind(name);
    let mut hits: Vec<Hit> = Vec::new();

    if is_php && matches!(scope, HiddenScope::Dir | HiddenScope::File) {
        hits.push(hit_name(
            "persist.php-in-hidden-dir",
            Severity::High,
            "PHP inside a hidden folder (or with a hidden file name)",
        ));
    }

    let kind = match zone {
        Zone::MuPlugin if is_php => {
            hits.push(hit_name(
                "persist.mu-plugin",
                Severity::Low,
                "mu-plugin: always loaded and cannot be deactivated from the WordPress admin",
            ));
            if name == "wp-locale-bootstrap.php" {
                hits.push(hit_name(
                    "ioc.wpanel-filename",
                    Severity::Critical,
                    "loader file name used by the \"wpanel\" malware (2026-11-04 incident)",
                ));
            }
            Kind::Php
        }
        Zone::DropIn if is_php => {
            let (sev, msg) = match name {
                "db.php" => (
                    Severity::Medium,
                    "db.php drop-in: replaces the WordPress database layer and is used as a loader. Check that a plugin you use installed it",
                ),
                "object-cache.php" | "advanced-cache.php" => (
                    Severity::Low,
                    "cache drop-in: check that it belongs to a caching plugin you use",
                ),
                _ => (Severity::Info, "WordPress drop-in present"),
            };
            hits.push(hit_name("persist.dropin", sev, msg));
            Kind::Php
        }
        Zone::ContentRoot if is_php => {
            hits.push(hit_name(
                "persist.unexpected-php-in-wp-content",
                Severity::High,
                "stray PHP file in the wp-content root (not a known drop-in)",
            ));
            Kind::Php
        }
        Zone::Uploads => {
            if rules::is_exec_ext(name) {
                hits.push(hit_name(
                    "persist.php-in-uploads",
                    Severity::High,
                    "PHP in uploads: WordPress never stores code there",
                ));
                Kind::Php
            } else if let Some(k) = special {
                k
            } else if rules::has_double_ext(name) {
                hits.push(hit_name(
                    "persist.double-extension",
                    Severity::Medium,
                    "double extension (.php.jpg...): attempt to pass PHP off as an image",
                ));
                Kind::NameOnly
            } else {
                return None;
            }
        }
        Zone::Languages if is_php => {
            hits.push(hit_name(
                "persist.php-in-languages",
                Severity::High,
                "PHP in languages/ that is not a .l10n.php translation file",
            ));
            if name == "class-wp-locale-data.php" {
                hits.push(hit_name(
                    "ioc.wpanel-filename",
                    Severity::Critical,
                    "payload file name used by the \"wpanel\" malware (2026-11-04 incident)",
                ));
            }
            Kind::Php
        }
        Zone::Upgrade if is_php => {
            hits.push(hit_name(
                "persist.php-in-upgrade",
                Severity::Medium,
                "PHP in upgrade/: may be a failed-update leftover or a hiding place",
            ));
            Kind::Php
        }
        Zone::ThemeEntry | Zone::Hidden if is_php => Kind::Php,
        _ if is_php && scope != HiddenScope::Clean => Kind::Php,
        _ if is_php && deep => Kind::Php,
        _ => special?,
    };
    Some((kind, hits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_zones() {
        let z = |p: &str| classify(Path::new(p)).0;
        assert_eq!(z("mu-plugins/a.php"), Zone::MuPlugin);
        assert_eq!(z("db.php"), Zone::DropIn);
        assert_eq!(z("foo.php"), Zone::ContentRoot);
        assert_eq!(z("uploads/2026/a.php"), Zone::Uploads);
        assert_eq!(z("languages/x.php"), Zone::Languages);
        assert_eq!(z("upgrade/x/y.php"), Zone::Upgrade);
        assert_eq!(z(".wpanel/agent.php"), Zone::Hidden);
        assert_eq!(z("themes/divi/functions.php"), Zone::ThemeEntry);
        assert_eq!(z("plugins/x/x.php"), Zone::Other);
        assert_eq!(z("plugins/x/.git/hooks/a.php"), Zone::Other);
        // Hidden folder inside a plugin: not a "hot" zone.
        assert_eq!(z("plugins/.tempwordfence/lib/a.php"), Zone::Other);
    }

    #[test]
    fn hidden_scopes() {
        let sc = |p: &str, root: bool| hidden_scope(Path::new(p), root);
        assert_eq!(
            sc("plugins/.tempwordfence/lib/a.php", false),
            HiddenScope::DirInPlugin
        );
        assert_eq!(
            sc("themes/x/.cache2/a.php", false),
            HiddenScope::DirInPlugin
        );
        assert_eq!(sc(".wpanel/agent.php", false), HiddenScope::Dir);
        assert_eq!(sc("uploads/.x/a.php", false), HiddenScope::Dir);
        assert_eq!(sc("plugins/x/.hidden.php", false), HiddenScope::File);
        assert_eq!(sc("plugins/x/.git/a.php", false), HiddenScope::Clean);
        assert_eq!(sc(".odd/a.php", true), HiddenScope::DirInPlugin);
        assert_eq!(sc("wp-includes/.odd/a.php", false), HiddenScope::Dir);
    }

    #[test]
    fn normalizes_paths() {
        assert_eq!(
            lexical_normalize(Path::new("/a/b/../c/./d")),
            Path::new("/a/c/d")
        );
    }
}
