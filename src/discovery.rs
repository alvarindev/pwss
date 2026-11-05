// SPDX-License-Identifier: GPL-3.0-or-later
//! WordPress installation discovery.
//!
//! Works the same on any server: walks the search paths and treats every
//! folder containing `wp-includes/version.php` as WordPress. It then locates
//! the configuration, even if it lives in another folder, and reads it
//! without executing PHP.

use crate::config::Config;
use crate::panel::{self, Panel};
use crate::phpconf::{self, ParsedConfig, ResolveCtx};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// `wp-config.php` next to the core.
    Standard,
    /// `wp-config.php` one level above the core (WordPress allows this).
    ConfigAbove,
    /// `wp-config.php` that loads other configuration files.
    SplitConfig,
    /// Bedrock / Composer (`config/application.php` + `.env`).
    Bedrock,
    /// Declared by hand in the configuration.
    Manual,
    /// Core without a configuration file.
    NoConfig,
}

impl Layout {
    pub fn label(self) -> &'static str {
        match self {
            Layout::Standard => "standard",
            Layout::ConfigAbove => "config above",
            Layout::SplitConfig => "split config",
            Layout::Bedrock => "Bedrock",
            Layout::Manual => "manual",
            Layout::NoConfig => "no config",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Site {
    /// Core folder (the one with `wp-includes` and `wp-admin`).
    pub core_dir: PathBuf,
    /// Public root of the site (the parent folder when the core lives in a
    /// subfolder such as `/cms` or `/wp`).
    pub web_root: PathBuf,
    pub layout: Layout,
    pub version: Option<String>,
    pub url: Option<String>,
    pub content_dir: PathBuf,
    pub plugins_dir: PathBuf,
    pub db_name: Option<String>,
    pub db_host: Option<String>,
    pub db_user: Option<String>,
    pub table_prefix: Option<String>,
    pub has_db_password: bool,
    pub multisite: bool,
    pub owner: Option<String>,
    pub git_repo: Option<PathBuf>,
    /// Set when this WordPress is inside another one (development copies, etc.).
    pub nested_in: Option<PathBuf>,
    pub config_files: Vec<PathBuf>,
    pub warnings: Vec<String>,
    /// Search path under which it was found.
    pub search_root: PathBuf,
}

impl Site {
    /// Short display name.
    pub fn display_name(&self) -> String {
        if let Some(u) = &self.url {
            let u = u
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            return u.trim_end_matches('/').to_string();
        }
        let p = self.web_root.display().to_string();
        // Folders that precede the domain in common panels.
        for marker in [
            "/data/www/",
            "/vhosts/",
            "/web/",
            "/htdocs/",
            "/wwwroot/",
            "/webapps/",
        ] {
            if let Some(i) = p.rfind(marker) {
                let rest = &p[i + marker.len()..];
                let rest = rest
                    .replacen("/httpdocs", "", 1)
                    .replacen("/public_html", "", 1);
                if !rest.is_empty() {
                    return rest;
                }
            }
        }
        if let Ok(rel) = self.web_root.strip_prefix(&self.search_root)
            && !rel.as_os_str().is_empty()
        {
            return rel.display().to_string();
        }
        p
    }

    /// `true` if we have what is needed to scan its database.
    pub fn db_ready(&self) -> bool {
        self.db_name.is_some() && self.table_prefix.is_some()
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Discovery {
    pub panels: Vec<Panel>,
    pub roots: Vec<PathBuf>,
    pub sites: Vec<Site>,
    /// `wp-config.php` files that belong to no core found.
    pub orphan_configs: Vec<PathBuf>,
    /// Folders that could not be read because of permissions.
    pub unreadable: usize,
    pub dirs_visited: usize,
}

/// Run options (the filesystem root is configurable so fake trees can be
/// used in tests).
pub struct Options<'a> {
    pub fs_root: &'a Path,
    pub extra_roots: &'a [PathBuf],
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            fs_root: Path::new("/"),
            extra_roots: &[],
        }
    }
}

pub fn search_roots(cfg: &Config, opts: &Options) -> (Vec<Panel>, Vec<PathBuf>) {
    let panels = panel::detect_with_root(opts.fs_root);
    let mut roots: Vec<PathBuf> = Vec::new();
    if !opts.extra_roots.is_empty() {
        roots.extend(opts.extra_roots.iter().cloned());
    } else if !cfg.discovery.roots.is_empty() {
        roots.extend(
            cfg.discovery
                .roots
                .iter()
                .map(|r| panel::rebase(opts.fs_root, &r.display().to_string())),
        );
    } else {
        for p in &panels {
            for pat in p.site_patterns() {
                // Only the fixed part of the pattern: the walk already enters every level.
                let fixed: String = pat.split("/*").next().unwrap_or(pat).to_string();
                roots.push(panel::rebase(opts.fs_root, &fixed));
            }
        }
        roots.extend(
            panel::GENERIC_ROOTS
                .iter()
                .map(|r| panel::rebase(opts.fs_root, r)),
        );
    }
    roots.retain(|r| r.is_dir());
    let mut canon: Vec<PathBuf> = roots.iter().filter_map(|r| r.canonicalize().ok()).collect();
    canon.sort();
    canon.dedup();
    // Drop roots contained in other roots.
    let all = canon.clone();
    canon.retain(|r| !all.iter().any(|o| o != r && r.starts_with(o)));
    (panels, canon)
}

pub fn discover(cfg: &Config, opts: &Options) -> Discovery {
    let (panels, roots) = search_roots(cfg, opts);
    let skip: BTreeSet<&str> = cfg.discovery.skip_dirs.iter().map(String::as_str).collect();
    let exclude: Vec<PathBuf> = cfg
        .discovery
        .exclude
        .iter()
        .map(|e| panel::rebase(opts.fs_root, &e.display().to_string()))
        .collect();

    let mut out = Discovery {
        panels,
        roots: roots.clone(),
        ..Default::default()
    };
    let mut cores: Vec<(PathBuf, PathBuf)> = Vec::new(); // (core, search root)
    let mut configs: BTreeSet<PathBuf> = BTreeSet::new();

    for root in &roots {
        let walker = WalkDir::new(root)
            .follow_links(false)
            .max_depth(cfg.discovery.max_depth)
            .into_iter()
            .filter_entry(|e| {
                if !e.file_type().is_dir() {
                    return false;
                }
                if e.depth() > 0 {
                    let name = e.file_name().to_string_lossy();
                    if skip.contains(name.as_ref()) {
                        return false;
                    }
                }
                !exclude.iter().any(|x| e.path().starts_with(x))
            });
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    out.unreadable += 1;
                    continue;
                }
            };
            out.dirs_visited += 1;
            let dir = entry.path();
            if dir.join("wp-includes/version.php").is_file() {
                cores.push((dir.to_path_buf(), root.clone()));
            }
            let c = dir.join("wp-config.php");
            if c.is_file()
                && let Ok(c) = c.canonicalize()
            {
                configs.insert(c);
            }
        }
    }

    for (core, root) in &cores {
        out.sites.push(build_site(core, root));
    }

    // Manually declared sites that were not found automatically.
    for m in &cfg.sites {
        let path = panel::rebase(opts.fs_root, &m.path.display().to_string());
        let known = out.sites.iter().any(|s| s.core_dir == path);
        if known {
            if let Some(s) = out.sites.iter_mut().find(|s| s.core_dir == path) {
                if m.db_name.is_some() {
                    s.db_name = m.db_name.clone();
                }
                if m.table_prefix.is_some() {
                    s.table_prefix = m.table_prefix.clone();
                }
            }
            continue;
        }
        let root = path.parent().unwrap_or(&path).to_path_buf();
        let mut s = build_site(&path, &root);
        s.layout = Layout::Manual;
        if m.db_name.is_some() {
            s.db_name = m.db_name.clone();
        }
        if m.table_prefix.is_some() {
            s.table_prefix = m.table_prefix.clone();
        }
        out.sites.push(s);
    }

    // Nested sites (development copies inside another site).
    let roots_of: Vec<(PathBuf, PathBuf)> = out
        .sites
        .iter()
        .map(|s| (s.core_dir.clone(), s.web_root.clone()))
        .collect();
    for s in &mut out.sites {
        s.nested_in = roots_of
            .iter()
            .filter(|(core, web)| {
                *core != s.core_dir && s.core_dir.starts_with(web) && *web != s.web_root
            })
            .map(|(_, web)| web.clone())
            .max_by_key(|w| w.components().count());
    }

    let used: BTreeSet<PathBuf> = out
        .sites
        .iter()
        .flat_map(|s| s.config_files.clone())
        .collect();
    out.orphan_configs = configs.into_iter().filter(|c| !used.contains(c)).collect();
    out.sites.sort_by(|a, b| a.core_dir.cmp(&b.core_dir));
    out
}

fn build_site(core: &Path, boundary: &Path) -> Site {
    let core = core.canonicalize().unwrap_or_else(|_| core.to_path_buf());
    let mut warnings = Vec::new();
    let ctx = ResolveCtx {
        core_dir: core.clone(),
        boundary: boundary.to_path_buf(),
    };

    let parent = core.parent().map(Path::to_path_buf);
    let bedrock_root = bedrock_root(&core);

    let (entry, mut layout) = if let Some(br) = &bedrock_root {
        (Some(br.join("config/application.php")), Layout::Bedrock)
    } else if core.join("wp-config.php").is_file() {
        (Some(core.join("wp-config.php")), Layout::Standard)
    } else if let Some(p) = parent
        .as_ref()
        .filter(|p| p.join("wp-config.php").is_file() && !p.join("wp-settings.php").is_file())
    {
        (Some(p.join("wp-config.php")), Layout::ConfigAbove)
    } else {
        (None, Layout::NoConfig)
    };

    let mut parsed = match &entry {
        Some(e) => phpconf::parse_config(e, &ctx),
        None => {
            warnings.push("wp-config.php not found".into());
            ParsedConfig::default()
        }
    };
    if let Some(br) = &bedrock_root {
        let env = br.join(".env");
        if env.is_file() {
            let e = phpconf::parse_config(&env, &ctx);
            merge(&mut parsed, e);
        } else {
            warnings.push("Bedrock without a .env file".into());
        }
    }
    if layout == Layout::Standard && parsed.files.len() > 1 {
        layout = Layout::SplitConfig;
    }
    if layout == Layout::ConfigAbove && parsed.files.len() > 1 {
        layout = Layout::SplitConfig;
    }

    if parsed.get("DB_NAME").is_none() && entry.is_some() {
        if parsed.dynamic.iter().any(|k| k == "DB_NAME") {
            warnings.push(
                "DB_NAME comes from environment variables: it will be located through MySQL".into(),
            );
        } else {
            warnings.push("could not read DB_NAME".into());
        }
    }
    if parsed.table_prefix.is_none() && entry.is_some() {
        warnings.push("could not read the table prefix".into());
    }
    for inc in &parsed.unresolved_includes {
        warnings.push(format!("unresolved include: {inc}"));
    }

    // Public folder: if the core is in a subfolder and the index.php above
    // loads the core, the website starts above.
    let web_root = parent
        .as_ref()
        .filter(|p| loads_core_from(p, &core))
        .cloned()
        .or_else(|| bedrock_root.as_ref().map(|b| b.join("web")))
        .unwrap_or_else(|| core.clone());

    let content_dir = parsed
        .get("WP_CONTENT_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .or_else(|| {
            bedrock_root
                .as_ref()
                .map(|b| b.join("web/app"))
                .filter(|p| p.is_dir())
        })
        .unwrap_or_else(|| core.join("wp-content"));
    let plugins_dir = parsed
        .get("WP_PLUGIN_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .unwrap_or_else(|| content_dir.join("plugins"));
    if !content_dir.is_dir() {
        warnings.push(format!(
            "content folder {} does not exist",
            content_dir.display()
        ));
    }

    let multisite = ["MULTISITE"].iter().any(|k| {
        parsed
            .get(k)
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
    });
    let url = parsed
        .get("WP_HOME")
        .or_else(|| parsed.get("WP_SITEURL"))
        .map(str::to_string);

    Site {
        version: read_version(&core),
        owner: owner_of(&core),
        git_repo: find_git(&core, boundary),
        web_root,
        layout,
        url,
        content_dir,
        plugins_dir,
        db_name: parsed.get("DB_NAME").map(str::to_string),
        db_host: parsed.get("DB_HOST").map(str::to_string),
        db_user: parsed.get("DB_USER").map(str::to_string),
        table_prefix: parsed.table_prefix.clone(),
        has_db_password: parsed.has_db_password,
        multisite,
        nested_in: None,
        config_files: parsed.files.clone(),
        warnings,
        core_dir: core,
        search_root: boundary.to_path_buf(),
    }
}

fn merge(into: &mut ParsedConfig, from: ParsedConfig) {
    for (k, v) in from.values {
        into.values.entry(k).or_insert(v);
    }
    if into.table_prefix.is_none() {
        into.table_prefix = from.table_prefix;
    }
    into.has_db_password |= from.has_db_password;
    into.files.extend(from.files);
}

/// Bedrock: the core lives in `<root>/web/wp` and the config in `<root>/config`.
fn bedrock_root(core: &Path) -> Option<PathBuf> {
    let web = core.parent()?;
    if core.file_name()? != "wp" || web.file_name()? != "web" {
        return None;
    }
    let root = web.parent()?;
    root.join("config/application.php")
        .is_file()
        .then(|| root.to_path_buf())
}

fn loads_core_from(dir: &Path, core: &Path) -> bool {
    let Some(name) = core.file_name() else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(dir.join("index.php")) else {
        return false;
    };
    let needle = format!("{}/wp-blog-header.php", name.to_string_lossy());
    text.contains(&needle)
}

fn read_version(core: &Path) -> Option<String> {
    let text = std::fs::read_to_string(core.join("wp-includes/version.php")).ok()?;
    let re = Regex::new(r#"\$wp_version\s*=\s*['"]([^'"]+)['"]"#).ok()?;
    re.captures(&text).map(|c| c[1].to_string())
}

fn find_git(core: &Path, boundary: &Path) -> Option<PathBuf> {
    let mut dir = Some(core);
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return Some(d.to_path_buf());
        }
        if d == boundary {
            break;
        }
        dir = d.parent();
    }
    None
}

fn owner_of(path: &Path) -> Option<String> {
    let uid = std::fs::metadata(path).ok()?.uid();
    users().get(&uid).cloned().or_else(|| Some(uid.to_string()))
}

fn users() -> &'static BTreeMap<u32, String> {
    static U: std::sync::OnceLock<BTreeMap<u32, String>> = std::sync::OnceLock::new();
    U.get_or_init(|| {
        std::fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let mut f = l.split(':');
                let name = f.next()?.to_string();
                f.next();
                let uid = f.next()?.parse().ok()?;
                Some((uid, name))
            })
            .collect()
    })
}
