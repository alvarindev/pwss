// SPDX-License-Identifier: GPL-3.0-or-later
//! Static reading of WordPress configuration files.
//!
//! PWSS never executes PHP. Instead it extracts the literal values it needs
//! from the files (database name, table prefix, paths...) and follows
//! `require`/`include` to find configuration split across several files, such
//! as `cms/wp-config.php` -> `config/wp-config.php` -> `config/site-config.php`,
//! or `.env` in Bedrock.

use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Keys we care about. Passwords are never stored: only whether they exist
/// is recorded.
pub const KEYS: &[&str] = &[
    "DB_NAME",
    "DB_USER",
    "DB_HOST",
    "DB_CHARSET",
    "WP_HOME",
    "WP_SITEURL",
    "WP_CONTENT_DIR",
    "WP_PLUGIN_DIR",
    "WPMU_PLUGIN_DIR",
    "UPLOADS",
    "MULTISITE",
    "WP_ALLOW_MULTISITE",
    "WP_ENV",
    "WP_ENVIRONMENT_TYPE",
];

const SECRET_KEYS: &[&str] = &["DB_PASSWORD"];

/// Maximum size of a configuration file we agree to read.
const MAX_CONFIG_BYTES: u64 = 512 * 1024;
/// Maximum depth when following `require`/`include`.
const MAX_INCLUDE_DEPTH: usize = 6;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ParsedConfig {
    /// Literal values found (no secrets).
    pub values: BTreeMap<String, String>,
    pub table_prefix: Option<String>,
    /// `true` if a database password was found (it is not stored).
    pub has_db_password: bool,
    /// Files read, in order.
    pub files: Vec<PathBuf>,
    /// Values coming from `getenv()`, `$_ENV`, `$_SERVER` or similar.
    pub dynamic: Vec<String>,
    /// Includes that could not be resolved.
    pub unresolved_includes: Vec<String>,
}

impl ParsedConfig {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
}

struct Patterns {
    define_sq: Regex,
    define_dq: Regex,
    define_lit: Regex,
    array_sq: Regex,
    array_dq: Regex,
    prefix_var: Regex,
    include: Regex,
    dynamic: Regex,
    env_line: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        define_sq: Regex::new(
            r#"(?i)define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*'((?:[^'\\]|\\.)*)'"#,
        )
        .unwrap(),
        define_dq: Regex::new(
            r#"(?i)define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*"((?:[^"\\]|\\.)*)""#,
        )
        .unwrap(),
        define_lit: Regex::new(
            r#"(?i)define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*(true|false|-?\d+)\s*\)"#,
        )
        .unwrap(),
        array_sq: Regex::new(r#"['"]([A-Za-z0-9_]+)['"]\s*=>\s*'((?:[^'\\]|\\.)*)'"#).unwrap(),
        array_dq: Regex::new(r#"['"]([A-Za-z0-9_]+)['"]\s*=>\s*"((?:[^"\\]|\\.)*)""#).unwrap(),
        prefix_var: Regex::new(r#"\$table_prefix\s*=\s*['"]([A-Za-z0-9_]*)['"]"#).unwrap(),
        include: Regex::new(r#"(?i)\b(?:require|include)(?:_once)?\b\s*\(?\s*([^;]+?)\s*\)?\s*;"#)
            .unwrap(),
        dynamic: Regex::new(
            r#"(?i)define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*(?:getenv\s*\(|\$_ENV\s*\[|\$_SERVER\s*\[|env\s*\()"#,
        )
        .unwrap(),
        env_line: Regex::new(r#"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$"#).unwrap(),
    })
}

/// Context for resolving paths in `require`.
#[derive(Debug, Clone)]
pub struct ResolveCtx {
    /// WordPress core folder (the one with `wp-includes`).
    pub core_dir: PathBuf,
    /// Upper bound: files outside this folder are never read.
    pub boundary: PathBuf,
}

/// Reads a `wp-config.php` (or `.env`) and everything it includes.
pub fn parse_config(entry: &Path, ctx: &ResolveCtx) -> ParsedConfig {
    let mut out = ParsedConfig::default();
    let mut constants: BTreeMap<String, String> = BTreeMap::new();
    constants.insert("ABSPATH".into(), format!("{}/", ctx.core_dir.display()));
    walk(entry, ctx, &mut out, &mut constants, 0);
    out
}

fn walk(
    file: &Path,
    ctx: &ResolveCtx,
    out: &mut ParsedConfig,
    constants: &mut BTreeMap<String, String>,
    depth: usize,
) {
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    let Ok(canon) = file.canonicalize() else {
        out.unresolved_includes.push(file.display().to_string());
        return;
    };
    if out.files.contains(&canon) || !canon.starts_with(&ctx.boundary) {
        return;
    }
    let Ok(meta) = std::fs::metadata(&canon) else {
        return;
    };
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return;
    }
    let Ok(bytes) = std::fs::read(&canon) else {
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    out.files.push(canon.clone());

    let is_env = canon
        .file_name()
        .map(|n| n.to_string_lossy().starts_with(".env"))
        .unwrap_or(false);
    if is_env {
        parse_env(&text, out);
        return;
    }

    let code = strip_php_comments(&text);
    let p = patterns();

    for re in [&p.define_sq, &p.define_dq, &p.array_sq, &p.array_dq] {
        for c in re.captures_iter(&code) {
            store(out, constants, &c[1], &unescape(&c[2]));
        }
    }
    for c in p.define_lit.captures_iter(&code) {
        store(out, constants, &c[1], &c[2].to_lowercase());
    }
    for c in p.dynamic.captures_iter(&code) {
        let k = c[1].to_uppercase();
        if !out.dynamic.contains(&k) {
            out.dynamic.push(k);
        }
    }
    if let Some(c) = p.prefix_var.captures(&code) {
        out.table_prefix.get_or_insert_with(|| c[1].to_string());
    }

    // Follow includes.
    let file_dir = canon.parent().unwrap_or(Path::new("/")).to_path_buf();
    let includes: Vec<String> = p
        .include
        .captures_iter(&code)
        .map(|c| c[1].to_string())
        .collect();
    for expr in includes {
        if is_wp_bootstrap(&expr) {
            continue;
        }
        match resolve_include(&expr, &canon, &file_dir, ctx, constants) {
            Some(target) => walk(&target, ctx, out, constants, depth + 1),
            None => out.unresolved_includes.push(expr.trim().to_string()),
        }
    }
}

fn store(out: &mut ParsedConfig, constants: &mut BTreeMap<String, String>, key: &str, value: &str) {
    // User constants (e.g. ROOT_PATH) help resolve includes.
    if key
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        constants
            .entry(key.to_string())
            .or_insert_with(|| value.to_string());
    }
    let upper = key.to_uppercase();
    if SECRET_KEYS.contains(&upper.as_str()) {
        if !value.is_empty() {
            out.has_db_password = true;
        }
        return;
    }
    if upper == "TABLE_PREFIX" || key == "table_prefix" {
        out.table_prefix.get_or_insert_with(|| value.to_string());
        return;
    }
    if KEYS.contains(&upper.as_str()) {
        out.values.entry(upper).or_insert_with(|| value.to_string());
    }
}

fn parse_env(text: &str, out: &mut ParsedConfig) {
    let p = patterns();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(c) = p.env_line.captures(line) {
            let key = c[1].to_uppercase();
            let mut val = c[2].trim().to_string();
            if let Some(pos) = val.find(" #")
                && !val.starts_with('"')
                && !val.starts_with('\'')
            {
                val.truncate(pos);
            }
            let val = val
                .trim()
                .trim_matches(|ch| ch == '"' || ch == '\'')
                .to_string();
            if SECRET_KEYS.contains(&key.as_str()) {
                if !val.is_empty() {
                    out.has_db_password = true;
                }
            } else if key == "DB_PREFIX" || key == "TABLE_PREFIX" {
                out.table_prefix.get_or_insert(val);
            } else if KEYS.contains(&key.as_str()) {
                out.values.entry(key).or_insert(val);
            }
        }
    }
}

fn is_wp_bootstrap(expr: &str) -> bool {
    let e = expr.to_lowercase();
    [
        "wp-settings.php",
        "wp-blog-header.php",
        "wp-load.php",
        "autoload.php",
    ]
    .iter()
    .any(|f| e.contains(f))
}

/// Resolves a `require` expression such as
/// `dirname(__DIR__) . '/config/site-config.php'` or `ROOT_PATH . 'config/x.php'`.
fn resolve_include(
    expr: &str,
    file: &Path,
    file_dir: &Path,
    ctx: &ResolveCtx,
    constants: &BTreeMap<String, String>,
) -> Option<PathBuf> {
    let mut known_prefix: Option<PathBuf> = None;
    let mut unknown_base = false;
    let mut tail = String::new();

    for part in split_concat(expr) {
        let part = part.trim();
        if let Some(lit) = string_literal(part) {
            tail.push_str(&lit);
        } else if let Some(base) = eval_dir_expr(part, file, file_dir) {
            known_prefix = Some(base);
            tail.clear();
        } else if let Some(v) = constants.get(part) {
            known_prefix = Some(PathBuf::from(v));
            tail.clear();
        } else if part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !part.is_empty() {
            // Unknown constant (e.g. ROOT_PATH defined by the server).
            unknown_base = true;
            tail.clear();
        } else {
            return None;
        }
    }
    if tail.is_empty() {
        return None;
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    let join = |base: &Path, t: &str| -> PathBuf {
        if t.starts_with('/') && base.as_os_str().is_empty() {
            PathBuf::from(t)
        } else {
            let mut s = base.display().to_string();
            if !s.ends_with('/') && !t.starts_with('/') {
                s.push('/');
            }
            s.push_str(t);
            PathBuf::from(s)
        }
    };
    match (known_prefix, unknown_base) {
        (Some(base), _) => candidates.push(join(&base, &tail)),
        (None, true) => {
            // Try the plausible roots, from the nearest to the farthest.
            let mut dir = Some(file_dir);
            while let Some(d) = dir {
                candidates.push(join(d, &tail));
                if d == ctx.boundary {
                    break;
                }
                dir = d.parent();
            }
        }
        (None, false) => {
            if tail.starts_with('/') {
                candidates.push(PathBuf::from(&tail));
            } else {
                candidates.push(file_dir.join(&tail));
                candidates.push(ctx.core_dir.join(&tail));
            }
        }
    }
    candidates.into_iter().find(|c| c.is_file())
}

fn eval_dir_expr(part: &str, file: &Path, file_dir: &Path) -> Option<PathBuf> {
    let compact: String = part.chars().filter(|c| !c.is_whitespace()).collect();
    let lower = compact.to_lowercase();
    if lower == "__dir__" || lower == "dirname(__file__)" {
        return Some(file_dir.to_path_buf());
    }
    if lower == "__file__" {
        return Some(file.to_path_buf());
    }
    // dirname(__DIR__), dirname(dirname(__FILE__)), dirname(__FILE__, 2)...
    let mut levels = 0usize;
    let mut inner = lower.as_str();
    while let Some(rest) = inner.strip_prefix("dirname(") {
        levels += 1;
        inner = rest;
    }
    if levels == 0 {
        return None;
    }
    let (base, extra) = if inner.starts_with("__dir__") {
        (file_dir.to_path_buf(), 0)
    } else if inner.starts_with("__file__") {
        (file.to_path_buf(), 0)
    } else {
        return None;
    };
    let mut lv = levels + extra;
    if let Some(idx) = inner.find(',') {
        let n: String = inner[idx + 1..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(n) = n.parse::<usize>() {
            lv = levels - 1 + n;
        }
    }
    let mut p = base;
    for _ in 0..lv {
        p = p.parent()?.to_path_buf();
    }
    Some(p)
}

fn split_concat(expr: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut depth = 0i32;
    let mut prev = '\0';
    for ch in expr.chars() {
        match quote {
            Some(q) => {
                cur.push(ch);
                if ch == q && prev != '\\' {
                    quote = None;
                }
            }
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    cur.push(ch);
                }
                '(' => {
                    depth += 1;
                    cur.push(ch);
                }
                ')' => {
                    depth -= 1;
                    cur.push(ch);
                }
                '.' if depth == 0 => {
                    parts.push(std::mem::take(&mut cur));
                }
                _ => cur.push(ch),
            },
        }
        prev = ch;
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    // Strip redundant wrapping parentheses: require( X . 'y' )
    parts
        .into_iter()
        .map(|p| {
            let t = p.trim();
            let opens = t.matches('(').count();
            let closes = t.matches(')').count();
            let mut s = t.to_string();
            if opens > closes && s.starts_with('(') {
                s.remove(0);
            }
            if closes > opens && s.ends_with(')') {
                s.pop();
            }
            s
        })
        .collect()
}

fn string_literal(part: &str) -> Option<String> {
    let t = part.trim();
    if t.len() >= 2
        && ((t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')))
    {
        return Some(unescape(&t[1..t.len() - 1]));
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("\\'", "'")
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

/// Removes PHP comments (`//`, `#`, `/* */`) while respecting strings.
pub fn strip_php_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = quote {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                out.push(c);
                i += 1;
            }
            '/' if i + 1 < b.len() && b[i + 1] == '*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            '/' if i + 1 < b.len() && b[i + 1] == '/' => {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
            }
            '#' if !(i + 1 < b.len() && b[i + 1] == '[') => {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_comments_but_not_strings() {
        let src = "<?php // x\n/* define('DB_NAME','no'); */ define('DB_NAME', 'a//b#c'); # y";
        let s = strip_php_comments(src);
        assert!(!s.contains("'no'"));
        assert!(s.contains("'a//b#c'"));
    }

    #[test]
    fn dirname_levels() {
        let f = Path::new("/a/b/c/wp-config.php");
        let d = Path::new("/a/b/c");
        assert_eq!(
            eval_dir_expr("dirname(__DIR__)", f, d).unwrap(),
            Path::new("/a/b")
        );
        assert_eq!(
            eval_dir_expr("dirname(dirname(__FILE__))", f, d).unwrap(),
            Path::new("/a/b")
        );
        assert_eq!(
            eval_dir_expr("dirname( __FILE__ , 2 )", f, d).unwrap(),
            Path::new("/a/b")
        );
        assert_eq!(eval_dir_expr("__DIR__", f, d).unwrap(), Path::new("/a/b/c"));
    }

    #[test]
    fn splits_concatenation() {
        let p = split_concat("dirname(__DIR__) . '/config/site-config.php'");
        assert_eq!(p.len(), 2);
        assert_eq!(string_literal(&p[1]).unwrap(), "/config/site-config.php");
    }
}
