// SPDX-License-Identifier: GPL-3.0-or-later
//! nginx checks.
//!
//! The 2026-11-04 incident: a vhost with `upstream { server localhost:1337; }`
//! kept nginx from starting after an automatic restart
//! (`[emerg] host not found in upstream`) and every site went down.
//!
//! nginx resolves the host names of `upstream` and `proxy_pass` **at
//! startup**. If resolution fails, nothing starts. Therefore:
//!
//! 1. `nginx -t` is run (the official check; it changes nothing);
//! 2. the configuration is read to locate every destination given by name;
//! 3. each name is resolved right now.
//!
//! A name that does not resolve is a failure; one that resolves but is used
//! by name is a latent risk: a DNS or `/etc/hosts` hiccup at restart time is
//! enough.

use crate::doctor::{Check, Status};
use crate::util;
use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: Option<u16>,
    pub file: PathBuf,
    pub line: usize,
    pub directive: String,
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub targets: Vec<Target>,
    pub files: usize,
    pub upstream_names: BTreeSet<String>,
}

#[derive(Debug)]
struct Stmt {
    words: Vec<String>,
    line: usize,
    stack: Vec<String>,
}

/// Splits nginx configuration text into statements.
fn statements(text: &str) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut in_comment = false;
    let mut var_depth = 0u32;
    let mut line = 1usize;
    let mut stmt_line = 1usize;

    macro_rules! flush {
        () => {
            if !cur.is_empty() {
                if words.is_empty() {
                    stmt_line = line;
                }
                words.push(std::mem::take(&mut cur));
            }
        };
    }

    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
                line += 1;
            }
            continue;
        }
        if let Some(q) = quote {
            cur.push(c);
            if c == '\\' {
                if let Some(n) = it.next() {
                    cur.push(n);
                }
            } else if c == q {
                quote = None;
            } else if c == '\n' {
                line += 1;
            }
            continue;
        }
        match c {
            '#' if cur.is_empty() => in_comment = true,
            '\'' | '"' => {
                quote = Some(c);
                cur.push(c);
            }
            '{' if cur.ends_with('$') || var_depth > 0 => {
                var_depth += 1;
                cur.push(c);
            }
            '}' if var_depth > 0 => {
                var_depth -= 1;
                cur.push(c);
            }
            ';' => {
                flush!();
                if !words.is_empty() {
                    out.push(Stmt {
                        words: std::mem::take(&mut words),
                        line: stmt_line,
                        stack: stack.clone(),
                    });
                }
            }
            '{' => {
                flush!();
                let head = words.join(" ");
                out.push(Stmt {
                    words: std::mem::take(&mut words),
                    line: stmt_line,
                    stack: stack.clone(),
                });
                stack.push(head);
            }
            '}' => {
                flush!();
                if !words.is_empty() {
                    out.push(Stmt {
                        words: std::mem::take(&mut words),
                        line: stmt_line,
                        stack: stack.clone(),
                    });
                }
                stack.pop();
            }
            c if c.is_whitespace() => {
                flush!();
                if c == '\n' {
                    line += 1;
                }
            }
            _ => cur.push(c),
        }
    }
    out
}

/// Parses the destination of `proxy_pass`, `fastcgi_pass` or `server`.
/// Returns `None` for IPs, unix sockets and destinations with variables.
fn parse_addr(addr: &str) -> Option<(String, Option<u16>)> {
    let mut a = addr.trim().trim_matches(|c| c == '"' || c == '\'');
    for scheme in ["http://", "https://", "grpc://", "grpcs://"] {
        if let Some(r) = a.strip_prefix(scheme) {
            a = r;
            break;
        }
    }
    if a.starts_with("unix:") || a.contains('$') || a.is_empty() {
        return None;
    }
    let hostport = a.split('/').next().unwrap_or(a);
    if hostport.starts_with('[') {
        return None; // IPv6 literal
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (hostport, None),
    };
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some((host.to_string(), port))
}

const PASS_DIRECTIVES: &[&str] = &[
    "proxy_pass",
    "fastcgi_pass",
    "uwsgi_pass",
    "scgi_pass",
    "grpc_pass",
];

/// Reads `/etc/nginx/nginx.conf` and everything it includes.
pub fn collect(fs_root: &Path) -> Parsed {
    let prefix = "/etc/nginx";
    let main = util::glob(fs_root, &format!("{prefix}/nginx.conf"));
    let mut parsed = Parsed::default();
    let mut queue: Vec<PathBuf> = main;
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    while let Some(file) = queue.pop() {
        if parsed.files >= 5000 || !visited.insert(file.clone()) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&file) else {
            continue;
        };
        if !meta.is_file() || meta.len() > 4 << 20 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        parsed.files += 1;
        for st in statements(&text) {
            let w = &st.words;
            if w.is_empty() {
                continue;
            }
            if w[0] == "include" && w.len() >= 2 {
                let pat = w[1].trim_matches(|c| c == '"' || c == '\'');
                let abs = if pat.starts_with('/') {
                    pat.to_string()
                } else {
                    format!("{prefix}/{pat}")
                };
                queue.extend(util::glob(fs_root, &abs));
                continue;
            }
            if w[0] == "upstream" && w.len() >= 2 {
                parsed.upstream_names.insert(w[1].clone());
                continue;
            }
            let in_upstream = st.stack.iter().any(|s| s.starts_with("upstream "));
            let addr = if in_upstream && w[0] == "server" && w.len() >= 2 {
                Some((w[1].as_str(), "upstream server"))
            } else if PASS_DIRECTIVES.contains(&w[0].as_str()) && w.len() >= 2 {
                Some((w[1].as_str(), w[0].as_str()))
            } else {
                None
            };
            if let Some((a, directive)) = addr
                && let Some((host, port)) = parse_addr(a)
            {
                parsed.targets.push(Target {
                    host,
                    port,
                    file: file.clone(),
                    line: st.line,
                    directive: directive.to_string(),
                });
            }
        }
    }
    // `proxy_pass http://upstream_name` is not a host.
    let names = parsed.upstream_names.clone();
    parsed.targets.retain(|t| !names.contains(&t.host));
    parsed
        .targets
        .sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    parsed
}

pub fn resolves(host: &str, port: Option<u16>) -> bool {
    (host, port.unwrap_or(80))
        .to_socket_addrs()
        .map(|mut a| a.next().is_some())
        .unwrap_or(false)
}

fn show(fs_root: &Path, p: &Path) -> String {
    let s = p.strip_prefix(fs_root).unwrap_or(p);
    let s = if s.is_absolute() {
        s.to_path_buf()
    } else {
        Path::new("/").join(s)
    };
    util::path_display(&s)
}

/// Builds the checks. `resolver` and `nginx_t` are injected so this can be
/// tested without a network or nginx.
pub fn checks(
    fs_root: &Path,
    parsed: &Parsed,
    resolver: &dyn Fn(&str, Option<u16>) -> bool,
    nginx_t: Option<(bool, String)>,
) -> Vec<Check> {
    let mut v = Vec::new();
    let g = "Web server";

    match nginx_t {
        Some((true, out)) => {
            let warns = out.lines().filter(|l| l.contains("[warn]")).count();
            v.push(Check {
                group: g,
                name: "nginx -t".into(),
                status: if warns > 0 { Status::Warn } else { Status::Ok },
                detail: if warns > 0 {
                    format!("configuration valid, with {warns} warnings")
                } else {
                    "configuration valid".into()
                },
                fix: (warns > 0).then(|| "Run `nginx -t` to see them.".into()),
            });
        }
        Some((false, out)) => {
            let errs: Vec<String> = out
                .lines()
                .filter(|l| l.contains("[emerg]") || l.contains("[crit]"))
                .take(3)
                .map(|l| util::sanitize(l.trim()))
                .collect();
            v.push(Check {
                group: g,
                name: "nginx -t".into(),
                status: Status::Fail,
                detail: format!(
                    "the configuration is NOT valid: nginx will not be able to restart. {}",
                    if errs.is_empty() { util::sanitize(out.lines().next().unwrap_or("")) } else { errs.join(" | ") }
                ),
                fix: Some("Fix the error before the next restart (unattended-upgrades restarts nginx by itself).".into()),
            });
        }
        None => {}
    }

    if parsed.files == 0 {
        return v;
    }

    let mut unresolved: Vec<&Target> = Vec::new();
    let mut by_name: Vec<&Target> = Vec::new();
    for t in &parsed.targets {
        if resolver(&t.host, t.port) {
            by_name.push(t);
        } else {
            unresolved.push(t);
        }
    }
    let place = |t: &Target| {
        format!(
            "{} → {} ({}:{})",
            util::sanitize(&t.host),
            t.directive,
            show(fs_root, &t.file),
            t.line
        )
    };
    let list = |ts: &[&Target]| {
        let mut s: Vec<String> = ts.iter().take(5).map(|t| place(t)).collect();
        if ts.len() > 5 {
            s.push(format!("and {} more", ts.len() - 5));
        }
        s.join("; ")
    };

    if !unresolved.is_empty() {
        v.push(Check {
            group: g,
            name: "Destinations that do not resolve".into(),
            status: Status::Fail,
            detail: format!(
                "nginx will not start (\"host not found in upstream\"): {}",
                list(&unresolved)
            ),
            fix: Some("Replace the name with an IP (127.0.0.1) or remove the vhost.".into()),
        });
    }
    if !by_name.is_empty() {
        v.push(Check {
            group: g,
            name: "Destinations given by host name".into(),
            status: Status::Warn,
            detail: format!(
                "nginx resolves these names at startup; if resolution fails on a restart, ALL sites go down: {}",
                list(&by_name)
            ),
            fix: Some("Use an IP instead of a name (e.g. 127.0.0.1:1337 instead of localhost:1337).".into()),
        });
    }
    if unresolved.is_empty() && by_name.is_empty() {
        v.push(Check {
            group: g,
            name: "nginx destinations".into(),
            status: Status::Ok,
            detail: format!(
                "{} configuration files checked; no proxy_pass/upstream depends on host names",
                parsed.files
            ),
            fix: None,
        });
    }
    v
}

/// Runs the nginx checks on this server.
pub fn run(fs_root: &Path, live: bool) -> Vec<Check> {
    let parsed = collect(fs_root);
    let nginx_t = if live && crate::doctor::is_root() && util::find_bin("nginx").is_some() {
        util::run_cmd("nginx", &["-t"], Duration::from_secs(20))
            .map(|o| (o.ok, format!("{}{}", o.stderr, o.stdout)))
    } else {
        None
    };
    if parsed.files == 0 && nginx_t.is_none() {
        return Vec::new();
    }
    checks(fs_root, &parsed, &resolves, nginx_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const VHOST_BAD: &str = "
server {
    listen 80;
    server_name app.example.com;
    location / { proxy_pass http://app; }
}
upstream app {
    server localhost:1337;  # host name
}
";
    const VHOST_GOOD: &str = "
upstream app { server 127.0.0.1:1337; }
server { location / { proxy_pass http://app; } }
";

    fn tree(vhost: &str) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("etc/nginx");
        fs::create_dir_all(d.join("sites")).unwrap();
        fs::write(
            d.join("nginx.conf"),
            "http {\n  include mime.types;\n  include /etc/nginx/sites/*.conf;\n}\n",
        )
        .unwrap();
        fs::write(d.join("mime.types"), "types { text/html html; }\n").unwrap();
        fs::write(d.join("sites/app.conf"), vhost).unwrap();
        t
    }

    #[test]
    fn finds_hostname_upstream_like_the_incident() {
        let t = tree(VHOST_BAD);
        let p = collect(t.path());
        assert_eq!(p.files, 3);
        assert_eq!(p.targets.len(), 1, "{:#?}", p.targets);
        let x = &p.targets[0];
        assert_eq!(
            (x.host.as_str(), x.port, x.line),
            ("localhost", Some(1337), 8)
        );
        assert_eq!(x.directive, "upstream server");
        assert!(x.file.ends_with("sites/app.conf"));
    }

    #[test]
    fn ip_upstream_is_fine_and_upstream_names_are_not_hosts() {
        let t = tree(VHOST_GOOD);
        let p = collect(t.path());
        assert!(p.targets.is_empty(), "{:#?}", p.targets);
        assert!(p.upstream_names.contains("app"));
        let c = checks(t.path(), &p, &|_, _| true, Some((true, String::new())));
        assert!(c.iter().all(|c| c.status == Status::Ok), "{c:#?}");
    }

    #[test]
    fn unresolvable_is_fail_resolvable_is_warn() {
        let t = tree(VHOST_BAD);
        let p = collect(t.path());
        let c = checks(t.path(), &p, &|_, _| false, None);
        assert_eq!(c[0].status, Status::Fail);
        assert!(c[0].detail.contains("localhost"));
        assert!(
            c[0].detail.contains("/etc/nginx/sites/app.conf:8"),
            "{}",
            c[0].detail
        );
        let c = checks(t.path(), &p, &|_, _| true, None);
        assert_eq!(c[0].status, Status::Warn);
        assert!(c[0].fix.as_deref().unwrap().contains("127.0.0.1"));
    }

    #[test]
    fn nginx_t_failure_is_reported() {
        let t = tree(VHOST_GOOD);
        let p = collect(t.path());
        let out = "nginx: [emerg] host not found in upstream \"localhost\" in /etc/nginx/x.conf:8\nnginx: configuration file test failed\n";
        let c = checks(t.path(), &p, &|_, _| true, Some((false, out.into())));
        assert_eq!(c[0].status, Status::Fail);
        assert!(c[0].detail.contains("host not found in upstream"));
    }

    #[test]
    fn ignores_variables_unix_sockets_ips_and_comments() {
        for a in [
            "unix:/run/x.sock",
            "http://$backend",
            "http://10.0.0.1:80",
            "http://[::1]:80/x",
            "127.0.0.1:9000",
        ] {
            assert!(parse_addr(a).is_none(), "{a}");
        }
        assert_eq!(
            parse_addr("http://backend.internal:8080/x"),
            Some(("backend.internal".into(), Some(8080)))
        );
        let st = statements(
            "# server localhost:1;\nserver_name a; # proxy_pass http://x;\nlocation ~ ^/(a|b)${x} { return 200; }",
        );
        assert_eq!(st.iter().filter(|s| s.words[0] == "proxy_pass").count(), 0);
    }

    #[test]
    fn real_resolver() {
        assert!(resolves("localhost", Some(80)));
        assert!(!resolves("does-not-exist.invalid", Some(80)));
    }
}
