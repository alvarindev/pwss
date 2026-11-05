// SPDX-License-Identifier: GPL-3.0-or-later
//! Detection rules.
//!
//! Everything is static text analysis: nothing is ever executed. The rules
//! are designed to raise few false alarms in the zones where malware hides to
//! persist (mu-plugins, drop-ins, `languages/`, `upgrade/`, `uploads/`,
//! hidden folders...), where almost any PHP is suspicious, and to be more
//! cautious in the rest of the code.

use crate::util::snippet;
use regex::bytes::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn bump(self) -> Self {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

/// Zone of `wp-content` where the file lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    MuPlugin,
    DropIn,
    ContentRoot,
    Uploads,
    Languages,
    Upgrade,
    Hidden,
    ThemeEntry,
    CoreRoot,
    Config,
    Other,
}

impl Zone {
    /// Persistence zones: any finding weighs more there.
    pub fn hot(self) -> bool {
        !matches!(self, Zone::ThemeEntry | Zone::Other)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub rule: &'static str,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

fn hit(rule: &'static str, severity: Severity, message: &str, evidence: Option<String>) -> Hit {
    Hit {
        rule,
        severity,
        message: message.to_string(),
        evidence,
    }
}

// ---------------------------------------------------------------------------
// Patrones
// ---------------------------------------------------------------------------

struct P {
    classes: RegexSet,
    strong_decode: Regex,
    weak_decode: Regex,
    eval_fn: Regex,
    exec_fn: Regex,
    exec_input: Regex,
    include_input: Regex,
    var_func_input: Regex,
    b64_input: Regex,
    remote_include: Regex,
    eval_remote: Regex,
    self_write: Regex,
    hex_run: Regex,
    chr_chain: Regex,
    long_b64: Regex,
    hidden_code: Regex,
    include_data_dir: Regex,
    fake_header: Regex,
    ioc: Regex,
    ht_handler_php: Regex,
    ht_handler_media: Regex,
    ht_prepend: Regex,
    ht_cgi: Regex,
    ht_cloak: Regex,
    ini_prepend: Regex,
    ini_url_include: Regex,
    l10n_ok: Regex,
    silence: Regex,
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap_or_else(|e| panic!("invalid regex {p}: {e}"))
}

fn p() -> &'static P {
    static S: OnceLock<P> = OnceLock::new();
    S.get_or_init(|| {
        let strong = r"(?i)\b(?:gzinflate|gzuncompress|gzdecode|convert_uudecode|str_rot13)\s*\(";
        let weak = r#"(?i)\b(?:base64_decode|hex2bin)\s*\(|\bpack\s*\(\s*['"]H\*?['"]"#;
        let evalf = r"(?i)\b(?:eval|create_function)\s*\(|\bassert\s*\(\s*(?:\$|base64_decode|gz|str_rot13)";
        let writef = r#"(?i)\b(?:file_put_contents|fwrite|fputs)\s*\(|\bfopen\s*\([^)]{0,200}['"][wax]\+?b?['"]"#;
        let execf = r"(?i)\b(?:system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(";
        P {
            classes: RegexSet::new([strong, weak, evalf, writef, execf, r"(?i)\$_(?:GET|POST|REQUEST|COOKIE)\b"])
                .unwrap(),
            strong_decode: re(strong),
            weak_decode: re(weak),
            eval_fn: re(evalf),
            exec_fn: re(execf),
            exec_input: re(
                r"(?is)\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open|create_function|pcntl_exec)\s*\(\s*[^;]{0,120}?\$_(?:GET|POST|REQUEST|COOKIE)\b",
            ),
            include_input: re(r"(?i)\b(?:include|require)(?:_once)?\b\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
            var_func_input: re(r"(?i)\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\["),
            b64_input: re(r"(?i)\b(?:base64_decode|gzinflate|str_rot13)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
            remote_include: re(r#"(?i)\b(?:include|require)(?:_once)?\b\s*\(?\s*['"]https?://"#),
            eval_remote: re(r"(?i)\beval\s*\(\s*@?(?:file_get_contents|curl_exec|gzinflate\s*\(\s*file_get_contents)"),
            self_write: re(
                r#"(?i)\b(?:file_put_contents|fopen)\s*\(\s*(?:__FILE__|dirname\s*\(\s*__FILE__\s*\)|__DIR__)"#,
            ),
            hex_run: re(r"(?:\\x[0-9a-fA-F]{2}){30,}"),
            chr_chain: re(r"(?i)(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){10,}"),
            long_b64: re(r"[A-Za-z0-9+/]{2000,}={0,2}"),
            hidden_code: re(r"[ \t]{300,}\S"),
            include_data_dir: re(
                r#"(?is)\b(?:include|require)(?:_once)?\b[^;]{0,200}?[/\\'"](?:languages|upgrade|uploads|\.[a-z0-9_-]{2,})[/\\'"][^;]{0,160}?\.php"#,
            ),
            fake_header: re(r"(?im)^[\s/*#]*Author(?:\s+URI)?\s*:\s*(?:WordPress\b|https?://wordpress\.org)"),
            // Indicators of the "wpanel" incident (2026-11-04).
            ioc: re(r"(?i)wpanel:begin|wpanel:end|wpanel_cron_heartbeat|wpanel_agent|\.wpanel[/\\]"),
            ht_handler_php: re(r"(?im)^\s*(?:AddHandler|SetHandler|AddType)\s+[^#\n]*php"),
            ht_handler_media: re(
                r"(?im)^\s*(?:AddHandler|AddType)\s+\S*php\S*\s+[^#\n]*\.(?:jpe?g|png|gif|ico|txt|svg|css|js|html?|log|dat|bak|tmp|webp)\b",
            ),
            ht_prepend: re(r"(?im)^\s*php_(?:admin_)?value\s+auto_(?:prepend|append)_file\s+(\S+)"),
            ht_cgi: re(r"(?im)^\s*(?:Options\s+[^#\n]*\+ExecCGI|AddHandler\s+cgi-script)"),
            ht_cloak: re(
                r"(?is)RewriteCond\s+%\{HTTP_(?:REFERER|USER_AGENT)\}[^\n]*(?:google|bing|yahoo|baidu|yandex)[^\n]*\n(?:\s*RewriteCond[^\n]*\n)*\s*RewriteRule\s+\S+\s+https?://",
            ),
            ini_prepend: re(r"(?im)^\s*auto_(?:prepend|append)_file\s*=\s*([^\s;]+)"),
            ini_url_include: re(r"(?im)^\s*allow_url_include\s*=\s*(?:1|on|true|yes)\b"),
            l10n_ok: re(r"(?s)\A\s*<\?php\s*(?://[^\n]*\n\s*)?return\s*(?:array\s*\(|\[)"),
            silence: re(r"(?i)silence is golden"),
        }
    })
}

/// Is the file the typical empty "Silence is golden" `index.php`?
pub fn is_silence_is_golden(data: &[u8]) -> bool {
    data.len() < 200 && p().silence.is_match(data)
}

/// Extensions the server executes as PHP.
pub fn is_php_ext(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    match n.rsplit_once('.') {
        Some((_, ext)) => matches!(
            ext,
            "php"
                | "php3"
                | "php4"
                | "php5"
                | "php6"
                | "php7"
                | "php8"
                | "phtml"
                | "pht"
                | "phar"
                | "phps"
                | "inc"
        ),
        None => false,
    }
}

/// Extensions that are executed directly (without `inc`).
pub fn is_exec_ext(name: &str) -> bool {
    is_php_ext(name) && !name.to_ascii_lowercase().ends_with(".inc")
}

/// Name with a double extension such as `x.php.jpg`.
pub fn has_double_ext(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let parts: Vec<&str> = n.split('.').collect();
    parts.len() > 2
        && parts[1..parts.len() - 1].iter().any(|e| {
            matches!(
                *e,
                "php" | "php3" | "php4" | "php5" | "php7" | "phtml" | "pht" | "phar"
            )
        })
}

/// A legitimate `.l10n.php` translation file (returns an array).
pub fn is_legit_l10n(name: &str, data: &[u8]) -> bool {
    name.to_ascii_lowercase().ends_with(".l10n.php") && p().l10n_ok.is_match(data)
}

/// A "bare" call: not preceded by `->` or `::` (so `$pdo->exec()` is not
/// confused with `exec()`).
fn standalone_find(r: &Regex, data: &[u8]) -> Option<(usize, usize)> {
    r.find_iter(data)
        .find(|m| {
            let s = m.start();
            if s == 0 {
                return true;
            }
            let prev = data[s - 1];
            let prev2 = if s >= 2 { data[s - 2] } else { 0 };
            !(prev == b'>' && prev2 == b'-') && !(prev == b':' && prev2 == b':')
        })
        .map(|m| (m.start(), m.end()))
}

// ---------------------------------------------------------------------------
// PHP code analysis
// ---------------------------------------------------------------------------

pub fn analyze_php(data: &[u8], zone: Zone) -> Vec<Hit> {
    let p = p();
    let mut hits: Vec<Hit> = Vec::new();
    let ev = |m: Option<(usize, usize)>| m.map(|(s, e)| snippet(data, s, e, 110));

    // Known indicators.
    if let Some(m) = p.ioc.find(data) {
        hits.push(hit(
            "ioc.wpanel",
            Severity::Critical,
            "contains an indicator of the \"wpanel\" malware (2026-11-04 incident)",
            ev(Some((m.start(), m.end()))),
        ));
    }

    // User input reaching execution.
    if let Some(m) = p.exec_input.find(data) {
        hits.push(hit(
            "code.exec-user-input",
            Severity::Critical,
            "executes code or commands with request data ($_GET/$_POST/...): webshell behaviour",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if let Some(m) = p.include_input.find(data) {
        hits.push(hit(
            "code.include-user-input",
            Severity::Critical,
            "include/require with a path taken from the request",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if let Some(m) = p.remote_include.find(data) {
        hits.push(hit(
            "code.remote-include",
            Severity::Critical,
            "include/require of a remote URL",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if let Some(m) = p.eval_remote.find(data) {
        hits.push(hit(
            "code.eval-remote",
            Severity::High,
            "eval() of downloaded content",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if let Some(m) = p.var_func_input.find(data) {
        hits.push(hit(
            "code.var-func-user-input",
            Severity::High,
            "calls a function whose name is held in a variable with request data",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if let Some(m) = p.b64_input.find(data) {
        hits.push(hit(
            "code.decode-user-input",
            Severity::High,
            "decodes request data (typical of webshell loaders)",
            ev(Some((m.start(), m.end()))),
        ));
    }

    // Decode + write/execute combinations.
    let classes = p.classes.matches(data);
    let (strong, weak, evalf, write, execf) = (
        classes.matched(0),
        classes.matched(1),
        classes.matched(2),
        classes.matched(3),
        classes.matched(4),
    );
    let exec_real = execf && standalone_find(&p.exec_fn, data).is_some();
    let first = |r: &Regex| r.find(data).map(|m| (m.start(), m.end()));

    if strong && evalf {
        hits.push(hit(
            "code.decode-eval",
            Severity::High,
            "decompresses/decodes and runs with eval (classic malware obfuscation)",
            ev(first(&p.strong_decode)),
        ));
    }
    if strong && write {
        hits.push(hit(
            "code.decode-write",
            Severity::High,
            "decompresses/decodes and writes files (can regenerate other malicious files)",
            ev(first(&p.strong_decode)),
        ));
    }
    if strong && exec_real {
        hits.push(hit(
            "code.decode-exec",
            Severity::High,
            "decompresses/decodes and runs system commands",
            ev(first(&p.strong_decode)),
        ));
    }
    if weak && evalf && !strong {
        hits.push(hit(
            "code.b64-eval",
            Severity::Medium,
            "decodes base64/hex and uses eval",
            ev(first(&p.weak_decode)),
        ));
    }
    if weak && exec_real && !strong {
        hits.push(hit(
            "code.b64-exec",
            Severity::Medium,
            "decodes base64/hex and runs system commands",
            ev(first(&p.weak_decode)),
        ));
    }
    if weak && write && !strong && !evalf {
        hits.push(hit(
            "code.b64-write",
            Severity::Low,
            "decodes base64/hex and writes files (common in legitimate code)",
            ev(first(&p.weak_decode)),
        ));
    }
    if evalf && !strong && !weak && !hits.iter().any(|h| h.severity >= Severity::Medium) {
        hits.push(hit(
            "code.eval",
            Severity::Low,
            "uses eval()",
            ev(first(&p.eval_fn)),
        ));
    }
    if let Some(m) = p.self_write.find(data) {
        hits.push(hit(
            "code.self-write",
            Severity::Medium,
            "rewrites itself or its own folder (persistence)",
            ev(Some((m.start(), m.end()))),
        ));
    }

    // Obfuscation.
    if let Some(m) = p.hex_run.find(data) {
        hits.push(hit(
            "code.hex-escapes",
            Severity::Medium,
            "strings written with \\x.. sequences (obfuscation)",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if let Some(m) = p.chr_chain.find(data) {
        hits.push(hit(
            "code.chr-chain",
            Severity::Medium,
            "text built character by character with chr() (obfuscation)",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if let Some(m) = p.long_b64.find_iter(data).find(|m| {
        let before = &data[m.start().saturating_sub(40)..m.start()];
        !before
            .windows(7)
            .any(|w| w.eq_ignore_ascii_case(b"base64,"))
    }) {
        let sev = if strong || weak || evalf {
            Severity::Medium
        } else {
            Severity::Low
        };
        hits.push(hit(
            "code.long-encoded-string",
            sev,
            "very long encoded string (over 2000 characters)",
            ev(Some((m.start(), (m.start() + 30).min(m.end())))),
        ));
    }
    if let Some(m) = p.hidden_code.find(data) {
        hits.push(hit(
            "code.hidden-after-spaces",
            Severity::Medium,
            "code hidden behind hundreds of spaces on the same line",
            ev(Some((m.end().saturating_sub(40), m.end()))),
        ));
    }
    if let Some(m) = p.include_data_dir.find(data) {
        hits.push(hit(
            "code.include-from-data-dir",
            Severity::High,
            "includes a PHP file from languages/, upgrade/, uploads/ or a hidden folder (payload loader)",
            ev(Some((m.start(), m.end()))),
        ));
    }
    if matches!(zone, Zone::MuPlugin | Zone::DropIn | Zone::ContentRoot)
        && let Some(m) = p.fake_header.find(data)
    {
        hits.push(hit(
            "code.fake-wordpress-header",
            Severity::Medium,
            "\"Author: WordPress\" header in a file that is not from WordPress (disguise)",
            ev(Some((m.start(), m.end()))),
        ));
    }

    // In persistence zones every finding weighs one level more.
    if zone.hot() {
        for h in &mut hits {
            if h.severity >= Severity::Low {
                h.severity = h.severity.bump();
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// .htaccess, .user.ini, php.ini
// ---------------------------------------------------------------------------

pub fn analyze_htaccess(data: &[u8], zone: Zone) -> Vec<Hit> {
    let p = p();
    let mut hits = Vec::new();
    let risky_zone = matches!(
        zone,
        Zone::Uploads | Zone::Languages | Zone::Upgrade | Zone::Hidden | Zone::MuPlugin
    );
    let ev = |m: regex::bytes::Match| Some(snippet(data, m.start(), m.end(), 110));

    if let Some(m) = p.ht_handler_media.find(data) {
        hits.push(hit(
            "htaccess.php-for-media",
            Severity::High,
            "makes image or text files execute as PHP",
            ev(m),
        ));
    } else if risky_zone && let Some(m) = p.ht_handler_php.find(data) {
        hits.push(hit(
            "htaccess.php-handler-in-data-dir",
            Severity::High,
            "enables PHP execution in a data folder",
            ev(m),
        ));
    }
    for c in p.ht_prepend.captures_iter(data) {
        let v = &c[1];
        if v.eq_ignore_ascii_case(b"none") || v == b"\"\"" || v == b"''" || v == b"0" {
            continue;
        }
        let m = c.get(0).unwrap();
        hits.push(hit(
            "htaccess.auto-prepend",
            Severity::High,
            "auto_prepend_file/auto_append_file: runs a PHP file before or after every page",
            ev(m),
        ));
        break;
    }
    if let Some(m) = p.ht_cgi.find(data) {
        let sev = if risky_zone {
            Severity::High
        } else {
            Severity::Medium
        };
        hits.push(hit("htaccess.cgi", sev, "enables CGI execution", ev(m)));
    }
    if let Some(m) = p.ht_cloak.find(data) {
        hits.push(hit(
            "htaccess.search-cloak",
            Severity::High,
            "redirects by referrer (Google/Bing...) to another domain: typical SEO spam",
            ev(m),
        ));
    }
    hits
}

pub fn analyze_ini(data: &[u8]) -> Vec<Hit> {
    let p = p();
    let mut hits = Vec::new();
    for c in p.ini_prepend.captures_iter(data) {
        let v = &c[1];
        if v == b"\"\"" || v == b"''" || v.eq_ignore_ascii_case(b"none") || v == b"0" {
            continue;
        }
        let m = c.get(0).unwrap();
        hits.push(hit(
            "ini.auto-prepend",
            Severity::High,
            "auto_prepend_file/auto_append_file: runs a PHP file on every request without touching the site files",
            Some(snippet(data, m.start(), m.end(), 110)),
        ));
        break;
    }
    if let Some(m) = p.ini_url_include.find(data) {
        hits.push(hit(
            "ini.allow-url-include",
            Severity::High,
            "allow_url_include enabled: allows including remote URLs",
            Some(snippet(data, m.start(), m.end(), 110)),
        ));
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worst(h: &[Hit]) -> Option<Severity> {
        h.iter().map(|x| x.severity).max()
    }

    #[test]
    fn webshell_is_critical() {
        let h = analyze_php(b"<?php @eval($_POST['a']);", Zone::Other);
        assert_eq!(worst(&h), Some(Severity::Critical));
    }

    #[test]
    fn pdo_exec_is_not_a_command() {
        let h = analyze_php(
            b"<?php $pdo->exec('SET NAMES utf8'); $x = base64_decode($s); file_put_contents($f, $x);",
            Zone::Other,
        );
        assert!(h.iter().all(|x| x.severity <= Severity::Low), "{h:#?}");
    }

    #[test]
    fn decode_and_write_is_high_and_critical_in_hot_zone() {
        let src = b"<?php $a = gzinflate(base64_decode('AAAA')); file_put_contents('x.php', $a);";
        assert_eq!(
            worst(&analyze_php(src, Zone::ThemeEntry)),
            Some(Severity::High)
        );
        assert_eq!(
            worst(&analyze_php(src, Zone::MuPlugin)),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn legit_code_is_quiet() {
        let src = b"<?php\nfunction mytheme_setup() { add_theme_support('title-tag'); }\n$x = json_decode($s);\n";
        assert!(analyze_php(src, Zone::ThemeEntry).is_empty());
    }

    #[test]
    fn data_url_base64_not_flagged() {
        let mut s = b"<?php $img = 'data:image/png;base64,".to_vec();
        s.extend(std::iter::repeat_n(b'A', 3000));
        s.extend_from_slice(b"';");
        assert!(analyze_php(&s, Zone::Other).is_empty());
    }

    #[test]
    fn l10n_files() {
        assert!(is_legit_l10n(
            "es_ES.l10n.php",
            b"<?php\nreturn ['domain'=>'default'];"
        ));
        assert!(!is_legit_l10n("es_ES.l10n.php", b"<?php\neval($x);"));
        assert!(!is_legit_l10n(
            "class-wp-locale-data.php",
            b"<?php return [];"
        ));
    }

    #[test]
    fn extensions() {
        assert!(is_exec_ext("a.PHP"));
        assert!(is_exec_ext("a.phtml"));
        assert!(!is_exec_ext("a.jpg"));
        assert!(has_double_ext("shell.php.jpg"));
        assert!(!has_double_ext("jquery.min.js"));
    }

    #[test]
    fn htaccess_rules() {
        let h = analyze_htaccess(
            b"AddHandler application/x-httpd-php .jpg .png\n",
            Zone::Other,
        );
        assert_eq!(worst(&h), Some(Severity::High));
        let h = analyze_htaccess(b"AddHandler application/x-httpd-php83 .php\n", Zone::Other);
        assert!(h.is_empty());
        let h = analyze_htaccess(
            b"AddHandler application/x-httpd-php83 .php\n",
            Zone::Uploads,
        );
        assert_eq!(worst(&h), Some(Severity::High));
        let h = analyze_htaccess(b"php_value auto_prepend_file none\n", Zone::Other);
        assert!(h.is_empty());
        let h = analyze_htaccess(b"php_value auto_prepend_file /tmp/x.php\n", Zone::Other);
        assert_eq!(worst(&h), Some(Severity::High));
    }

    #[test]
    fn ini_rules() {
        assert!(analyze_ini(b"auto_prepend_file =\n").is_empty());
        assert_eq!(
            worst(&analyze_ini(b"auto_prepend_file = /x/a.php\n")),
            Some(Severity::High)
        );
    }
}
