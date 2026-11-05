// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for `pwss scan` using HARMLESS fixtures that reproduce the
//! persistence layers of the 2026-11-04 incident (the "wpanel" malware) plus
//! several negative controls that guard against false positives.
//!
//! No fixture contains working code: only text that satisfies the patterns
//! the rules look for.

mod common;

use common::{core, write};
use pwss::config::Config;
use pwss::discovery::{Options, discover};
use pwss::scan::{self, Finding, Report, rules::Severity};
use std::fs;
use std::path::Path;

const SITE: &str = "var/www/u_usr/data/www/infected.com";

fn infected_server() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("usr/local/fastpanel2")).unwrap();
    core(r, SITE, "7.1.3");
    let c = format!("{SITE}/wp-content");

    // --- The five layers of the incident ---------------------------------
    // 1. Block at the end of a premium theme's functions.php.
    write(
        r,
        &format!("{c}/themes/Divi/style.css"),
        "/* Theme Name: Divi */",
    );
    write(
        r,
        &format!("{c}/themes/Divi/functions.php"),
        "<?php\nfunction divi_setup() { add_theme_support('title-tag'); }\nadd_action('after_setup_theme', 'divi_setup');\n\
         // WPANEL:BEGIN\n$p = gzinflate(base64_decode('AAAA'));\nfile_put_contents(dirname(__FILE__) . '/x.txt', $p);\n// WPANEL:END-AGENT\n",
    );
    // 2. db.php drop-in used as a loader.
    write(
        r,
        &format!("{c}/db.php"),
        "<?php\nrequire_once WP_CONTENT_DIR . '/languages/class-wp-locale-data.php';\n",
    );
    // 3. mu-plugin with a fake header.
    write(
        r,
        &format!("{c}/mu-plugins/wp-locale-bootstrap.php"),
        "<?php\n/*\nPlugin Name: Locale Bootstrap\nAuthor: WordPress\n*/\ninclude WP_CONTENT_DIR . '/languages/class-wp-locale-data.php';\n",
    );
    // 4. Payload in languages/, a copy in upgrade/ and a hidden path.
    let payload = "<?php\n// test marker\n$x = gzinflate(base64_decode('AAAA'));\neval($x);\n";
    write(
        r,
        &format!("{c}/languages/class-wp-locale-data.php"),
        payload,
    );
    write(
        r,
        &format!("{c}/upgrade/copia/class-wp-locale-data.php"),
        payload,
    );
    write(r, &format!("{c}/.wpanel/agent.php"), payload);

    // --- Others -----------------------------------------------------------
    write(
        r,
        &format!("{c}/uploads/2026/shell.php"),
        "<?php @eval($_POST['a']);\n",
    );
    write(r, &format!("{c}/uploads/2026/foto.php.jpg"), "GIF89a");
    write(
        r,
        &format!("{c}/uploads/.htaccess"),
        "AddHandler application/x-httpd-php .jpg .png\n",
    );
    write(
        r,
        &format!("{SITE}/.user.ini"),
        "auto_prepend_file = /tmp/x.php\n",
    );
    write(r, &format!("{SITE}/zz-backdoor.php"), "<?php echo 1;\n");
    write(
        r,
        &format!("{c}/plugins/hello/.cache2/a.php"),
        "<?php // empty\n",
    );
    // A plugin with base64 + eval: only in --deep.
    write(
        r,
        &format!("{c}/plugins/hello/hello.php"),
        "<?php\neval(base64_decode($data));\n",
    );

    // --- Negative controls (must not reach medium severity or higher) ----
    write(
        r,
        &format!("{c}/index.php"),
        "<?php\n// Silence is golden.\n",
    );
    write(
        r,
        &format!("{c}/uploads/index.php"),
        "<?php\n// Silence is golden.\n",
    );
    write(r, &format!("{c}/uploads/2026/foto.jpg"), "GIF89a");
    write(
        r,
        &format!("{c}/languages/es_ES.l10n.php"),
        "<?php\nreturn ['domain' => 'default', 'messages' => []];\n",
    );
    write(r, &format!("{c}/languages/es_ES.mo"), "binary");
    write(
        r,
        &format!("{c}/mu-plugins/hosting.php"),
        "<?php\n/* Plugin Name: Hosting */\nadd_filter('x', '__return_true');\n",
    );
    write(
        r,
        &format!("{c}/themes/twentytwentysix/functions.php"),
        "<?php\nfunction t_setup() { add_theme_support('title-tag'); }\n",
    );
    write(
        r,
        &format!("{c}/plugins/legit/legit.php"),
        "<?php\n$wpdb->exec('SET NAMES utf8');\n$pdo->exec('x');\n$d = base64_decode($img);\nfile_put_contents($f, $d);\n",
    );
    t
}

fn run(t: &tempfile::TempDir, deep: bool, min: Severity, cfg: &Config) -> Report {
    let d = discover(
        cfg,
        &Options {
            fs_root: t.path(),
            extra_roots: &[],
        },
    );
    let opts = scan::Options {
        deep,
        threads: 2,
        min_severity: min,
        ..Default::default()
    };
    scan::run(&d.sites, cfg, &opts)
}

fn find<'a>(r: &'a Report, ends: &str) -> Option<&'a Finding> {
    r.findings
        .iter()
        .find(|f| f.path.to_string_lossy().ends_with(ends))
}

fn rules_of(f: &Finding) -> Vec<&'static str> {
    f.reasons.iter().map(|h| h.rule).collect()
}

#[test]
fn finds_every_layer_of_the_wpanel_incident() {
    let t = infected_server();
    let r = run(&t, false, Severity::Low, &Config::default());

    let f = find(&r, "themes/Divi/functions.php").expect("functions.php");
    assert_eq!(f.severity, Severity::Critical);
    assert!(rules_of(f).contains(&"ioc.wpanel"));
    assert!(rules_of(f).contains(&"code.decode-write"));

    let f = find(&r, "wp-content/db.php").expect("db.php");
    assert!(f.severity >= Severity::High, "{f:#?}");
    assert!(rules_of(f).contains(&"persist.dropin"));
    assert!(rules_of(f).contains(&"code.include-from-data-dir"));

    let f = find(&r, "mu-plugins/wp-locale-bootstrap.php").expect("mu-plugin");
    assert_eq!(f.severity, Severity::Critical);
    assert!(rules_of(f).contains(&"code.fake-wordpress-header"));
    assert!(rules_of(f).contains(&"ioc.wpanel-filename"));

    let f = find(&r, "languages/class-wp-locale-data.php").expect("languages");
    assert_eq!(f.severity, Severity::Critical);
    assert!(rules_of(f).contains(&"persist.php-in-languages"));

    let f = find(&r, "upgrade/copia/class-wp-locale-data.php").expect("upgrade");
    assert!(f.severity >= Severity::High);

    let f = find(&r, ".wpanel/agent.php").expect("hidden");
    assert!(f.severity >= Severity::High);
    assert!(rules_of(f).contains(&"persist.php-in-hidden-dir"));
}

#[test]
fn finds_webshells_and_persistence_outside_the_five_layers() {
    let t = infected_server();
    let r = run(&t, false, Severity::Low, &Config::default());

    let f = find(&r, "uploads/2026/shell.php").unwrap();
    assert_eq!(f.severity, Severity::Critical);
    assert!(rules_of(f).contains(&"persist.php-in-uploads"));
    assert!(rules_of(f).contains(&"code.exec-user-input"));
    assert!(f.sha256.as_deref().is_some_and(|h| h.len() == 64));

    assert!(find(&r, "foto.php.jpg").unwrap().severity >= Severity::Medium);
    assert_eq!(
        find(&r, "uploads/.htaccess").unwrap().severity,
        Severity::High
    );
    assert_eq!(find(&r, ".user.ini").unwrap().severity, Severity::High);
    assert!(find(&r, "zz-backdoor.php").unwrap().severity >= Severity::Medium);
    // A hidden folder inside a plugin is reported once, as the folder; its
    // harmless file is not reported on its own.
    let d = find(&r, "hello/.cache2").unwrap();
    assert_eq!(d.severity, Severity::Medium);
    assert!(rules_of(d).contains(&"persist.hidden-dir"));
    assert!(find(&r, ".cache2/a.php").is_none());
}

#[test]
fn hidden_plugin_folder_does_not_flood_the_report() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    core(r, SITE, "6.8");
    let c = format!("{SITE}/wp-content");
    for i in 0..50 {
        write(
            r,
            &format!("{c}/plugins/.legacy-plugin/inc/part{i}.php"),
            "<?php\nfunction f() { return 1; }\n",
        );
    }
    let rep = run(&t, false, Severity::Low, &Config::default());
    let hits: Vec<_> = rep
        .findings
        .iter()
        .filter(|f| f.path.to_string_lossy().contains(".legacy-plugin"))
        .collect();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].severity, Severity::Medium);
}

#[test]
fn one_finding_per_file_with_several_reasons() {
    let t = infected_server();
    let r = run(&t, false, Severity::Low, &Config::default());
    let mut paths: Vec<_> = r.findings.iter().map(|f| f.path.clone()).collect();
    let n = paths.len();
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), n);
    let f = find(&r, "languages/class-wp-locale-data.php").unwrap();
    assert!(f.reasons.len() >= 3);
    // Sorted from most to least severe.
    assert!(f.reasons.windows(2).all(|w| w[0].severity >= w[1].severity));
}

#[test]
fn negative_controls_stay_quiet() {
    let t = infected_server();
    let r = run(&t, false, Severity::Medium, &Config::default());
    for quiet in [
        "wp-content/index.php",
        "uploads/index.php",
        "uploads/2026/foto.jpg",
        "es_ES.l10n.php",
        "es_ES.mo",
        "mu-plugins/hosting.php",
        "twentytwentysix/functions.php",
        "plugins/legit/legit.php",
        "index.php",
        "wp-config.php",
    ] {
        assert!(
            find(&r, quiet).is_none(),
            "falso positivo en {quiet}: {:#?}",
            find(&r, quiet)
        );
    }
    // The legitimate l10n file does not show up even at maximum detail.
    let all = run(&t, false, Severity::Info, &Config::default());
    assert!(find(&all, "es_ES.l10n.php").is_none());
    assert!(find(&all, "uploads/index.php").is_none());
}

#[test]
fn mu_plugin_listing_is_low() {
    let t = infected_server();
    let r = run(&t, false, Severity::Low, &Config::default());
    let f = find(&r, "mu-plugins/hosting.php").unwrap();
    assert_eq!(f.severity, Severity::Low);
    assert!(rules_of(f).contains(&"persist.mu-plugin"));
}

#[test]
fn deep_mode_adds_plugin_code_normal_mode_does_not() {
    let t = infected_server();
    let normal = run(&t, false, Severity::Medium, &Config::default());
    assert!(find(&normal, "plugins/hello/hello.php").is_none());
    let deep = run(&t, true, Severity::Medium, &Config::default());
    let f = find(&deep, "plugins/hello/hello.php").expect("deep");
    assert_eq!(f.severity, Severity::Medium);
    assert!(rules_of(f).contains(&"code.b64-eval"));
    // The legitimate plugin still stays out, even in deep mode.
    assert!(find(&deep, "plugins/legit/legit.php").is_none());
    assert!(deep.stats.analysed > normal.stats.analysed);
}

#[test]
fn allow_list_and_ignore_rules() {
    let t = infected_server();
    let base = run(&t, false, Severity::Medium, &Config::default());
    let sh = find(&base, "uploads/2026/shell.php")
        .unwrap()
        .sha256
        .clone()
        .unwrap();

    let mut cfg = Config::default();
    cfg.scan.allow_sha256.push(sh.to_uppercase());
    let r = run(&t, false, Severity::Medium, &cfg);
    assert!(find(&r, "uploads/2026/shell.php").is_none());
    assert!(find(&r, "languages/class-wp-locale-data.php").is_some());

    let mut cfg = Config::default();
    cfg.scan.ignore_rules.push("persist.dropin".into());
    let r = run(&t, false, Severity::Low, &cfg);
    let f = find(&r, "wp-content/db.php").unwrap();
    assert!(!rules_of(f).contains(&"persist.dropin"));

    let mut cfg = Config::default();
    cfg.scan.ignore_paths.push(
        t.path()
            .canonicalize()
            .unwrap()
            .join(SITE)
            .join("wp-content/uploads"),
    );
    let r = run(&t, false, Severity::Low, &cfg);
    assert!(
        r.findings
            .iter()
            .all(|f| !f.path.to_string_lossy().contains("/uploads/"))
    );
}

#[test]
fn min_severity_hides_and_counts() {
    let t = infected_server();
    let r = run(&t, false, Severity::Critical, &Config::default());
    assert!(r.findings.iter().all(|f| f.severity == Severity::Critical));
    assert!(r.hidden_below_min > 0);
}

#[test]
fn symlinks_are_never_followed() {
    let t = infected_server();
    let up = t.path().join(SITE).join("wp-content/uploads");
    std::os::unix::fs::symlink("/etc/passwd", up.join("pass.php")).unwrap();
    std::os::unix::fs::symlink("/etc", up.join("etc")).unwrap();
    let r = run(&t, true, Severity::Low, &Config::default());
    let f = find(&r, "uploads/pass.php").expect("symlink flagged");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(rules_of(f), vec!["persist.symlink-out"]);
    assert!(f.sha256.is_none(), "must not read the target");
    assert!(f.reasons.iter().all(|h| h.evidence.is_none()));
    // Does not descend into the linked directory.
    assert!(
        r.findings
            .iter()
            .all(|f| !f.path.to_string_lossy().contains("uploads/etc/"))
    );
}

#[test]
fn fifo_does_not_hang() {
    let t = infected_server();
    let fifo = t
        .path()
        .join(SITE)
        .join("wp-content/uploads/fifo-block.php");
    let ok = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("mkfifo not available; test skipped");
        return;
    }
    let r = run(&t, true, Severity::Low, &Config::default());
    assert!(find(&r, "fifo-block.php").is_none());
}

#[test]
fn hostile_file_names_are_sanitized_for_display() {
    let t = infected_server();
    let up = t.path().join(SITE).join("wp-content/uploads");
    let evil = "ev\x1b[2Jil\u{202e}gpj.php".to_string();
    fs::write(up.join(&evil), "<?php echo 1;").unwrap();
    let r = run(&t, false, Severity::Low, &Config::default());
    let f = r
        .findings
        .iter()
        .find(|f| f.path.to_string_lossy().contains("ev\x1b"))
        .expect("found");
    let shown = pwss::util::path_display(&f.path);
    assert!(
        !shown.contains('\x1b') && !shown.contains('\u{202e}'),
        "{shown}"
    );
}

#[test]
fn output_never_contains_database_password() {
    let t = infected_server();
    let r = run(&t, true, Severity::Info, &Config::default());
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("'p'"));
}

#[test]
fn nested_sites_are_not_scanned_twice() {
    let t = infected_server();
    let nested = format!("{SITE}/development");
    core(t.path(), &nested, "6.8.2");
    write(
        t.path(),
        &format!("{nested}/wp-content/uploads/x.php"),
        "<?php @eval($_POST['a']);",
    );
    let r = run(&t, true, Severity::Low, &Config::default());
    let n = r
        .findings
        .iter()
        .filter(|f| {
            f.path
                .to_string_lossy()
                .ends_with("development/wp-content/uploads/x.php")
        })
        .count();
    assert_eq!(n, 1);
    let f = find(&r, "development/wp-content/uploads/x.php").unwrap();
    assert!(f.site.contains("development"), "{}", f.site);
}

#[test]
fn clean_site_has_no_findings_at_default_level() {
    let t = tempfile::tempdir().unwrap();
    core(t.path(), "var/www/a_usr/data/www/ok.com", "7.1.3");
    write(
        t.path(),
        "var/www/a_usr/data/www/ok.com/wp-content/index.php",
        "<?php // Silence is golden.",
    );
    write(
        t.path(),
        "var/www/a_usr/data/www/ok.com/wp-content/themes/t/functions.php",
        "<?php function a() {}",
    );
    fs::create_dir_all(t.path().join("usr/local/fastpanel2")).unwrap();
    let r = run(&t, true, Severity::Medium, &Config::default());
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
    assert!(Path::new(&r.stats.files.to_string()).to_str().is_some());
}
