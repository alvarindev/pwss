// SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery tests against a fake server that reproduces real-world layouts:
//! FastPanel, nested copies, split configuration, Bedrock...

use pwss::config::Config;
use pwss::discovery::{Layout, Options, discover};
use pwss::panel::Panel;
use std::fs;
use std::path::Path;

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

fn core(root: &Path, dir: &str, version: &str) {
    write(
        root,
        &format!("{dir}/wp-includes/version.php"),
        &format!("<?php\n$wp_version = '{version}';\n"),
    );
    write(root, &format!("{dir}/wp-settings.php"), "<?php\n");
    write(root, &format!("{dir}/wp-blog-header.php"), "<?php\n");
    fs::create_dir_all(root.join(dir).join("wp-content/plugins")).unwrap();
    fs::create_dir_all(root.join(dir).join("wp-admin")).unwrap();
}

fn std_config(db: &str, prefix: &str) -> String {
    format!(
        "<?php\n// Configuration\ndefine( 'DB_NAME', '{db}' );\ndefine( 'DB_USER', 'u' );\n\
         define( 'DB_PASSWORD', 's3cr3t' );\ndefine( 'DB_HOST', 'localhost' );\n\
         /* define('DB_NAME', 'commented-out'); */\n$table_prefix = '{prefix}';\n\
         if ( ! defined( 'ABSPATH' ) ) {{ define( 'ABSPATH', __DIR__ . '/' ); }}\n\
         require_once ABSPATH . 'wp-settings.php';\n"
    )
}

fn fake_server() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("usr/local/fastpanel2")).unwrap();

    // 1. Standard site + 2. nested development copy.
    let a = "var/www/a_usr/data/www/a.com";
    core(r, a, "7.1.3");
    write(r, &format!("{a}/wp-config.php"), &std_config("a_db", "wp_"));
    core(r, &format!("{a}/development"), "6.8.2");
    write(
        r,
        &format!("{a}/development/wp-config.php"),
        &std_config("a_dev", "dev_"),
    );

    // 3. Configuration split across several files.
    let j = "var/www/j_usr/data/www/j.es";
    core(r, &format!("{j}/cms"), "7.1.3");
    write(
        r,
        &format!("{j}/index.php"),
        "<?php\ndefine('WP_USE_THEMES', true);\nrequire( dirname( __FILE__ ) . '/cms/wp-blog-header.php' );\n",
    );
    write(
        r,
        &format!("{j}/cms/wp-config.php"),
        "<?php\ndefine('ROOT_PATH', dirname(__DIR__) . '/');\nrequire_once(ROOT_PATH . 'config/wp-config.php');\n",
    );
    write(
        r,
        &format!("{j}/config/wp-config.php"),
        "<?php\n$config = require_once dirname(__DIR__) . '/config/site-config.php';\n\
         foreach (['DB_NAME','DB_USER','DB_PASSWORD','DB_HOST',\n  'WP_HOME',\n  'WP_SITEURL'] as $k) { define($k, $config[$k]); }\n\
         $table_prefix = $config['table_prefix'];\n\
         if (!defined('ABSPATH'))\n  define('ABSPATH', dirname(__FILE__) . '/');\nrequire_once(ABSPATH . 'wp-settings.php');\n",
    );
    write(
        r,
        &format!("{j}/config/site-config.php"),
        "<?php\nreturn [\n  'DB_NAME' => 'jv_db',\n  'DB_USER' => 'jv',\n  'DB_PASSWORD' => 'x',\n  'DB_HOST' => 'localhost',\n  'table_prefix' => 'jv_',\n  'WP_HOME' => 'https://j.es',\n  'WP_SITEURL' => 'https://j.es/cms',\n];\n",
    );

    // 4. wp-config.php one level above the core.
    let b = "var/www/b_usr/data/www/b.com";
    core(r, &format!("{b}/public"), "7.0");
    write(r, &format!("{b}/wp-config.php"), &std_config("b_db", "b_"));

    // 5. Bedrock.
    let c = "var/www/c_usr/data/www/c.com";
    core(r, &format!("{c}/web/wp"), "7.1.2");
    fs::create_dir_all(r.join(c).join("web/app/plugins")).unwrap();
    write(
        r,
        &format!("{c}/config/application.php"),
        "<?php\nConfig::define('DB_NAME', env('DB_NAME'));\n$table_prefix = env('DB_PREFIX') ?: 'wp_';\n",
    );
    write(
        r,
        &format!("{c}/.env"),
        "DB_NAME='bedrock_db'\nDB_USER=bed\nDB_PASSWORD=\"pw\"\nDB_PREFIX=bd_\nWP_HOME=https://c.com # comment\n",
    );

    // 6. Credentials from environment variables.
    let d = "var/www/d_usr/data/www/d.com";
    core(r, d, "6.9.4");
    write(
        r,
        &format!("{d}/wp-config.php"),
        "<?php\ndefine('DB_NAME', getenv('WP_DB'));\n$table_prefix = 'd_';\n",
    );

    // 7. Orphan wp-config.php.
    write(
        r,
        "var/www/e_usr/data/www/old/wp-config.php",
        &std_config("viejo", "wp_"),
    );

    // 8. A "core" inside uploads must not count.
    core(r, &format!("{a}/wp-content/uploads/falso"), "1.0");

    // 9. Git repository.
    fs::create_dir_all(r.join("var/www/j_usr/data/www/j.es/.git")).unwrap();
    t
}

fn run(t: &tempfile::TempDir) -> pwss::discovery::Discovery {
    let cfg = Config::default();
    discover(
        &cfg,
        &Options {
            fs_root: t.path(),
            extra_roots: &[],
        },
    )
}

#[test]
fn detects_fastpanel() {
    let t = fake_server();
    assert_eq!(run(&t).panels, vec![Panel::FastPanel]);
}

#[test]
fn finds_every_install_and_skips_wp_content() {
    let t = fake_server();
    let d = run(&t);
    let names: Vec<String> = d
        .sites
        .iter()
        .map(|s| {
            s.core_dir
                .strip_prefix(t.path().canonicalize().unwrap())
                .unwrap()
                .display()
                .to_string()
        })
        .collect();
    assert_eq!(d.sites.len(), 6, "{names:#?}");
    assert!(!names.iter().any(|n| n.contains("uploads")));
}

#[test]
fn standard_site_and_password_is_never_stored() {
    let t = fake_server();
    let d = run(&t);
    let s = d
        .sites
        .iter()
        .find(|s| s.db_name.as_deref() == Some("a_db"))
        .unwrap();
    assert_eq!(s.layout, Layout::Standard);
    assert_eq!(s.table_prefix.as_deref(), Some("wp_"));
    assert_eq!(s.version.as_deref(), Some("7.1.3"));
    assert!(s.has_db_password);
    let json = serde_json::to_string(&d).unwrap();
    assert!(!json.contains("s3cr3t"));
    assert!(!json.contains("commented-out"));
}

#[test]
fn nested_dev_copy() {
    let t = fake_server();
    let d = run(&t);
    let dev = d
        .sites
        .iter()
        .find(|s| s.db_name.as_deref() == Some("a_dev"))
        .unwrap();
    assert!(dev.nested_in.as_ref().unwrap().ends_with("a.com"));
    let main = d
        .sites
        .iter()
        .find(|s| s.db_name.as_deref() == Some("a_db"))
        .unwrap();
    assert!(main.nested_in.is_none());
}

#[test]
fn split_config_across_files() {
    let t = fake_server();
    let d = run(&t);
    let s = d
        .sites
        .iter()
        .find(|s| s.core_dir.ends_with("j.es/cms"))
        .unwrap();
    assert_eq!(s.layout, Layout::SplitConfig);
    assert_eq!(s.db_name.as_deref(), Some("jv_db"));
    assert_eq!(s.table_prefix.as_deref(), Some("jv_"));
    assert_eq!(s.url.as_deref(), Some("https://j.es"));
    assert!(s.web_root.ends_with("j.es"));
    assert_eq!(s.config_files.len(), 3, "{:#?}", s.config_files);
    assert!(s.git_repo.is_some());
    assert!(s.warnings.is_empty(), "{:#?}", s.warnings);
}

#[test]
fn config_one_level_above() {
    let t = fake_server();
    let d = run(&t);
    let s = d
        .sites
        .iter()
        .find(|s| s.core_dir.ends_with("b.com/public"))
        .unwrap();
    assert_eq!(s.layout, Layout::ConfigAbove);
    assert_eq!(s.db_name.as_deref(), Some("b_db"));
}

#[test]
fn bedrock() {
    let t = fake_server();
    let d = run(&t);
    let s = d
        .sites
        .iter()
        .find(|s| s.layout == Layout::Bedrock)
        .unwrap();
    assert_eq!(s.db_name.as_deref(), Some("bedrock_db"));
    assert_eq!(s.table_prefix.as_deref(), Some("bd_"));
    assert_eq!(s.url.as_deref(), Some("https://c.com"));
    assert!(s.plugins_dir.ends_with("web/app/plugins"));
    assert!(s.has_db_password);
}

#[test]
fn dynamic_credentials_are_flagged() {
    let t = fake_server();
    let d = run(&t);
    let s = d
        .sites
        .iter()
        .find(|s| s.core_dir.ends_with("d.com"))
        .unwrap();
    assert!(s.db_name.is_none());
    assert!(
        s.warnings
            .iter()
            .any(|w| w.contains("environment variables"))
    );
}

#[test]
fn orphan_config_reported() {
    let t = fake_server();
    let d = run(&t);
    assert_eq!(d.orphan_configs.len(), 1);
    assert!(d.orphan_configs[0].ends_with("old/wp-config.php"));
}

#[test]
fn works_without_panel_with_explicit_root() {
    let t = fake_server();
    let root = t.path().join("var/www/b_usr");
    let cfg = Config::default();
    let d = discover(
        &cfg,
        &Options {
            fs_root: Path::new("/"),
            extra_roots: &[root],
        },
    );
    assert_eq!(d.sites.len(), 1);
}
