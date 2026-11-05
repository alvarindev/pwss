// SPDX-License-Identifier: GPL-3.0-or-later
mod common;

use common::{core, write};
use pwss::config::Config;
use pwss::discovery::{Options, discover};
use pwss::hunt::{self, Needle};
use pwss::util::sha256_bytes;

fn server() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    std::fs::create_dir_all(r.join("usr/local/fastpanel2")).unwrap();
    for d in ["a", "b", "c"] {
        core(r, &format!("var/www/{d}_usr/data/www/{d}.com"), "7.1.3");
    }
    // The same file in two sites, a different one in the third.
    write(
        r,
        "var/www/a_usr/data/www/a.com/wp-content/languages/x.php",
        "<?php // marker-IOC-123\n",
    );
    write(
        r,
        "var/www/b_usr/data/www/b.com/wp-content/.cache/x.php",
        "<?php // marker-IOC-123\n",
    );
    write(
        r,
        "var/www/c_usr/data/www/c.com/wp-content/plugins/p/ok.php",
        "<?php // clean\n",
    );
    write(
        r,
        "var/www/c_usr/data/www/c.com/wp-content/uploads/foto.jpg",
        "marker-IOC-123",
    );
    t
}

fn sites(t: &tempfile::TempDir) -> Vec<pwss::discovery::Site> {
    discover(
        &Config::default(),
        &Options {
            fs_root: t.path(),
            extra_roots: &[],
        },
    )
    .sites
}

#[test]
fn finds_by_hash_across_sites() {
    let t = server();
    let h = sha256_bytes(b"<?php // marker-IOC-123\n");
    let r = hunt::run(&sites(&t), &[Needle::Sha256(h)], &hunt::Options::default());
    assert_eq!(r.matches.len(), 2);
    let names: Vec<_> = r.matches.iter().map(|m| m.site.as_str()).collect();
    assert!(
        names.contains(&"a.com") && names.contains(&"b.com"),
        "{names:?}"
    );
}

#[test]
fn finds_by_text_and_respects_extension_filter() {
    let t = server();
    let n = [Needle::Text("MARKER-ioc-123".into())];
    let opts = hunt::Options {
        ignore_case: true,
        ..Default::default()
    };
    let r = hunt::run(&sites(&t), &n, &opts);
    assert_eq!(
        r.matches.len(),
        2,
        "the .jpg is excluded by the extension list"
    );
    assert!(r.matches.iter().all(|m| m.evidence.is_some()));

    let opts = hunt::Options {
        ignore_case: true,
        exts: None,
        ..Default::default()
    };
    let r = hunt::run(&sites(&t), &n, &opts);
    assert_eq!(r.matches.len(), 3, "with --all-files the .jpg is read too");

    // Without ignore_case, case differences do not match.
    let r = hunt::run(&sites(&t), &n, &hunt::Options::default());
    assert!(r.matches.is_empty());
}

#[test]
fn finds_by_name_with_wildcards() {
    let t = server();
    let r = hunt::run(
        &sites(&t),
        &[Needle::Name("x.php".into())],
        &hunt::Options::default(),
    );
    assert_eq!(r.matches.len(), 2);
    let r = hunt::run(
        &sites(&t),
        &[Needle::Name("*.jpg".into())],
        &hunt::Options::default(),
    );
    assert_eq!(r.matches.len(), 1);
    assert!(r.matches[0].sha256.is_some());
}

#[test]
fn large_files_are_skipped_not_truncated() {
    let t = server();
    write(
        t.path(),
        "var/www/a_usr/data/www/a.com/wp-content/big.php",
        &"x".repeat(5000),
    );
    let opts = hunt::Options {
        max_size: 1000,
        ..Default::default()
    };
    let r = hunt::run(&sites(&t), &[Needle::Text("xxxx".into())], &opts);
    assert!(r.matches.is_empty());
    assert!(r.stats.skipped_large >= 1);
}
