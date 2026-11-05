// SPDX-License-Identifier: GPL-3.0-or-later
//! Helpers for building fake servers in tests.
#![allow(dead_code)]

use std::fs;
use std::path::Path;

pub fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

/// Creates a minimal WordPress core in `dir`.
pub fn core(root: &Path, dir: &str, version: &str) {
    write(
        root,
        &format!("{dir}/wp-includes/version.php"),
        &format!("<?php\n$wp_version = '{version}';\n"),
    );
    write(root, &format!("{dir}/wp-settings.php"), "<?php\n");
    write(root, &format!("{dir}/wp-blog-header.php"), "<?php\n");
    write(
        root,
        &format!("{dir}/index.php"),
        "<?php\nrequire __DIR__ . '/wp-blog-header.php';\n",
    );
    write(
        root,
        &format!("{dir}/wp-config.php"),
        "<?php\ndefine('DB_NAME','db');\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','p');\n$table_prefix='wp_';\nrequire_once ABSPATH . 'wp-settings.php';\n",
    );
    fs::create_dir_all(root.join(dir).join("wp-content/plugins")).unwrap();
    fs::create_dir_all(root.join(dir).join("wp-content/themes")).unwrap();
    fs::create_dir_all(root.join(dir).join("wp-admin")).unwrap();
}
