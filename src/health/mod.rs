// SPDX-License-Identifier: GPL-3.0-or-later
//! Server health checks used by `pwss doctor`.
//!
//! They are read-only. External commands (`systemctl`, `journalctl`,
//! `nginx -t`) run with a timeout and without an inherited environment.

pub mod nginx;
pub mod systemd;
pub mod webstack;

use crate::doctor::Check;
use std::path::Path;

pub struct Env<'a> {
    pub fs_root: &'a Path,
    pub proc_root: &'a Path,
    /// Run commands and read `/proc` (disabled in tests).
    pub live: bool,
}

impl Default for Env<'_> {
    fn default() -> Self {
        Env {
            fs_root: Path::new("/"),
            proc_root: Path::new("/proc"),
            live: true,
        }
    }
}

pub fn run(env: &Env) -> Vec<Check> {
    let mut v = Vec::new();
    v.extend(nginx::run(env.fs_root, env.live));
    v.extend(systemd::run(env.live));
    v.extend(webstack::run(env.fs_root, env.proc_root, env.live));
    v
}
