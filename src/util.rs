// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared utilities.
//!
//! PWSS reads files that may be malicious and prints them to a terminal, so
//! the basic defences live here:
//!
//! * reads that never follow symlinks and never block on FIFOs;
//! * size limits;
//! * sanitising everything that is printed (escape sequences, bidirectional
//!   characters that spoof file names);
//! * external commands with a timeout.

use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Data read from a file.
#[derive(Debug)]
pub struct FileData {
    pub bytes: Vec<u8>,
    pub size: u64,
    /// `true` if the file was larger than the limit and only its head and
    /// tail were read.
    pub truncated: bool,
    pub mtime: i64,
}

/// Opens a regular file without following symlinks or blocking on FIFOs or
/// devices. Tries not to update the access time.
pub fn open_regular(path: &Path) -> std::io::Result<(File, std::fs::Metadata)> {
    let base = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(base | libc::O_NOATIME)
        .open(path)
    {
        Ok(f) => f,
        // O_NOATIME requires being the owner or root.
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => OpenOptions::new()
            .read(true)
            .custom_flags(base)
            .open(path)?,
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok((f, meta))
}

/// Reads a file up to a byte limit. If it is larger, reads half the limit
/// from the start and half from the end (malware is often appended to the end
/// of legitimate files).
pub fn read_limited(path: &Path, max: u64) -> std::io::Result<FileData> {
    let (mut f, meta) = open_regular(path)?;
    let size = meta.len();
    let mut bytes = Vec::with_capacity(size.min(max) as usize);
    let truncated = size > max;
    if !truncated {
        f.by_ref().take(max).read_to_end(&mut bytes)?;
    } else {
        let half = max / 2;
        f.by_ref().take(half).read_to_end(&mut bytes)?;
        bytes.extend_from_slice(b"\n/* ...pwss: content omitted... */\n");
        f.seek(SeekFrom::Start(size - half))?;
        f.by_ref().take(half).read_to_end(&mut bytes)?;
    }
    Ok(FileData {
        bytes,
        size,
        truncated,
        mtime: meta.mtime(),
    })
}

/// SHA-256 of a whole file (streamed). `None` if unreadable or larger than
/// `max`.
pub fn sha256_file(path: &Path, max: u64) -> Option<String> {
    let (mut f, meta) = open_regular(path).ok()?;
    if meta.len() > max {
        return None;
    }
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex(&h.finalize()))
}

pub fn sha256_bytes(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Makes text safe to print in a terminal or an email: control characters
/// (including ESC), bidirectional marks and zero-width characters are shown
/// as `\u{..}`.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let bad = c.is_control()
            || matches!(c as u32,
                0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF);
        if bad {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

pub fn path_display(p: &Path) -> String {
    sanitize(&p.to_string_lossy())
}

/// Evidence snippet around a match: one line, collapsed whitespace,
/// sanitised and truncated.
pub fn snippet(data: &[u8], start: usize, end: usize, max_chars: usize) -> String {
    let from = start.saturating_sub(24);
    let to = (end + 40).min(data.len());
    let text = String::from_utf8_lossy(&data[from..to]);
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let clean = sanitize(&one_line);
    if clean.chars().count() > max_chars {
        let t: String = clean.chars().take(max_chars).collect();
        format!("{t}…")
    } else {
        clean
    }
}

// ---------------------------------------------------------------------------
// Dates (no dependencies)
// ---------------------------------------------------------------------------

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// (year, month, day, hour, minute) in UTC.
pub fn civil(secs: i64) -> (i64, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32)
}

/// Days since 1970-01-01 for a civil date (Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn fmt_ts(secs: i64) -> String {
    let (y, m, d, hh, mm) = civil(secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

// ---------------------------------------------------------------------------
// Low priority
// ---------------------------------------------------------------------------

/// Lowers the CPU and disk priority of the process (and of threads created
/// afterwards) so production sites are not affected.
pub fn lower_priority() {
    // SAFETY: system calls without pointers; failure is harmless.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
        // IOPRIO_WHO_PROCESS = 1, class IDLE = 3, value in the high bits.
        libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13);
    }
}

// ---------------------------------------------------------------------------
// External commands
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CmdOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

const BIN_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

pub fn find_bin(name: &str) -> Option<PathBuf> {
    BIN_DIRS
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// Runs a read-only command with a timeout. `None` if it does not exist or
/// could not be launched. Output is capped at 8 MiB.
pub fn run_cmd(program: &str, args: &[&str], timeout: Duration) -> Option<CmdOutput> {
    let bin = find_bin(program)?;
    let mut child = Command::new(bin)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut so = child.stdout.take()?;
    let mut se = child.stderr.take()?;
    let t1 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.by_ref().take(8 << 20).read_to_end(&mut b);
        b
    });
    let t2 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.by_ref().take(8 << 20).read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => break None,
        }
    };
    let stdout = t1.join().unwrap_or_default();
    let stderr = t2.join().unwrap_or_default();
    Some(CmdOutput {
        ok: status.map(|s| s.success()).unwrap_or(false),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

// ---------------------------------------------------------------------------
// Simple globs
// ---------------------------------------------------------------------------

/// Matches with `*` and `?`.
pub fn wildcard(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Expands a wildcard pattern segment by segment. `fs_root` allows testing
/// against a fake tree.
pub fn glob(fs_root: &Path, pattern: &str) -> Vec<PathBuf> {
    let base = if fs_root == Path::new("/") {
        PathBuf::from("/")
    } else {
        fs_root.to_path_buf()
    };
    let mut current = vec![base];
    for seg in pattern.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        let mut next = Vec::new();
        for dir in &current {
            if seg.contains('*') || seg.contains('?') {
                if let Ok(rd) = std::fs::read_dir(dir) {
                    let mut kids: Vec<PathBuf> = rd
                        .flatten()
                        .filter(|e| {
                            let n = e.file_name().to_string_lossy().into_owned();
                            (!n.starts_with('.') || seg.starts_with('.')) && wildcard(seg, &n)
                        })
                        .map(|e| e.path())
                        .collect();
                    kids.sort();
                    next.extend(kids);
                }
            } else {
                let p = dir.join(seg);
                if p.exists() {
                    next.push(p);
                }
            }
        }
        current = next;
    }
    current
}

/// Human-readable size in bytes.
pub fn fmt_size(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.1} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

/// Human-readable megabytes. Small values keep a decimal so they do not
/// show up as "0 MB".
pub fn fmt_mb(mb: f64) -> String {
    if mb >= 1024.0 {
        format!("{:.1} GB", mb / 1024.0)
    } else if mb >= 10.0 {
        format!("{mb:.0} MB")
    } else {
        format!("{mb:.1} MB")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_terminal_and_bidi() {
        let s = sanitize("a\x1b[31mb\u{202e}gpj.php\n");
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\u{202e}'));
        assert!(!s.contains('\n'));
        assert!(s.contains("\\u{1b}"));
        assert!(s.contains("\\u{202e}"));
    }

    #[test]
    fn dates() {
        assert_eq!(fmt_ts(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_ts(1_793_815_200), "2026-11-04 18:00 UTC");
        assert_eq!(civil(951_782_400).0, 2000);
    }

    #[test]
    fn civil_roundtrip() {
        for secs in [0i64, 86_400 * 365, 1_793_815_200, 1_000_000_000] {
            let (y, m, d, _, _) = civil(secs);
            assert_eq!(days_from_civil(y, m, d), secs.div_euclid(86_400));
        }
    }

    #[test]
    fn mb_formatting() {
        assert_eq!(fmt_mb(0.4), "0.4 MB");
        assert_eq!(fmt_mb(85.0), "85 MB");
        assert_eq!(fmt_mb(2048.0), "2.0 GB");
    }

    #[test]
    fn wildcards() {
        assert!(wildcard("*.conf", "a.conf"));
        assert!(!wildcard("*.conf", "a.confx"));
        assert!(wildcard("fastpanel2-sites/*", "fastpanel2-sites/x"));
        assert!(wildcard("a?c", "abc"));
    }

    #[test]
    fn snippet_is_one_line_and_clean() {
        let d = b"<?php\n\n  eval(\x1b[0m $_POST['x']);";
        let s = snippet(d, 8, 12, 80);
        assert!(!s.contains('\n') && !s.contains('\x1b'));
    }
}
