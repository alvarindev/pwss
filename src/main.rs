// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::Result;
use clap::{Parser, Subcommand};
use pwss::{config::Config, discovery, doctor, hunt, scan, ui, util};
use std::path::PathBuf;
use std::process::ExitCode;

/// PWSS - Painless WordPress Security for Servers.
///
/// Security scanner for servers that host many WordPress sites.
/// Read-only: it never modifies a file or a database.
#[derive(Parser)]
#[command(name = "pwss", version, about, long_about = None)]
struct Cli {
    /// Configuration file (default: /etc/pwss/config.toml, if it exists).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Path to search for WordPress (repeatable). Replaces the automatic ones.
    #[arg(long = "root", global = true)]
    roots: Vec<PathBuf>,

    /// JSON output for scripts.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Lists the WordPress installations found.
    Sites {
        /// Shows paths, configuration files and warnings for each site.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Checks whether this server is compatible and what will work.
    Doctor,
    /// Looks for malware and persistence in every site (read-only).
    Scan {
        /// Analyses all PHP in the site, not just the persistence zones.
        #[arg(long)]
        deep: bool,
        /// Worker threads (default: what `doctor` recommends).
        #[arg(long)]
        threads: Option<usize>,
        /// Minimum severity to show: info, low, medium, high, critical.
        #[arg(long, default_value = "medium")]
        min_severity: String,
        /// Only sites whose name or path contains this text.
        #[arg(long)]
        site: Option<String>,
        /// Do not lower the CPU/disk priority of the process.
        #[arg(long)]
        no_nice: bool,
    },
    /// Looks for an indicator of compromise (hash, text or name) in every site.
    Hunt {
        /// SHA-256 of a file (repeatable).
        #[arg(long)]
        sha256: Vec<String>,
        /// Text contained in files (repeatable).
        #[arg(long = "string")]
        strings: Vec<String>,
        /// File name, supports * and ? (repeatable).
        #[arg(long)]
        name: Vec<String>,
        /// Case-insensitive matching.
        #[arg(short = 'i', long)]
        ignore_case: bool,
        /// Extensions to read (repeatable). Default: the usual ones.
        #[arg(long = "ext")]
        exts: Vec<String>,
        /// Read files of any extension.
        #[arg(long)]
        all_files: bool,
        /// Maximum size in MB of the files that are read.
        #[arg(long, default_value_t = 8)]
        max_size: u64,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long)]
        no_nice: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("pwss: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref())?;
    let opts = discovery::Options {
        extra_roots: &cli.roots,
        ..Default::default()
    };

    match cli.cmd {
        Cmd::Sites { verbose } => {
            let d = discovery::discover(&cfg, &opts);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&d)?);
            } else {
                ui::print_sites(&d, verbose);
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Doctor => {
            let d = discovery::discover(&cfg, &opts);
            let r = doctor::run(&d);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                ui::print_doctor(&r);
            }
            Ok(if r.has_failures() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Scan {
            deep,
            threads,
            min_severity,
            site,
            no_nice,
        } => {
            let min = scan::rules::Severity::parse(&min_severity)
                .ok_or_else(|| anyhow::anyhow!("unknown severity: {min_severity}"))?;
            if !no_nice {
                util::lower_priority();
            }
            let d = discovery::discover(&cfg, &opts);
            let so = scan::Options {
                deep,
                threads: threads.unwrap_or_else(doctor::recommended_threads),
                min_severity: min,
                filter: site,
                progress: !cli.json && std::io::IsTerminal::is_terminal(&std::io::stderr()),
            };
            let r = scan::run(&d.sites, &cfg, &so);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                ui::print_scan(&r);
            }
            Ok(if r.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Hunt {
            sha256,
            strings,
            name,
            ignore_case,
            exts,
            all_files,
            max_size,
            threads,
            no_nice,
        } => {
            let mut needles = Vec::new();
            for h in &sha256 {
                needles.push(hunt::Needle::Sha256(
                    hunt::parse_sha256(h).ok_or_else(|| anyhow::anyhow!("invalid sha256: {h}"))?,
                ));
            }
            needles.extend(strings.into_iter().map(hunt::Needle::Text));
            needles.extend(name.into_iter().map(hunt::Needle::Name));
            if needles.is_empty() {
                anyhow::bail!("give at least one of --sha256, --string or --name");
            }
            if !no_nice {
                util::lower_priority();
            }
            let d = discovery::discover(&cfg, &opts);
            let ho = hunt::Options {
                threads: threads.unwrap_or_else(doctor::recommended_threads),
                ignore_case,
                exts: if all_files {
                    None
                } else if exts.is_empty() {
                    Some(hunt::default_exts())
                } else {
                    Some(
                        exts.iter()
                            .map(|e| e.trim_start_matches('.').to_lowercase())
                            .collect(),
                    )
                },
                max_size: max_size << 20,
            };
            let r = hunt::run(&d.sites, &needles, &ho);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                ui::print_hunt(&r);
            }
            Ok(if r.matches.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}
