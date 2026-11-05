# PWSS - Painless WordPress Security for Servers

A free, open-source security scanner for Linux servers that host many
WordPress sites. One static binary, no subscription, no account, and
**read-only**: it never modifies a file or a database.

> **Status: alpha (v0.2).** File scanning, IOC hunting and server health
> checks work. Database analysis and WordPress.org integrity checks are
> planned (see the [roadmap](#roadmap)).
>
> PWSS is an independent project. It is inspired by the idea behind
> Wordfence CLI but shares no code with it and is not affiliated with
> Wordfence or Defiant.

## Why

Managing dozens of WordPress sites on one server means the interesting
question is rarely "is this one file bad?" but "where does this malware
persist, is it anywhere else, and is the server itself healthy?" PWSS is built
around those questions:

- **Persistence first.** The normal scan looks where malware hides to survive
  a cleanup: `mu-plugins/`, drop-ins (`db.php`, `object-cache.php`...),
  `languages/`, `upgrade/`, `uploads/`, hidden folders, theme entry files,
  `wp-config.php`, the WordPress root, `.htaccess` and `.user.ini`.
- **Hunt across the whole server.** Found something in one site? `pwss hunt`
  checks every other site for the same hash, string or file name.
- **Server health, not just files.** `pwss doctor` also catches the
  operational problems that tend to show up around an incident: nginx
  upstreams that stop resolving, failed systemd units, OOM kills,
  end-of-life PHP versions and over-committed memory.
- **Safe to run in production.** Static analysis only (PHP is never executed,
  WP-CLI is not needed), low CPU and I/O priority by default, symlinks are
  never followed, and everything printed is sanitised.

## Commands

| Command | What it does |
| --- | --- |
| `pwss sites` | Lists every WordPress install: version, layout, database. `--verbose` adds paths, config files and warnings |
| `pwss doctor` | Checks compatibility and server health (details below) |
| `pwss scan` | Malware and persistence scan. `--deep` analyses all PHP; `--site`, `--min-severity`, `--threads` |
| `pwss hunt` | Looks for an indicator across all sites: `--sha256`, `--string`, `--name` (repeatable) |

Global options: `--json` (machine-readable output), `--root PATH` (search only
there, repeatable), `--config FILE`.

**Exit codes:** `0` nothing found, `1` findings, `2` error or failed
`doctor` check.

### `pwss doctor`

Besides compatibility (OS, panel, database engine, mail, other scanners), it
checks:

- **nginx**: runs `nginx -t` and finds `upstream`/`proxy_pass` destinations
  given by host name. nginx resolves those at startup, so a name that stops
  resolving after a restart takes down every site.
- **systemd**: failed units, and processes killed by the OOM killer in the
  last 30 days.
- **PHP**: running versions and whether they still receive security fixes;
  `session.upload_progress.enabled` per pool (mitigation for the PHP advisory
  CVE-2026-115560 of 2026-10-23; PWSS does not claim which versions are
  affected because they have not been published).
- **Memory capacity**: worst case if every Apache and PHP-FPM worker fills up
  at once, compared with installed RAM.

### `pwss scan`

Findings carry a severity (`info`, `low`, `medium`, `high`, `critical`) and
one finding is reported per file, with every reason that applies. Rules in
persistence zones weigh one level more than the same code elsewhere.

A hidden folder inside `plugins/` or `themes/` is reported **once, as the
folder** (medium); its files are only reported if their code is suspicious.
Hidden PHP anywhere else (for example `wp-content/.x/a.php`) is high.

### `pwss hunt`

```bash
sudo pwss hunt --sha256 <hash>
sudo pwss hunt --string some_marker --string other_marker -i
sudo pwss hunt --name 'wp-locale-bootstrap.php' --name 'class-wp-locale-data.php'
```

By default only common text extensions are read (`--all-files` reads
everything; `--max-size` raises the per-file limit, default 8 MB).

## Install

Prebuilt static binaries (`x86_64` and `aarch64`, musl) are attached to each
GitHub release. Download one, verify it, and put it somewhere only root can
reach - **never inside a web root**, where it would be publicly downloadable:

```bash
sudo mkdir -p /opt/pwss && sudo chmod 700 /opt/pwss
sudo tar -xzf pwss-<target>.tar.gz -C /opt/pwss
sudo /opt/pwss/pwss doctor
```

Or build it yourself (stable Rust):

```bash
cargo build --release
cargo test
```

## Configuration

Everything is optional. Without a config file PWSS detects the environment
(panel, search paths, sites). For anything it cannot detect, use
`/etc/pwss/config.toml`:

```toml
[discovery]
roots = ["/var/www", "/opt/sites"]
exclude = ["/var/www/backups"]

[[site]]
path = "/opt/legacy/wp"
db_name = "legacy_db"
table_prefix = "lg_"

[scan]
# Silence a path, a rule, or a file you have reviewed and accepted.
ignore_paths = ["/var/www/example/data/www/dev.example.com/wp-content/uploads/backup"]
ignore_rules = ["persist.mu-plugin"]
allow_sha256 = ["<sha256 of a reviewed file>"]
```

### How it adapts to a server

1. **Generic discovery.** Any folder containing `wp-includes/version.php` is
   WordPress. The configuration is located wherever WordPress allows it (next
   to the core or one level up), `require`/`include` chains are followed, and
   Bedrock (`config/application.php` + `.env`) is understood.
2. **Panel paths.** FastPanel, Plesk, cPanel, HestiaCP, CloudPanel, aaPanel,
   ISPConfig and RunCloud add their typical paths. Without a panel it uses
   `/var/www`, `/srv/www`, `/home`, ...
3. **Manual config** for the rest.

## Safety

- Database passwords are never stored or printed; only their presence is
  recorded.
- Files are opened with `O_NOFOLLOW`/`O_NONBLOCK`, so symlinks are never
  followed and FIFOs cannot hang a scan. Large files are read head + tail
  only.
- Terminal escape sequences and bidirectional/zero-width characters in file
  names or snippets are escaped before printing.
- External commands run with a timeout and a clean environment.
- PWSS never deletes, moves or edits anything. Review a finding before you act
  on it; heuristics produce false positives (use the `[scan]` allow-lists).

## Roadmap

- [x] Site discovery, `doctor`, `scan`, `hunt`
- [ ] Database analysis with a read-only user (unknown cron hooks, options
  that contain code, rogue administrators)
- [ ] Core/plugin/theme integrity checks against WordPress.org
- [ ] `pwss setup` (SMTP and schedule), systemd timers, e-mail alerts
- [ ] `pwss baseline`: remember the expected services and flag changes
- [ ] `pwss self-update` (pull-based, verified)

## Contributing

Issues and pull requests are welcome. Please do not include real site names,
domains, paths or credentials from your own servers in tests or bug reports;
use invented ones.

## License

PWSS is free software, licensed under the **GNU General Public License v3.0
or later**. See [LICENSE](LICENSE).
