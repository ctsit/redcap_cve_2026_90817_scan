# CVE-2026-90817 REDCap compromise scanner

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23426068.svg)](https://doi.org/10.5281/zenodo.23426068)

`redcap_cve_2026_90817_scan.py` is a **read-only, passive** scanner that checks a
REDCap host for exposure to and compromise by **CVE-2026-90817** — the
unauthenticated survey-endpoint remote-code-execution flaw abused by the XMRig
cryptomining campaign documented by Palo Alto Unit 42
(`2026-10-07-XMRig-campaign-through-CVE-2026-90817`).

It answers two questions about the host it runs on:

1. **Am I vulnerable?** Is the installed REDCap version below the patched releases?
2. **Am I compromised?** Are any of the documented indicators of compromise (IOCs)
   present — and if the host was attacked, did the attacks land *before* or *after*
   it was patched?

## Safety / scope

This tool is **detection only**. It:

- never sends HTTP requests and never reproduces the exploit or any payload;
- never modifies, quarantines, deletes, or "cleans" anything;
- only reads files, process metadata, sockets, and logs on the host.

It is intended for an administrator running it against **their own** REDCap server.

## Requirements

- Python 3.7+. **Standard library only** — no `pip` installs.
- Runs on **Debian- and RHEL-family** Linux. Apache logs are auto-scanned at
  `/var/log/apache2` (Debian) or `/var/log/httpd` (RHEL/CentOS/Rocky/Alma), and
  nginx at `/var/log/nginx`. On RHEL 8 the system `python3` is 3.6, so invoke
  `python3.9` (or newer) there; RHEL/Rocky/Alma 9 ship 3.9+.
- Run as **root** for a complete scan (per-user crontabs, other users'
  `authorized_keys` and `/proc/<pid>/exe`, and some logs are otherwise unreadable).
  Without root it still runs and clearly marks the result as a partial scan.

## Usage

```bash
# Simplest: defaults to /var/www/html/redcap, auto-detects the mitigation date
sudo python3 -I redcap_cve_2026_90817_scan.py

# Point at a non-default install, pin the mitigation date, list every attack entry
sudo python3 -I redcap_cve_2026_90817_scan.py \
    --redcap-root /var/https/redcap \
    --mitigation-date 2026-09-21 \
    --max-log-matches all

# Machine-readable output for monitoring / ticketing
sudo python3 -I redcap_cve_2026_90817_scan.py --json
```

`-I` runs Python in isolated mode (ignores `$PYTHONPATH` and the CWD) — good hygiene
when scanning a possibly-tampered host.

### Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--redcap-root PATH` | `/var/www/html/redcap` | REDCap install root. |
| `--log-dir DIR` (repeatable) | `/var/log/apache2`, `/var/log/httpd`, `/var/log/nginx` | Web-server log directories to scan (handles rotated `.gz`). |
| `--home-dir DIR` (repeatable) | `/root` + each `/home/*` | Extra home dirs to scan for SSH keys / shell rc files. |
| `--mitigation-date YYYY-MM-DD` | *auto-detected* | Date the vulnerability was closed by upgrading. See [Attack timing](#attack-timing). |
| `--full-hash-scan` | off | Recursively hash files under `temp/cache` and staging dirs (slower). |
| `--max-log-matches N` \| `all` | `100` | How many attack log entries to list per category, kept **verbatim**. |
| `--json` | off | Emit JSON instead of the text report. |
| `--quiet` | off | Suppress `OK`/`INFO` lines in text output. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean and patched, and the scan completed fully. |
| `1` | One or more findings (vulnerable version and/or IOC/attack) — investigate. |
| `2` | Scan could not be completed fully (errors, or non-root and otherwise clean — a clean result could not be fully asserted). |

## What it checks

Each documented IOC maps to a passive local check:

- **Version / patch state** — reads the installed version from the `redcap_vX.Y.Z`
  directory names and compares against the patched releases
  (**16.0.49 LTS / 17.3.10 LTS / 17.4.4 Standard**; affected floor 13.3.0).
- **Known-bad files in `temp/cache`** — every file there (and in the staging
  dirs) is hashed against the Unit 42 dropper SHA-256. Note: the tool does **not**
  flag files by the `.bladec` extension. REDCap core uses the BladeOne template
  engine, which writes hash-named `.bladec` compiled templates to `temp/cache` as
  normal output, so the extension is not an indicator of compromise; a genuinely
  malicious dropped file is caught by its content hash, regardless of extension.
- **Miner staging** — `.syslog-*` dirs, `xmrig*` archives, and the competitor
  directories (`/dev/shm/duet`, `/var/tmp/.bin`) the campaign locks to perms `000`.
- **Processes** — miners (XMRig / pool / wallet references), executables running
  from `/var/tmp`, `/dev/shm`, `/tmp`, and `syslog-ng-*` masquerading processes.
- **Sockets** — the local XMRig JSON-RPC API on `127.0.0.1:50001`, and live
  connections to the attacker source IP.
- **Cron persistence** — fetch-to-shell cradles and IOC references in system and
  per-user crontabs.
- **SSH `authorized_keys`** — keys matching the attacker's backdoor fingerprint.
  (It deliberately does **not** list unrelated keys for "review" — on a normal host
  those belong to real accounts and aren't independently verifiable.)
- **Shell rc / `~/.profile`** — injected startup code and `HISTFILE` anti-forensics.
- **Web-server access logs** — exploit-attempt signatures (see below).

### Web-log detection (how false positives are avoided)

`__passthru` and `route=` on their own are **legitimate REDCap parameters** —
External Modules route through `__passthru`, and normal survey traffic uses a plain
`__passthru=index.php` to reach benign controllers like `PdfController` and
`SendItController`. The scanner therefore never matches on those alone. A log line
is treated as **exploit-shaped** only when it shows:

- the **RCE sink** — `__passthru` reaching **`DataImportController`** (the report's
  documented sink), at any encoding; or
- a **double-encoded** `__passthru` reaching **any** internal `…Controller` — e.g.
  `__passthru=%2569ndex.php&route=ParcelController:show`. This is the campaign's
  generalizable signature: legitimate clients send a plain, literal `index.php`,
  never a double-encoded one, so the **obfuscation** (not the controller name, not
  the HTTP status) is what distinguishes the attack. This is what catches attacker
  hosts *other than* the one documented IOC IP; or
- the specific attacker **survey hash** from the report.

Traffic merely **from the known attacker source IP** is classified separately as
reconnaissance (MEDIUM), not as an exploit-shaped request.

Because detection is by request *pattern*, not by IP, the scanner **aggregates every
distinct source IP** that issued an exploit-shaped request and calls out any beyond
the documented IOC IP. Each exploit hit is also **ranked by HTTP status**: a `2xx`
means the `__passthru` **reached** the controller unauthenticated, while a non-`2xx`
is an attempt that did not reach it. Reaching the controller is *reachability*, **not**
proof that code executed or that the host was compromised — the host-state checks are
what confirm an actual breach.

Matched entries are kept **verbatim and untruncated**, each prefixed with its parsed
date, the reason(s) it matched, and the status ranking, so the raw evidence is
preserved for review.

### Attack timing

If the host wasn't compromised on-disk, whether logged attacks *matter* depends on
when they happened relative to the patch. The scanner buckets every attack entry
**before / on / after** the mitigation date and sets the verdict accordingly:

| Attack timing | Verdict |
|---------------|---------|
| **before** the mitigation date | `LIKELY COMPROMISED` (attacked while vulnerable) |
| **on** the mitigation date | `POSSIBLY COMPROMISED` — compare each attack's time to the actual upgrade timestamp |
| **after** the mitigation date | `ATTACKED but NOT LIKELY COMPROMISED` |

The mitigation date comes from `--mitigation-date`, or, if that's omitted, is
inferred from the install mtime of the **earliest patched** `redcap_vX.Y.Z`
directory (the moment the host first ran a non-vulnerable version). The report
header shows which source was used. Host-state IOCs (known-bad file hash, miner,
persistence) always force `LIKELY COMPROMISED` regardless of timing.

## Caveats

- A log hit is evidence of an *attempt*, not proof of success — the host-state
  checks are what confirm an actual breach.
- The LTS-vs-Standard version boundaries are drawn from public threat-intel;
  confirm the exact fixed release against the REDCap vendor release notes.
- The log timestamp parser expects the standard Apache CLF format
  `[dd/Mon/yyyy:HH:MM:SS ±zzzz]`. Attacks in a customized `LogFormat` are counted as
  "undated" and flagged for manual review rather than silently dropped.
- IOC definitions live in one clearly-marked constants block at the top of the
  script — update them there if the vendor publishes more indicators.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). Copyright 2026 University of Florida.
