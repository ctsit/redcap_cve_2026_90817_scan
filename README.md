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

- Python 3.7+. **Standard library only** — no `pip` installs. A single file; copy
  it to the host and run.
- **Linux** (Debian- and RHEL-family): fully supported. Apache logs are
  auto-scanned at `/var/log/apache2` (Debian) or `/var/log/httpd`
  (RHEL/CentOS/Rocky/Alma), and nginx at `/var/log/nginx`. On RHEL 8 the system
  `python3` is 3.6, so invoke `python3.9` (or newer) there; RHEL/Rocky/Alma 9
  ship 3.9+. Run as **root** for a complete scan (per-user crontabs, other users'
  `authorized_keys` and `/proc/<pid>/exe`, and some logs are otherwise
  unreadable). Without root it still runs and clearly marks the result as a
  partial scan.
- **Windows** (REDCap on IIS or Apache/XAMPP): **untested** — it has never
  been run on a Windows host. See
  [Platforms & Windows support](#platforms--windows-support). Run from an
  **elevated** PowerShell/cmd for a complete scan.

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

On **Windows**, run from an elevated prompt and point `--redcap-root` at the
install (platform and default log dirs are auto-detected):

```powershell
# IIS or Apache/XAMPP; logs under C:\inetpub\logs\LogFiles or the Apache logs dir
python -I redcap_cve_2026_90817_scan.py --redcap-root C:\redcap --json
```

`-I` runs Python in isolated mode (ignores `$PYTHONPATH` and the CWD) — good hygiene
when scanning a possibly-tampered host.

### Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--redcap-root PATH` | `/var/www/html/redcap` | REDCap install root. |
| `--log-dir DIR` (repeatable) | *platform-specific* (Apache/nginx on Linux; IIS `LogFiles` + Apache on Windows) | Web-server log directories to scan (handles rotated `.gz` and IIS W3C logs). |
| `--home-dir DIR` (repeatable) | `/root` + each `/home/*` (Linux); each `C:\Users\*` (Windows) | Extra home dirs to scan for SSH keys / shell/profile files. |
| `--platform auto`\|`linux`\|`windows` | `auto` | Host platform to assume. Auto-detects from the OS; force it to select a provider (OS-specific host probes still run only on the matching live OS). |
| `--mitigation-date YYYY-MM-DD` | *auto-detected* | Date the vulnerability was closed by upgrading. See [Attack timing](#attack-timing). |
| `--since YYYY-MM-DD` | — | Only examine web-log entries on or after this date (inclusive). Log files last modified earlier are not opened. Applies to both log passes; host-state checks are unaffected. See [Attack timing](#attack-timing). |
| `--until YYYY-MM-DD` | — | Only examine web-log entries on or before this date (inclusive). |
| `--full-hash-scan` | off | Recursively hash files under `temp/cache` and staging dirs (slower). |
| `--max-log-matches N` \| `all` | `100` | How many attack log entries to list per category, kept **verbatim**. |
| `--attacker-ip IP` (repeatable) | — | Extra known attacker IP (e.g. from another host's scan). Treated like the documented IOC IP. See [Second pass](#second-pass-attacker-pivot--candidate-iocs). |
| `--json` | off | Emit JSON instead of the text report. |
| `--quiet` | off | Suppress `OK`/`INFO` lines in text output. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean and patched, and the scan completed fully. |
| `1` | One or more findings (vulnerable version and/or IOC/attack) — investigate. |
| `2` | Scan could not be completed fully (errors, or unprivileged and otherwise clean — a clean result could not be fully asserted). |

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
  connections to the attacker source IP(s) — the documented one, the
  observed ones, any `--attacker-ip`, and every IP the web-log check discovered.
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

Some requests are classified separately as **reconnaissance** (MEDIUM), not as
exploit-shaped requests:

- Any request from a **known attacker IP**: the documented IOC IP, any
  `--attacker-ip`, or the observed IPs below.
- A **doubled survey path that 404s**, from any IP. Examples:
  `/redcap/surveys/surveys?s=…`, `/redcap/surveys/redcap/surveys/`,
  `/redcap/redcap/surveys/`. This is a path-joining bug in the attack tool.
- A **tool-generated user agent** on a `/surveys` request, from any IP. This
  means a datetime inside the Gecko token, such as
  `Gecko/8618-10-13 16:07:47.714447 Firefox/3.8`, the kind of string Python
  Faker generates. Real browsers send e.g. `Gecko/20100101`.

A line that matches **only** one of these two probe patterns is listed as
reconnaissance but does **not** count toward the attack totals or the
[attack-timing](#attack-timing) verdict. Either pattern can come from a benign
source, such as a broken link or an odd client. When the same line comes from a
known attacker IP, it counts as usual.

#### Observed attacker IPs (not in the Unit 42 report)

These IPs sent exploit-shaped requests to a UF REDCap host in October 2026.
They are treated exactly like the documented IP:
- their log traffic is reconnaissance (MEDIUM);
- a live socket, cron or profile reference to one of them is HIGH.

| IP | First seen | Behaviour |
|----|-----------|-----------|
| 72.167.149.182 | 2026-10-14 | `python-requests`; base-path probe, then ParcelController |
| 18.163.208.19 | 2026-10-15 | `python-requests`; base-path probe, then ParcelController |
| 159.65.159.30, 45.225.183.6, 159.89.115.81, 165.22.168.95 | 2026-10-19 | made-up user agents, paired IPs; ParcelController |
| 5.180.77.102 | 2026-10-19 | DataImportController; same survey targets and doubled-path bug as 202.61.130.221 |

Most are cloud hosts that can be reassigned, so each evidence line shows where
the IP came from. Remove entries from `IOC_OBSERVED_IPS` when they go stale.

The following were seen in the same traffic but are **not** IOCs:
- The **survey hashes** the attackers targeted: they are the site's real
  surveys, so matching them would flag genuine respondents.
- **`python-requests`**: too generic.
- The **5-byte 2xx response**: it shows the request reached the controller,
  which is already ranked by HTTP status.

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

### Second pass: attacker pivot & candidate IOCs

Every IP found issuing exploit-shaped requests is fed back through a **second
pass**:

1. **Logs.** All *other* requests from those IPs are collected — probes, path
   guessing, follow-up activity. These lines aren't exploit-shaped, so the first
   pass skips them. They are reported as `Other traffic from N attacker IP(s)
   discovered by pattern` (MEDIUM).
2. **Host state.** Live sockets, scheduled jobs, and startup/profile files are
   searched for those IPs. A hit is HIGH and forces `LIKELY COMPROMISED`, just
   like a hit on the documented IOC IP.
3. **Candidate IOCs.** The scanner collects features of all attacker traffic
   and compares them with what it already knows. It lists anything not yet
   covered under **Candidate IOCs for review**, in the text report and as
   `candidate_iocs` in `--json`:
   - new attacker IPs;
   - controllers not in `KNOWN_EXPLOIT_CONTROLLERS`;
   - survey hashes or user agents shared by 2+ attacker IPs;
   - each distinct exploit request shape (survey hash masked, so encoding
     changes such as `:` → `%3A` show up);
   - recurring 2xx response sizes;
   - non-GET methods;
   - non-exploit paths.

   Candidates are listed oldest first, so you can read how the attack changed
   over time.

Candidates are **never added automatically**. Review them, then update the IOC
constants block if they generalize. To share IPs between hosts, pass them to
other hosts' scans with `--attacker-ip`. Candidate survey hashes are printed as
`?s=HASH`, so `sanitize_scan_result.py` masks them as it does any other hash.

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

`--since` / `--until` speed up routine rescans by limiting which log entries are
examined. Entries without a parseable timestamp are kept. If `--since` is later
than the mitigation date (or the mitigation date is unknown), the scan did not
look at the pre-patch period. The verdict then says so (`logs limited to … —
earlier attacks (incl. pre-patch) not examined`), so a limited scan is never
mistaken for an all-clear. For a first scan of a host, run without `--since`.

## Caveats

- A log hit is evidence of an *attempt*, not proof of success — the host-state
  checks are what confirm an actual breach.
- The LTS-vs-Standard version boundaries are drawn from public threat-intel;
  confirm the exact fixed release against the REDCap vendor release notes.
- The log timestamp parser expects the standard Apache CLF/Combined format
  `[dd/Mon/yyyy:HH:MM:SS ±zzzz]`. **IIS W3C Extended logs** are supported too:
  each W3C row is converted to the combined-log shape (reading the `#Fields:`
  header for column positions) and fed through the *same* classifier, so the
  attack signatures are identical across Apache and IIS. Attacks in a customized
  `LogFormat` with an unparseable timestamp are counted as "undated" and flagged
  for manual review rather than silently dropped.
- IOC definitions live in one clearly-marked constants block at the top of the
  script — update them there if the vendor publishes more indicators.

## Platforms & Windows support

Host-OS access (processes, sockets, scheduled jobs, keys, profiles, staging
dirs, log locations) is abstracted behind a small `HostProvider` seam, so the
same tool serves Linux and Windows and the **vulnerability** and
**exploit-attempt** detection — which live entirely in REDCap's PHP and the
web-server logs — is byte-for-byte identical on both.

- **Linux** — fully supported and matches the **documented** Unit 42 campaign
  IOCs (ELF XMRig miner, `syslog-ng-<hash>` masquerade, Monero wallet on a
  command line, cron persistence, SSH backdoor key).
- **Windows** — **UNTESTED.** No part of the Windows support has been run on a
  Windows host or against a real IIS log. It has only been exercised by unit
  tests on macOS, with a hand-written IIS log and a fake host provider. Treat
  every Windows result as unverified. Also note that the documented campaign is
  Linux-only, so a Windows REDCap host exploited through the *same* CVE would
  almost certainly get a *different* post-exploitation payload. Accordingly:
  - The **"am I vulnerable?"** (version) and **"am I being attacked?"**
    (web-log signature) checks use the same detection code as Linux. The
    Windows-specific parts are untested: finding the log directories, and
    parsing real IIS W3C logs, which may have more `#Fields:` columns or
    different encodings than the test fixture.
  - The **"am I compromised?"** host-state checks are **PROVISIONAL / generic
    heuristics** (a miner process or its `:50001` local API listener, a
    Scheduled Task running a PowerShell/`certutil` download cradle, a new admin
    SSH key, executables staged in Windows temp dirs, a system image running
    from outside `System32`) rather than the exact documented artifacts. The
    text report prints a note to this effect, and the Windows provider uses
    stdlib only (`subprocess` to `tasklist`/`netstat`/`schtasks`/`reg` and
    Task-Scheduler XML reads — no third-party WMI libraries).

Help validating the Windows path on a live instance is welcome — see the test
harness below.

## Development / tests

`tests/` holds a stdlib `unittest` suite (no `pip`) with recorded log fixtures
and a `FakeProvider` that injects host facts, so **either platform can be tested
on any OS with no live host**: the Linux path (and the shared version/log/verdict
logic) can be regression-tested with no Windows box, and the Windows provider /
IOC logic can be unit-tested against fixtures with no live compromised host.

```bash
python3 -m unittest discover -s tests -v
```

`tests/fixtures/logs/` contains the same attack expressed as both Apache CLF and
IIS W3C logs; a test asserts the two produce an identical attack summary.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). Copyright 2026 University of Florida.
