# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-20

> **Windows support is UNTESTED.** None of the Windows features have been run
> on a Windows host or against a real IIS log. Everything Windows-specific has
> only been checked by unit tests run on macOS, using a hand-written IIS log
> and an injected fake host provider. That covers:
>
> - the Windows host-state probes (`tasklist`, `netstat`, `schtasks`, `reg`,
>   Task Scheduler XML);
> - Windows default log locations and privilege detection;
> - IIS W3C parsing.
>
> Real IIS logs often use more `#Fields:` columns than the fixture and encode
> some values differently (for example `+` for spaces in the user agent).
> Treat Windows results as unverified until someone validates them on a live
> instance.
>
> The Linux path is unaffected. It has been run against the real UF REDCap
> host.

### Added

- **Windows support (untested; see the note above)** through a `HostProvider`
  layer that separates OS-specific host checks from the detection logic.
  - Linux keeps the documented Unit 42 checks.
  - Windows host-state checks are **provisional** generic post-exploitation
    heuristics, and the report says so.
  - IIS W3C Extended logs are converted to the combined-log format and go
    through the same classifier as Apache logs.
  - New option `--platform {auto,linux,windows}`.
- **Second-pass attacker pivot.** Every IP found sending exploit-shaped
  requests is run back through the scanner:
  - all of its other log traffic is reported (probes, path guessing,
    follow-ups);
  - live sockets, scheduled jobs and startup/profile files are searched for
    it, and a hit is HIGH and gives the verdict LIKELY COMPROMISED;
  - features of attacker traffic that the scanner doesn't cover yet are
    listed under **Candidate IOCs for review** (`candidate_iocs` in
    `--json`). These are for a person to review and are never added
    automatically.
- `--attacker-ip IP` (repeatable): treat extra IPs as known attackers, for
  example IPs found on another host.
- `--since YYYY-MM-DD` / `--until YYYY-MM-DD`: limit the web logs examined.
  - Files last modified before `--since` are not opened.
  - Both log passes use the same window.
  - If the window hides the period before the patch, the verdict says
    earlier attacks were not examined.
- **IOCs observed in the October 2026 attacks on a UF REDCap host:**
  - 7 attacker IPs beyond the documented one: 72.167.149.182,
    18.163.208.19, 159.65.159.30, 45.225.183.6, 159.89.115.81,
    165.22.168.95, 5.180.77.102. They are treated like the documented IP,
    and each evidence line says where the IP came from.
  - A doubled survey path that returns 404, for example
    `/redcap/surveys/surveys?s=…` or `/redcap/redcap/surveys/`. This comes
    from a path-joining bug in the attack tool.
  - A tool-generated user agent with a timestamp inside the Gecko token, as
    the Python Faker library produces.
- Per-IP attack summary now shows first and last timestamps, user agents and
  survey hashes.
- Unit test suite (stdlib `unittest`) with recorded log fixtures and a fake
  host provider, so both platforms can be tested on any OS.

### Changed

- The reconnaissance finding is renamed "Reconnaissance: known attacker IPs
  or campaign probe patterns". It covers the documented, observed and
  `--attacker-ip` IPs as well as the two probe patterns.
- A line flagged **only** by the doubled-path or fake-user-agent pattern, and
  not from a known attacker IP, is still listed as reconnaissance. It no
  longer counts toward the attack totals or the before/after-patch timing
  verdict. The summary shows these lines as "probe-pattern-only, not
  counted".

## [1.0.0] - 2026-10-16

First release: a read-only, passive scanner for CVE-2026-90817 (the REDCap
survey-endpoint RCE used in the XMRig campaign reported by Unit 42).

### Added

- Version check against the patched releases: 16.0.49 LTS, 17.3.10 LTS and
  17.4.4 Standard.
- Host-state IOC checks:
  - dropper file hash;
  - miner staging directories;
  - miner and masquerading processes;
  - the XMRig local API socket and connections to the attacker IP;
  - cron jobs that download and run code;
  - the backdoor SSH key;
  - startup-file injection and shell-history suppression.
- Web-log exploit detection, for both Apache CLF and rotated `.gz` logs. It
  flags:
  - `__passthru` reaching DataImportController;
  - any controller reached through a double-encoded `index.php`.

  It also groups results by source IP and ranks each hit by HTTP status.
- Attack-timing verdict: attacks before, on or after the mitigation date.
  The date is given with `--mitigation-date` or inferred from the install
  date of the patched version directory.
- `sanitize_scan_result.py`, which masks survey hashes and hostnames before a
  report is shared.
- Apache-2.0 license, `CITATION.cff` and a Zenodo DOI.

### Fixed

- Removed the `.bladec` web-shell indicator. Those files are normal BladeOne
  template output, so flagging them overstated compromise.
- Apache logs on RHEL/CentOS (`/var/log/httpd`) are now found.

[Unreleased]: https://github.com/ctsit/redcap_cve_2026_90817_scan/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/ctsit/redcap_cve_2026_90817_scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ctsit/redcap_cve_2026_90817_scan/releases/tag/v1.0.0
