#!/usr/bin/env python3
#
# Copyright 2026 University of Florida
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
"""
redcap_cve_2026_90817_scan.py

Read-only, passive compromise & vulnerability scanner for CVE-2026-90817 --
the unauthenticated REDCap survey-endpoint RCE abused by the XMRig cryptomining
campaign documented by Palo Alto Unit 42 (2026-10-07,
"2026-10-07-XMRig-campaign-through-CVE-2026-90817").

This tool is DETECTION ONLY. It is meant to be run ON your own REDCap host to
answer two questions:

  1. Am I vulnerable?    -- is the installed REDCap version below the patched
                            releases (16.0.49 LTS / 17.3.10 LTS / 17.4.4 Std)?
  2. Am I compromised?   -- are any of the indicators of compromise (IOCs) from
                            the Unit 42 report present on this host?

It NEVER sends HTTP requests, NEVER reproduces the exploit or any payload, and
NEVER modifies, quarantines, or removes anything. It only reads files,
processes, sockets, and logs. Run as root for a complete scan; it degrades
gracefully (and says so) without privileges.

Stdlib only. Python 3.7+. Runs on Debian- and RHEL-family Linux
(Apache logs at /var/log/apache2 or /var/log/httpd are auto-detected).

Usage:
    sudo python3 -I redcap_cve_2026_90817_scan.py [--redcap-root PATH] [--json]

Exit codes:
    0  clean and patched (and scan was complete)
    1  one or more findings (vulnerable version and/or IOC) -- investigate
    2  scan could not be completed fully (errors, or non-root and otherwise
       clean -- a clean result could not be fully asserted)
"""

from __future__ import annotations

import argparse
import base64
import datetime
import glob
import gzip
import hashlib
import json
import os
import re
import socket
import sys
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

# --------------------------------------------------------------------------- #
# IOC constants -- single source of truth (from the Unit 42 report).
# Update here if the vendor/threat-intel publishes more indicators.
# --------------------------------------------------------------------------- #

IOC_SOURCE_IP = "202.61.130.221"            # exploit source
IOC_POOL_DOMAIN = "auto.c3pool.org"         # mining pool
IOC_DROPPER_SHA256 = (
    "39a435123dc1fffd499aa2acf11ef46e3ee2e805bf137811af0c2c5b12546920"
)
IOC_WEBSHELL_BASENAME = (
    "d3f11fc8ee9c2d986425eff26ecace5b4004eb8e.bladec"
)
IOC_MINER_ARCHIVE = "/var/tmp/.syslog-a224be51/xmrig.tar.gz"
IOC_COMPETITOR_DIRS = ["/dev/shm/duet", "/var/tmp/.bin"]
IOC_MONERO_WALLET = (
    "87maYgt7bMvgDxQsBavYNVDr6BQgJNaaRKXg2yBh8A3GLVoizCq9eeyc"
    "BT7v6kdnm8f41Vfz84x6XLeEUJDRqvYbSrhvzTw"
)
IOC_SSH_FP_PARTIAL = "Ant3qLKQ9"            # partial key fingerprint from report
IOC_MINER_API_PORT = 50001                  # local XMRig JSON-RPC API
IOC_PAYLOAD_NAMES = [
    "banner_avp_800x800.jpg",
    "banner-ver2_800x800.jpg",
    "grepb2.jpg",
]
# Exploit-request fingerprint for web-server logs.
# IMPORTANT: `__passthru` and `route=` are LEGITIMATE REDCap parameters --
# External Modules route through __passthru (e.g.
# `__passthru=ExternalModules&prefix=legacy_url_fixer&ajax=1`) and
# DataImportController is a real authenticated controller. Matching either
# substring alone produces false positives, so _exploit_log_reasons() below
# matches only the specific malicious combination / obfuscation, never the
# bare parameter names.
IOC_ATTACKER_SURVEY_HASH = "s=NXCJMDCWXE"   # specific hash from the report sample

# Patched releases and affected floor (public threat-intel; confirm vs. vendor).
FIXED_VERSIONS = {
    (16, 0): (16, 0, 49),   # LTS line
    (17, 3): (17, 3, 10),   # LTS line
    (17, 4): (17, 4, 4),    # Standard line
}
AFFECTED_FLOOR = (13, 3, 0)
TOP_STANDARD_FIX = (17, 4, 4)

# Suspicious staging locations commonly abused by the campaign.
STAGING_DIRS = ["/var/tmp", "/dev/shm", "/tmp"]
EXEC_FROM_DIRS = ("/var/tmp", "/dev/shm", "/tmp")

# Patterns indicating a fetch-to-shell cradle in cron / profile files.
FETCH_TO_SHELL_RE = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(bash|sh)\b"
    r"|base64\s+(-d|--decode)\b[^\n|]*\|\s*(bash|sh)\b"
    r"|\beval\b.*\$\(.*(curl|wget)",
    re.IGNORECASE,
)

# Read caps so untrusted/huge host files can't blow up memory.
MAX_TEXT_BYTES = 5 * 1024 * 1024            # 5 MiB for config/rc/cron files
MAX_HASH_BYTES = 256 * 1024 * 1024          # 256 MiB per hashed file
MAX_LOG_MATCHES = 100                       # default attack entries kept per category

# --------------------------------------------------------------------------- #
# Finding / Report model
# --------------------------------------------------------------------------- #

# Severity ordering (higher = worse) used for the verdict and exit code.
SEV_OK = "OK"
SEV_INFO = "INFO"
SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"
SEV_CRITICAL = "CRITICAL"
SEV_ERROR = "ERROR"

_SEV_RANK = {
    SEV_OK: 0,
    SEV_INFO: 1,
    SEV_ERROR: 2,   # an inability to check is noteworthy but not a finding
    SEV_LOW: 3,
    SEV_MEDIUM: 4,
    SEV_HIGH: 5,
    SEV_CRITICAL: 6,
}


@dataclass
class Finding:
    severity: str
    check: str
    title: str
    detail: str = ""
    evidence: list = field(default_factory=list)


@dataclass
class Report:
    findings: list = field(default_factory=list)
    partial: bool = False          # true if some checks could not run (e.g. non-root)
    redcap_version: Optional[str] = None
    notes: list = field(default_factory=list)
    mitigation_date: Optional[str] = None   # ISO date the host became patched
    mitigation_source: str = ""              # how that date was determined
    attack_summary: Optional[dict] = None    # log-attack counts / timing

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)

    def max_rank(self) -> int:
        ranks = [_SEV_RANK.get(f.severity, 0) for f in self.findings]
        return max(ranks) if ranks else 0

    def has_at_least(self, sev: str) -> bool:
        return self.max_rank() >= _SEV_RANK[sev]


# --------------------------------------------------------------------------- #
# Low-level helpers (all read-only, all exception-safe)
# --------------------------------------------------------------------------- #

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:       # non-POSIX platform (no geteuid)
        return False


def read_text(path: str, cap: int = MAX_TEXT_BYTES) -> Optional[str]:
    """Return up to `cap` bytes of a text file, or None if unreadable."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap + 1)
    except (OSError, PermissionError):
        return None
    if len(data) > cap:
        data = data[:cap]
    try:
        return data.decode("utf-8", "replace")
    except Exception:
        return None


def read_lines(path: str, cap: int = MAX_TEXT_BYTES) -> list:
    txt = read_text(path, cap)
    return txt.splitlines() if txt is not None else []


def open_maybe_gzip(path: str):
    """Open a plain or .gz text file for line iteration; None on failure."""
    try:
        if path.endswith(".gz"):
            return gzip.open(path, "rt", encoding="utf-8", errors="replace")
        return open(path, "r", encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def sha256_file(path: str, cap: int = MAX_HASH_BYTES) -> Optional[str]:
    try:
        h = hashlib.sha256()
        read = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > cap:
                    return None          # too large; skip rather than stall
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def mtime_str(path: str) -> str:
    try:
        ts = os.lstat(path).st_mtime
        return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except OSError:
        return "?"


def iter_proc_net(path: str) -> Iterable[dict]:
    """Yield parsed rows from /proc/net/tcp or /proc/net/tcp6."""
    lines = read_lines(path)
    for line in lines[1:]:          # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        yield {
            "local": parts[1],
            "remote": parts[2],
            "state": parts[3],
        }


def _hex_ipv4(h: str) -> str:
    # /proc stores IPv4 as little-endian hex, e.g. 0100007F -> 127.0.0.1
    try:
        b = bytes.fromhex(h)
        return ".".join(str(x) for x in reversed(b))
    except ValueError:
        return h


def parse_procnet_addr(addr: str) -> tuple:
    """'0100007F:C351' -> ('127.0.0.1', 50001). Handles v4 and ::ffff:v4."""
    try:
        host_hex, port_hex = addr.split(":")
        port = int(port_hex, 16)
    except (ValueError, IndexError):
        return ("?", 0)
    if len(host_hex) == 8:
        return (_hex_ipv4(host_hex), port)
    if len(host_hex) == 32:
        # IPv6; recover a ::ffff: mapped v4 if present (last 32 bits), else raw.
        tail = host_hex[24:]
        if host_hex[:24] == "0000000000000000FFFF0000" or host_hex[16:24].upper() == "FFFF0000":
            return (_hex_ipv4(tail), port)
        return ("ipv6:" + host_hex, port)
    return (host_hex, port)


def list_home_dirs(extra: list) -> list:
    homes = []
    if os.path.isdir("/root"):
        homes.append("/root")
    homes.extend(sorted(glob.glob("/home/*")))
    for d in extra or []:
        if d not in homes:
            homes.append(d)
    return [h for h in homes if os.path.isdir(h)]


def parse_version(s: str) -> Optional[tuple]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def version_is_patched(v: tuple) -> bool:
    """True if version tuple v is at or above the patched release for its branch."""
    if v >= TOP_STANDARD_FIX or v[0] > 17:
        return True
    branch = (v[0], v[1])
    return branch in FIXED_VERSIONS and v >= FIXED_VERSIONS[branch]


_APACHE_TS_RE = re.compile(
    r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]")


def parse_apache_time(line: str):
    """Parse a CLF timestamp like '[02/Oct/2026:00:48:49 -0400]' into an aware
    datetime, or None if the line has no parseable timestamp."""
    m = _APACHE_TS_RE.search(line)
    if not m:
        return None
    try:
        return datetime.datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def detect_mitigation_date(redcap_root: str):
    """Infer the date the host became patched from the install mtime of the
    EARLIEST patched redcap_vX.Y.Z directory (that is the moment the host first
    ran a non-vulnerable version). These dirs may not exist; when they do their
    mtime is reliable per REDCap packaging. Returns (date | None, source_str)."""
    try:
        names = os.listdir(redcap_root)
    except (OSError, PermissionError):
        return (None, f"{redcap_root!r} not readable")
    best_mt, best_name = None, None
    for name in names:
        m = re.fullmatch(r"redcap_v(\d+\.\d+\.\d+)", name)
        if not m:
            continue
        v = parse_version(m.group(1))
        if not v or not version_is_patched(v):
            continue
        try:
            mt = os.lstat(os.path.join(redcap_root, name)).st_mtime
        except OSError:
            continue
        if best_mt is None or mt < best_mt:
            best_mt, best_name = mt, name
    if best_mt is not None:
        return (datetime.datetime.fromtimestamp(best_mt).date(),
                f"install date of {best_name} (directory mtime)")
    return (None, "no patched redcap_vX.Y.Z directory found")


def _url_unquote_recursive(s: str, rounds: int = 3) -> str:
    """URL-decode repeatedly (caps rounds) to defeat double/triple encoding
    such as %2569ndex.php -> %69ndex.php -> index.php."""
    prev = s
    for _ in range(rounds):
        cur = urllib.parse.unquote(prev)
        if cur == prev:
            break
        prev = cur
    return prev


def _dedup(items: list) -> list:
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _classify_log_line(line: str) -> tuple:
    """Classify a web-server access-log line for CVE-2026-90817.

    Returns (exploit_reasons, recon_reasons).

    The developer-confirmed HALLMARK of the attack is reaching the internal
    DataImportController through the unauthenticated survey `__passthru`.
    Normal REDCap survey traffic *also* uses `__passthru=index.php` to reach
    benign controllers (PdfController, SendItController, ...), so neither
    `__passthru` nor `index.php` is an indicator on its own, and we never match
    on them. We decode the line first so an attacker URL-encoding the route
    (e.g. %2569ndex.php) is still caught by the DataImportController test."""
    exploit, recon = [], []
    decoded = _url_unquote_recursive(line).lower()

    # Hallmark: survey passthru reaching the data-import controller.
    if "__passthru" in decoded and "route=dataimportcontroller" in decoded:
        exploit.append("survey __passthru -> DataImportController (attack hallmark)")
    # Exact attacker survey hash from the report sample.
    if IOC_ATTACKER_SURVEY_HASH.lower() in line.lower():
        exploit.append(f"attacker survey hash {IOC_ATTACKER_SURVEY_HASH}")

    # Known attacker source IP. Not exploit-shaped on its own -> reconnaissance.
    if IOC_SOURCE_IP in line:
        recon.append(f"contact from known attacker IP {IOC_SOURCE_IP}")

    return (_dedup(exploit), _dedup(recon))


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_version(rep: Report, redcap_root: str) -> None:
    """Determine installed REDCap version and compare to patched releases."""
    versions = []
    try:
        for name in os.listdir(redcap_root):
            m = re.fullmatch(r"redcap_v(\d+\.\d+\.\d+)", name)
            if m and os.path.isdir(os.path.join(redcap_root, name)):
                versions.append(parse_version(m.group(1)))
    except (OSError, PermissionError):
        rep.add(Finding(SEV_ERROR, "version",
                        "REDCap root not readable",
                        f"Could not list {redcap_root!r}; version check skipped. "
                        "Pass --redcap-root if the install lives elsewhere."))
        return

    if not versions:
        rep.add(Finding(SEV_INFO, "version",
                        "REDCap version not found on disk",
                        f"No redcap_vX.Y.Z directory under {redcap_root!r}. "
                        "Confirm the path, or check the redcap_config DB table."))
        return

    v = max(versions)
    vstr = ".".join(str(x) for x in v)
    rep.redcap_version = vstr

    patched = version_is_patched(v)

    if v < AFFECTED_FLOOR:
        rep.add(Finding(SEV_INFO, "version",
                        f"REDCap {vstr} predates the published affected range",
                        "Version is below 13.3.0, the stated floor for "
                        "CVE-2026-90817. Verify against the vendor advisory; "
                        "upgrade regardless, as this is a very old release."))
    elif patched:
        rep.add(Finding(SEV_OK, "version",
                        f"REDCap {vstr} is at or above the patched release "
                        "for its branch"))
    else:
        rep.add(Finding(SEV_HIGH, "version",
                        f"REDCap {vstr} appears VULNERABLE to CVE-2026-90817",
                        "Version is >= 13.3.0 and below the patched release for "
                        "its branch (16.0.49 LTS / 17.3.10 LTS / 17.4.4 Std). "
                        "LTS-vs-Standard boundaries are fuzzy in public sources "
                        "-- confirm against the REDCap release notes, then patch.",
                        evidence=[f"installed: {vstr}"]))


def check_webshell(rep: Report, redcap_root: str) -> None:
    cache = os.path.join(redcap_root, "temp", "cache")
    exact = os.path.join(cache, IOC_WEBSHELL_BASENAME)
    if os.path.exists(exact):
        rep.add(Finding(SEV_CRITICAL, "webshell",
                        "Known CVE-2026-90817 web shell present",
                        "The exact dropped Blade web shell from the Unit 42 "
                        "report exists.",
                        evidence=[f"{exact} (mtime {mtime_str(exact)})"]))
    try:
        others = [p for p in glob.glob(os.path.join(cache, "*.bladec"))
                  if os.path.abspath(p) != os.path.abspath(exact)]
    except OSError:
        others = []
    if others:
        rep.add(Finding(SEV_HIGH, "webshell",
                        "Unexpected .bladec file(s) in REDCap temp/cache",
                        "Compiled Blade templates are not normal in a REDCap "
                        "temp/cache directory; the campaign drops its web shell "
                        "with this extension. Review each file.",
                        evidence=[f"{p} (mtime {mtime_str(p)})" for p in others]))
    if not os.path.isdir(cache):
        rep.note(f"temp/cache not found under {redcap_root!r}; web-shell check limited.")


def check_staging(rep: Report) -> None:
    hits = []
    # Exact documented archive path.
    if os.path.exists(IOC_MINER_ARCHIVE):
        hits.append((SEV_CRITICAL, f"{IOC_MINER_ARCHIVE} (mtime {mtime_str(IOC_MINER_ARCHIVE)})"))
    # Masquerading .syslog-* staging dirs and stray xmrig archives.
    for base in STAGING_DIRS:
        for p in glob.glob(os.path.join(base, ".syslog-*")):
            hits.append((SEV_HIGH, f"{p} (mtime {mtime_str(p)})"))
        for p in glob.glob(os.path.join(base, "**", "xmrig*"), recursive=True):
            hits.append((SEV_HIGH, f"{p} (mtime {mtime_str(p)})"))
    if hits:
        rep.add(Finding(max(hits, key=lambda h: _SEV_RANK[h[0]])[0], "staging",
                        "Miner staging artifact(s) found",
                        "Files/dirs matching the XMRig staging pattern.",
                        evidence=[h[1] for h in hits]))
    # Competitor-removal dirs locked to 000.
    comp = []
    for d in IOC_COMPETITOR_DIRS:
        if os.path.exists(d):
            try:
                mode = os.lstat(d).st_mode & 0o777
            except OSError:
                mode = -1
            comp.append(f"{d} (mode {oct(mode)}, mtime {mtime_str(d)})")
    if comp:
        rep.add(Finding(SEV_HIGH, "staging",
                        "Competitor-miner staging dir(s) present",
                        "The campaign locks rival-miner directories to perms 000.",
                        evidence=comp))


def _hash_candidates(full: bool, redcap_root: str) -> Iterable[str]:
    seen = set()
    roots = [os.path.join(redcap_root, "temp", "cache")] + STAGING_DIRS
    for base in roots:
        if not os.path.isdir(base):
            continue
        if full:
            for dirpath, _dirs, files in os.walk(base):
                for fn in files:
                    p = os.path.join(dirpath, fn)
                    if p not in seen:
                        seen.add(p)
                        yield p
        else:
            # Non-recursive + the known hidden staging dirs only.
            try:
                entries = [os.path.join(base, e) for e in os.listdir(base)]
            except (OSError, PermissionError):
                entries = []
            for p in entries:
                if os.path.isfile(p) and p not in seen:
                    seen.add(p)
                    yield p
                elif os.path.isdir(p) and os.path.basename(p).startswith(".syslog-"):
                    for dirpath, _d, files in os.walk(p):
                        for fn in files:
                            q = os.path.join(dirpath, fn)
                            if q not in seen:
                                seen.add(q)
                                yield q


def check_hashes(rep: Report, redcap_root: str, full: bool) -> None:
    matched = []
    count = 0
    for path in _hash_candidates(full, redcap_root):
        count += 1
        if sha256_file(path) == IOC_DROPPER_SHA256:
            matched.append(path)
    if matched:
        rep.add(Finding(SEV_CRITICAL, "hash",
                        "File matching known dropper SHA-256 found",
                        "Byte-for-byte match to the Unit 42 secondary dropper.",
                        evidence=matched))
    elif count == 0:
        rep.note("No candidate files were available to hash.")


def check_processes(rep: Report) -> None:
    if not os.path.isdir("/proc"):
        rep.note("/proc unavailable; process check skipped.")
        return
    masq, fromtmp, miner = [], [], []
    for entry in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(entry)
        comm = (read_text(os.path.join(entry, "comm")) or "").strip()
        cmdline_raw = read_text(os.path.join(entry, "cmdline")) or ""
        cmdline = cmdline_raw.replace("\x00", " ").strip()
        try:
            exe = os.readlink(os.path.join(entry, "exe"))
        except (OSError, PermissionError):
            exe = ""
        low = (comm + " " + cmdline).lower()

        if comm.startswith("syslog-ng-"):
            masq.append(f"pid {pid}: comm={comm!r} exe={exe or '?'}")
        if exe.startswith(EXEC_FROM_DIRS):
            fromtmp.append(f"pid {pid}: exe={exe} comm={comm!r}")
        if ("xmrig" in low or "c3pool" in low or "stratum+tcp" in low
                or IOC_MONERO_WALLET.lower() in low):
            miner.append(f"pid {pid}: comm={comm!r} cmd={cmdline[:200]!r}")

    if miner:
        rep.add(Finding(SEV_CRITICAL, "process",
                        "Cryptominer process indicator(s) running",
                        "Process name/args reference XMRig, the pool, or the wallet.",
                        evidence=miner))
    if fromtmp:
        rep.add(Finding(SEV_HIGH, "process",
                        "Process(es) executing from a temp directory",
                        "Executables under /var/tmp, /dev/shm, or /tmp are a strong "
                        "indicator of the in-memory dropper / miner.",
                        evidence=fromtmp))
    if masq:
        rep.add(Finding(SEV_HIGH, "process",
                        "syslog-ng-* masquerading process(es)",
                        "The miner is launched via exec -a with syslog-style names; "
                        "the real daemon's comm is 'syslog-ng', not 'syslog-ng-<hash>'.",
                        evidence=masq))
    if not is_root():
        rep.note("Process check ran without root; other users' exe links may be hidden.")


def check_sockets(rep: Report) -> None:
    listen, connected = [], []
    for fam, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
        if not os.path.exists(path):
            continue
        for row in iter_proc_net(path):
            lhost, lport = parse_procnet_addr(row["local"])
            rhost, rport = parse_procnet_addr(row["remote"])
            state = row["state"].upper()
            if state == "0A" and lport == IOC_MINER_API_PORT and lhost in ("127.0.0.1", "::1"):
                listen.append(f"{fam} LISTEN {lhost}:{lport}")
            if rhost == IOC_SOURCE_IP:
                connected.append(f"{fam} {state} -> {rhost}:{rport}")
    if listen:
        rep.add(Finding(SEV_HIGH, "socket",
                        f"Local XMRig JSON-RPC API on 127.0.0.1:{IOC_MINER_API_PORT}",
                        "A listener on the miner's documented local control port.",
                        evidence=listen))
    if connected:
        rep.add(Finding(SEV_HIGH, "socket",
                        f"Active connection involving exploit source {IOC_SOURCE_IP}",
                        "Current socket to/from the documented attacker IP.",
                        evidence=connected))


def _scan_file_for_patterns(path: str, rep_notes: Report) -> list:
    """Return (lineno, text) hits for fetch-to-shell / IOC patterns in a file."""
    hits = []
    lines = read_lines(path)
    for i, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        low = line.lower()
        flagged = False
        if FETCH_TO_SHELL_RE.search(line):
            flagged = True
        if IOC_POOL_DOMAIN in low or IOC_SOURCE_IP in line:
            flagged = True
        if any(name in low for name in (n.lower() for n in IOC_PAYLOAD_NAMES)):
            flagged = True
        if flagged:
            hits.append((i, line.strip()[:200]))
    return hits


def check_cron(rep: Report) -> None:
    cron_files = ["/etc/crontab"]
    cron_files += glob.glob("/etc/cron.d/*")
    for sub in ("hourly", "daily", "weekly", "monthly"):
        cron_files += glob.glob(f"/etc/cron.{sub}/*")
    cron_files += glob.glob("/var/spool/cron/crontabs/*")
    cron_files += glob.glob("/var/spool/cron/*")

    evidence = []
    unreadable = 0
    for path in cron_files:
        if not os.path.isfile(path):
            continue
        if read_text(path) is None:
            unreadable += 1
            continue
        for lineno, text in _scan_file_for_patterns(path, rep):
            evidence.append(f"{path}:{lineno}: {text}")
    if evidence:
        rep.add(Finding(SEV_HIGH, "cron",
                        "Suspicious cron entry(ies) (fetch-to-shell / IOC)",
                        "Cron content matches the campaign's remote-payload pull "
                        "or references a known IOC. Review before acting.",
                        evidence=evidence))
    if unreadable and not is_root():
        rep.note(f"{unreadable} cron file(s) were unreadable without root; cron check partial.")


def _ssh_fingerprint(blob: str) -> Optional[str]:
    try:
        raw = base64.b64decode(blob, validate=False)
        digest = hashlib.sha256(raw).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    except Exception:
        return None


def check_authorized_keys(rep: Report, homes: list) -> None:
    # Only report keys that match the IOC backdoor fingerprint. We deliberately
    # do NOT list or ask anyone to "review" the other keys: on a normal host
    # they belong to real user accounts and are not independently verifiable,
    # so listing them is pure noise.
    matched, unreadable = [], 0
    key_files = []
    for home in homes:
        key_files.append(os.path.join(home, ".ssh", "authorized_keys"))
        key_files.append(os.path.join(home, ".ssh", "authorized_keys2"))
    for path in key_files:
        if not os.path.exists(path):
            continue
        lines = read_lines(path)
        if not lines and read_text(path) is None:
            unreadable += 1
            continue
        for lineno, line in enumerate(lines, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split()
            blob = parts[1] if len(parts) >= 2 and parts[0].startswith(("ssh-", "ecdsa", "sk-")) else ""
            fp = _ssh_fingerprint(blob) if blob else None
            if IOC_SSH_FP_PARTIAL in line or (fp and IOC_SSH_FP_PARTIAL in fp):
                desc = f"{path}:{lineno}: {line.strip()[:120]}"
                if fp:
                    desc += f"  [{fp}]"
                matched.append(desc)
    if matched:
        rep.add(Finding(SEV_CRITICAL, "ssh",
                        "authorized_keys entry matches the IOC fingerprint",
                        f"A key contains the partial fingerprint {IOC_SSH_FP_PARTIAL!r} "
                        "reported as the attacker's backdoor key.",
                        evidence=matched))
    if unreadable and not is_root():
        rep.note(f"{unreadable} authorized_keys file(s) unreadable without root; SSH check partial.")


def check_profiles(rep: Report, homes: list) -> None:
    evidence = []
    histfile_hits = []
    rc_names = (".profile", ".bashrc", ".bash_profile", ".bash_login")
    for home in homes:
        for name in rc_names:
            path = os.path.join(home, name)
            if not os.path.isfile(path):
                continue
            for lineno, text in _scan_file_for_patterns(path, rep):
                evidence.append(f"{path}:{lineno}: {text}")
            for i, line in enumerate(read_lines(path), 1):
                s = line.strip()
                if re.search(r"\bunset\s+HISTFILE\b", s) or \
                        re.search(r"\bHISTFILE\s*=\s*(/dev/null)?\s*$", s) or \
                        "HISTFILE=/dev/null" in s:
                    histfile_hits.append(f"{path}:{i}: {s[:160]}")
        # bash_history tampering
        hist = os.path.join(home, ".bash_history")
        try:
            if os.path.islink(hist) and os.path.realpath(hist) == "/dev/null":
                histfile_hits.append(f"{hist} -> /dev/null (history suppressed)")
        except OSError:
            pass
    if evidence:
        rep.add(Finding(SEV_HIGH, "profile",
                        "Shell rc/profile contains fetch-to-shell / IOC content",
                        "Injected startup code matching the campaign's persistence.",
                        evidence=evidence))
    if histfile_hits:
        rep.add(Finding(SEV_MEDIUM, "profile",
                        "Shell history suppression detected (anti-forensics)",
                        "HISTFILE is unset/nulled or .bash_history points to /dev/null. "
                        "The campaign disables history to hide its tracks.",
                        evidence=histfile_hits))


def check_access_logs(rep: Report, log_dirs: list, mitigation_date=None,
                      max_matches=MAX_LOG_MATCHES) -> None:
    # max_matches is how many example entries to list per category; None = all.
    # Matched attack lines are kept VERBATIM (untruncated) -- the full request,
    # status, and user-agent are exactly what makes them worth reading.
    unlimited = max_matches is None
    files = []
    for d in log_dirs:
        if not os.path.isdir(d):
            continue
        files += glob.glob(os.path.join(d, "*access*"))
        files += glob.glob(os.path.join(d, "*access*.gz"))
    files = sorted(set(files))
    if not files:
        rep.note("No web-server access logs found; exploit-attempt check skipped. "
                 "Pass --log-dir if logs live elsewhere.")
        return

    exploit_ev, recon_ev = [], []
    exploit_total = recon_total = 0
    before = on = after = undated = 0        # attack timing vs mitigation_date
    earliest = latest = None
    unreadable = 0
    for path in files:
        fh = open_maybe_gzip(path)
        if fh is None:
            unreadable += 1
            continue
        try:
            for line in fh:
                ex, rc = _classify_log_line(line)
                if not (ex or rc):
                    continue
                dt = parse_apache_time(line)
                tstr = dt.date().isoformat() if dt else "undated"
                if dt is not None:
                    if earliest is None or dt < earliest:
                        earliest = dt
                    if latest is None or dt > latest:
                        latest = dt
                if mitigation_date is not None:
                    if dt is None:
                        undated += 1
                    elif dt.date() < mitigation_date:
                        before += 1
                    elif dt.date() == mitigation_date:
                        on += 1
                    else:
                        after += 1
                if ex:
                    exploit_total += 1
                    if unlimited or len(exploit_ev) < max_matches:
                        exploit_ev.append(f"{path} [{tstr}]: [{'; '.join(ex + rc)}] {line.strip()}")
                else:
                    recon_total += 1
                    if unlimited or len(recon_ev) < max_matches:
                        recon_ev.append(f"{path} [{tstr}]: [{'; '.join(rc)}] {line.strip()}")
        except Exception:
            unreadable += 1
        finally:
            fh.close()

    total = exploit_total + recon_total
    if total:
        rep.attack_summary = {
            "total": total,
            "exploit": exploit_total,
            "recon": recon_total,
            "before_mitigation": before,
            "on_mitigation_date": on,
            "after_mitigation": after,
            "undated": undated,
            "earliest": earliest.isoformat() if earliest else None,
            "latest": latest.isoformat() if latest else None,
        }

    if not unlimited and exploit_total > max_matches:
        exploit_ev.append(f"... (+{exploit_total - max_matches} more exploit-shaped "
                          "request(s); pass --max-log-matches all to list every one)")
    if not unlimited and recon_total > max_matches:
        recon_ev.append(f"... (+{recon_total - max_matches} more request(s) from the "
                        "attacker IP; pass --max-log-matches all to list every one)")

    if exploit_ev:
        rep.add(Finding(SEV_HIGH, "weblog",
                        "CVE-2026-90817 exploit-attempt signature in access logs",
                        "Request(s) reaching DataImportController via the survey "
                        "__passthru (the attack's hallmark) or using the known attacker "
                        "survey hash. This is an exploitation ATTEMPT in the logs -- it "
                        "is not by itself proof of success; the host-state checks above "
                        "(web shell, miner, persistence) are what confirm compromise.",
                        evidence=exploit_ev))
    if recon_ev:
        rep.add(Finding(SEV_MEDIUM, "weblog",
                        f"Traffic from the known attacker source IP ({IOC_SOURCE_IP})",
                        "Request(s) from the documented exploit source IP that were NOT "
                        "exploit-shaped (e.g. GET / or /surveys/ probes) -- most likely "
                        "reconnaissance. Worth noting that the host was targeted, but "
                        "not evidence of exploitation on its own.",
                        evidence=recon_ev))
    if unreadable and not is_root():
        rep.note(f"{unreadable} log file(s) unreadable without root; log check partial.")


# --------------------------------------------------------------------------- #
# Rendering & orchestration
# --------------------------------------------------------------------------- #

def _attack_timing_verdict(rep: Report, s: dict, vuln: bool) -> str:
    """Compromise likelihood from WHEN the logged attacks happened relative to
    the mitigation date. Earliest bucket wins (before > on > after)."""
    n = s["total"]
    md = rep.mitigation_date
    tail = ""
    if s["undated"]:
        tail = (f"; {s['undated']} attack(s) had no parseable timestamp -- "
                "review manually")
    if md is None:
        if vuln:
            return (f"ATTACKED and host is still VULNERABLE -- LIKELY COMPROMISED "
                    f"({n} malicious request(s) in logs){tail}")
        return (f"ATTACKED: {n} malicious request(s) in logs; set --mitigation-date "
                "(or restore the patched redcap_vX.Y.Z directory) to judge whether "
                f"they predate your fix{tail}")
    if s["before_mitigation"] > 0:
        return (f"ATTACKED WHILE VULNERABLE -- LIKELY COMPROMISED: "
                f"{s['before_mitigation']} attack(s) predate mitigation {md}{tail}")
    if s["on_mitigation_date"] > 0:
        return (f"ATTACKED -- POSSIBLY COMPROMISED: {s['on_mitigation_date']} attack(s) "
                f"on the mitigation date {md}; compare each attack's time to the actual "
                f"upgrade timestamp{tail}")
    return (f"ATTACKED but NOT LIKELY COMPROMISED: all {n} attack(s) post-date "
            f"mitigation {md}{tail}")


def verdict(rep: Report) -> str:
    # Only host-STATE findings (artifacts of a successful compromise) force the
    # "compromised" verdict outright. Web-server log hits are attacks against
    # the endpoint; whether they imply compromise depends on their timing vs.
    # the mitigation date, handled in _attack_timing_verdict.
    host_state = {"webshell", "staging", "hash", "process", "socket",
                  "cron", "ssh", "profile"}
    worst = SEV_OK
    for f in rep.findings:
        if f.check in host_state and _SEV_RANK[f.severity] > _SEV_RANK[worst]:
            worst = f.severity
    vuln = any(f.check == "version" and f.severity == SEV_HIGH for f in rep.findings)

    parts = []
    if _SEV_RANK[worst] >= _SEV_RANK[SEV_HIGH]:
        parts.append("LIKELY COMPROMISED (host IOCs present)")
    elif _SEV_RANK[worst] >= _SEV_RANK[SEV_MEDIUM]:
        parts.append("SUSPICIOUS host state -- investigate")
    else:
        s = rep.attack_summary
        if not s or s["total"] == 0:
            parts.append("no host compromise indicators; no attacks observed in logs")
        else:
            parts.append(_attack_timing_verdict(rep, s, vuln))
    if vuln:
        parts.append("VULNERABLE (version below patch)")
    return " / ".join(parts)


_SEV_COLORS = {
    SEV_CRITICAL: "CRIT", SEV_HIGH: "HIGH", SEV_MEDIUM: "MED ",
    SEV_LOW: "LOW ", SEV_INFO: "INFO", SEV_OK: "OK  ", SEV_ERROR: "ERR ",
}


def render_text(rep: Report, args) -> str:
    out = []
    out.append("=" * 72)
    out.append("CVE-2026-90817 REDCap compromise scan (read-only / passive)")
    out.append(f"host:        {socket.gethostname()}")
    out.append(f"time:        {datetime.datetime.now().isoformat(timespec='seconds')}")
    out.append(f"redcap root: {args.redcap_root}")
    out.append(f"redcap ver:  {rep.redcap_version or 'unknown'}")
    mit = rep.mitigation_date or "unknown"
    if rep.mitigation_source:
        mit += f"  ({rep.mitigation_source})"
    out.append(f"mitigation:  {mit}")
    out.append(f"privileges:  {'root' if is_root() else 'NON-ROOT (scan is partial)'}")
    out.append("=" * 72)
    for i, line in enumerate(_wrap(f"VERDICT: {verdict(rep)}", 70)):
        out.append(line if i == 0 else f"         {line}")
    out.append("")

    s = rep.attack_summary
    if s:
        out.append("Attack timing (log requests classified as attacks):")
        out.append(f"  total {s['total']}  (exploit-shaped {s['exploit']}, "
                   f"attacker-IP {s['recon']})")
        if rep.mitigation_date:
            out.append(f"  vs mitigation {rep.mitigation_date}:  "
                       f"before {s['before_mitigation']}, "
                       f"on {s['on_mitigation_date']}, "
                       f"after {s['after_mitigation']}, "
                       f"undated {s['undated']}")
        if s["earliest"]:
            out.append(f"  observed window:  {s['earliest']}  ..  {s['latest']}")
        out.append("")

    actionable = [f for f in rep.findings if f.severity not in (SEV_OK,)]
    actionable.sort(key=lambda f: -_SEV_RANK[f.severity])
    if not actionable:
        out.append("No findings. (Still confirm the version against vendor notes.)")
    for f in actionable:
        if args.quiet and f.severity in (SEV_INFO,):
            continue
        out.append(f"[{_SEV_COLORS.get(f.severity, f.severity)}] {f.check}: {f.title}")
        if f.detail:
            for line in _wrap(f.detail, 68):
                out.append(f"        {line}")
        for ev in f.evidence:
            out.append(f"          - {ev}")
        out.append("")

    if not args.quiet:
        oks = [f for f in rep.findings if f.severity == SEV_OK]
        for f in oks:
            out.append(f"[OK  ] {f.check}: {f.title}")
        if oks:
            out.append("")

    if rep.notes:
        out.append("Scan notes:")
        for n in rep.notes:
            out.append(f"  * {n}")
        out.append("")

    # Only suggest remediation when there is actually something to remediate.
    if rep.has_at_least(SEV_LOW):
        out.append("-" * 72)
        out.append("Remediation:")
        out.append("  1. Patch REDCap to a fixed release (16.0.49 LTS / 17.3.10 LTS /")
        out.append("     17.4.4 Std or later); confirm the exact release vs. vendor notes.")
        out.append("  2. If any IOC fired: isolate the host from the network, preserve")
        out.append("     evidence, rotate all credentials and SSH keys, and engage IR.")
        out.append("  3. This tool does NOT remediate -- it only detects.")
        out.append("-" * 72)
    return "\n".join(out)


def _wrap(text: str, width: int) -> list:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines


def render_json(rep: Report, args) -> str:
    payload = {
        "tool": "redcap_cve_2026_90817_scan",
        "cve": "CVE-2026-90817",
        "host": socket.gethostname(),
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "redcap_root": args.redcap_root,
        "redcap_version": rep.redcap_version,
        "privileges": "root" if is_root() else "non-root",
        "partial_scan": rep.partial or not is_root(),
        "mitigation_date": rep.mitigation_date,
        "mitigation_source": rep.mitigation_source,
        "attack_summary": rep.attack_summary,
        "verdict": verdict(rep),
        "findings": [asdict(f) for f in rep.findings if f.severity != SEV_OK],
        "ok_checks": [f.check for f in rep.findings if f.severity == SEV_OK],
        "notes": rep.notes,
    }
    return json.dumps(payload, indent=2)


def compute_exit_code(rep: Report) -> int:
    if rep.has_at_least(SEV_MEDIUM):
        return 1
    # Clean so far. If the scan was partial (non-root/errors), we cannot fully
    # assert "clean" -> exit 2. Otherwise 0.
    if rep.partial or not is_root() or any(f.severity == SEV_ERROR for f in rep.findings):
        return 2
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Passive, read-only compromise/vulnerability scanner for "
                    "CVE-2026-90817 (REDCap RCE / XMRig campaign). Detection only.")
    p.add_argument("--redcap-root", default="/var/www/html/redcap",
                   help="REDCap install root (default: /var/www/html/redcap)")
    p.add_argument("--log-dir", action="append", default=None,
                   help="Web-server log dir to scan (repeatable). "
                        "Default: /var/log/apache2, /var/log/httpd, /var/log/nginx.")
    p.add_argument("--home-dir", action="append", default=None,
                   help="Extra home dir to scan for SSH keys / rc files (repeatable).")
    p.add_argument("--full-hash-scan", action="store_true",
                   help="Recursively hash files under temp/cache and staging dirs "
                        "(slower). Default: a bounded set only.")
    p.add_argument("--mitigation-date", metavar="YYYY-MM-DD", default=None,
                   help="Date the vulnerability was closed by upgrading REDCap. "
                        "Log attacks are bucketed before/on/after this date to judge "
                        "compromise likelihood. If omitted, inferred from the install "
                        "mtime of the earliest patched redcap_vX.Y.Z directory.")
    p.add_argument("--max-log-matches", metavar="N", default=str(MAX_LOG_MATCHES),
                   help=f"Max attack log entries to list per category, kept verbatim "
                        f"(default: {MAX_LOG_MATCHES}). Use 'all' to list every match.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress OK/INFO lines in text output.")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    log_dirs = args.log_dir or ["/var/log/apache2", "/var/log/httpd", "/var/log/nginx"]
    homes = list_home_dirs(args.home_dir)

    rep = Report()
    if not is_root():
        rep.partial = True

    # Resolve the mitigation date: explicit flag wins, else infer from the
    # install mtime of the earliest patched redcap_vX.Y.Z directory.
    mitigation_date = None
    if args.mitigation_date:
        try:
            mitigation_date = datetime.date.fromisoformat(args.mitigation_date)
            rep.mitigation_source = "provided via --mitigation-date"
        except ValueError:
            print(f"error: --mitigation-date must be YYYY-MM-DD (got "
                  f"{args.mitigation_date!r})", file=sys.stderr)
            return 2
    else:
        mitigation_date, rep.mitigation_source = detect_mitigation_date(args.redcap_root)
    rep.mitigation_date = mitigation_date.isoformat() if mitigation_date else None

    # How many attack log entries to list (verbatim); 'all' = unlimited.
    _mlm = args.max_log_matches.strip().lower()
    if _mlm in ("all", "none", "unlimited"):
        max_matches = None
    else:
        try:
            max_matches = int(_mlm)
        except ValueError:
            print(f"error: --max-log-matches must be an integer or 'all' (got "
                  f"{args.max_log_matches!r})", file=sys.stderr)
            return 2

    # Each check is isolated so one failure never aborts the scan.
    checks = [
        ("version", lambda: check_version(rep, args.redcap_root)),
        ("webshell", lambda: check_webshell(rep, args.redcap_root)),
        ("staging", lambda: check_staging(rep)),
        ("hash", lambda: check_hashes(rep, args.redcap_root, args.full_hash_scan)),
        ("process", lambda: check_processes(rep)),
        ("socket", lambda: check_sockets(rep)),
        ("cron", lambda: check_cron(rep)),
        ("ssh", lambda: check_authorized_keys(rep, homes)),
        ("profile", lambda: check_profiles(rep, homes)),
        ("weblog", lambda: check_access_logs(rep, log_dirs, mitigation_date, max_matches)),
    ]
    for name, fn in checks:
        try:
            fn()
        except Exception as exc:  # defensive: never crash the whole scan
            rep.add(Finding(SEV_ERROR, name, f"check '{name}' raised an error",
                            str(exc)))
            rep.partial = True

    out = render_json(rep, args) if args.json else render_text(rep, args)
    print(out)
    return compute_exit_code(rep)


if __name__ == "__main__":
    sys.exit(main())
