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
processes, sockets, and logs. Run as root (Linux) or an elevated Administrator
(Windows) for a complete scan; it degrades gracefully (and says so) without
privileges.

Stdlib only. Python 3.7+.

Platforms
---------
  * Linux  (Debian- and RHEL-family): fully supported, matches the documented
    Unit 42 campaign IOCs. Apache logs at /var/log/apache2 or /var/log/httpd and
    nginx at /var/log/nginx are auto-detected.
  * Windows (REDCap on IIS or Apache/XAMPP): BEST-EFFORT, see the WINDOWS
    SUPPORT note below. The host OS primitives are abstracted behind a
    HostProvider so the vulnerability/exploit-attempt detection (which lives
    entirely in REDCap's PHP and the web-server logs) is identical on both.

WINDOWS SUPPORT (read this before trusting a Windows "compromised" verdict)
--------------------------------------------------------------------------
The documented Unit 42 campaign is Linux-only: an ELF XMRig miner, a
`syslog-ng-<hash>` exec masquerade, a Monero wallet on a process command line,
cron persistence, and an SSH backdoor key. A Windows REDCap host exploited
through the SAME CVE would almost certainly be given a DIFFERENT post-
exploitation payload (a Windows miner, Run-key / Scheduled-Task persistence,
etc.). So on Windows:

  * The "am I vulnerable?" and "am I being attacked?" answers (version + web-log
    signature) are first-class and fully shared with Linux.
  * The "am I compromised?" host-state checks are PROVISIONAL / lower-confidence.
    They look for GENERIC post-exploitation (a miner process or its local API
    listener, a scheduled task pulling a remote script, a new admin SSH key,
    executables staged in temp dirs) rather than the exact documented artifacts,
    and the Windows provider itself has not been validated on real hardware yet.
    Findings are labeled accordingly; confirm manually before acting.

Usage:
    sudo python3 -I redcap_cve_2026_90817_scan.py [--redcap-root PATH] [--json]

Exit codes:
    0  clean and patched (and scan was complete)
    1  one or more findings (vulnerable version and/or IOC) -- investigate
    2  scan could not be completed fully (errors, or unprivileged and otherwise
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
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional, Tuple

# --------------------------------------------------------------------------- #
# IOC constants -- single source of truth (from the Unit 42 report).
# Update here if the vendor/threat-intel publishes more indicators.
# These are platform-independent facts about the campaign; where an IOC is
# Linux-specific (a path, an ELF, a Linux TTP) the platform provider owns it.
# --------------------------------------------------------------------------- #

IOC_SOURCE_IP = "202.61.130.221"            # exploit source
IOC_POOL_DOMAIN = "auto.c3pool.org"         # mining pool
IOC_DROPPER_SHA256 = (
    "39a435123dc1fffd499aa2acf11ef46e3ee2e805bf137811af0c2c5b12546920"
)
# NOTE: `.bladec` files in temp/cache are NOT an indicator. REDCap core uses the
# BladeOne template engine, which compiles views to hash-named `.bladec` files in
# temp/cache as normal output -- so the extension (and any incident-specific
# compiled-template hash name) is routine, not malicious. A genuinely malicious
# file dropped there is still caught by content hash in check_hashes(), which is
# extension-independent. Do NOT reintroduce a `.bladec`-extension web-shell check.
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
# Process command-line / name tokens that indicate the miner itself. These are
# cross-platform: the pool domain, wallet, and the XMRig/stratum strings would
# reappear on a Windows miner too, so we match them regardless of OS.
MINER_CMD_TOKENS = ("xmrig", "c3pool", "stratum+tcp", IOC_POOL_DOMAIN.lower(),
                    IOC_MONERO_WALLET.lower())

# Exploit-request fingerprint for web-server logs.
# IMPORTANT: `__passthru` and `route=` are LEGITIMATE REDCap parameters --
# External Modules route through __passthru (e.g.
# `__passthru=ExternalModules&prefix=legacy_url_fixer&ajax=1`) and normal survey
# traffic uses a plain `__passthru=index.php&route=PdfController:index` to reach
# benign controllers. Matching either substring alone produces false positives,
# so _classify_log_line() below matches only the malicious combinations:
#
#   1. DataImportController reached via __passthru -- the report's RCE sink.
#      Always flagged, at any encoding.
#   2. ANY internal <name>Controller reached via a __passthru whose `index.php`
#      was DOUBLE-ENCODED (e.g. %2569ndex.php). This is the campaign's real
#      generalizable signature: legitimate clients send a plain, literal
#      `index.php`, never a double-encoded one, so the obfuscation -- not the
#      controller name, not the HTTP status -- is what distinguishes the attack.
#      (Observed in the wild reaching ParcelController:show, which the old
#      DataImportController-only rule missed and caught only by source IP.)
#
# Never match the bare parameter names.
IOC_ATTACKER_SURVEY_HASH = "s=NXCJMDCWXE"   # specific hash from the report sample
# Extract the internal controller a request routes to (for reporting).
INTERNAL_CONTROLLER_RE = re.compile(r"route=([a-z0-9_]+controller)\b", re.IGNORECASE)

# Patched releases and affected floor (public threat-intel; confirm vs. vendor).
FIXED_VERSIONS = {
    (16, 0): (16, 0, 49),   # LTS line
    (17, 3): (17, 3, 10),   # LTS line
    (17, 4): (17, 4, 4),    # Standard line
}
AFFECTED_FLOOR = (13, 3, 0)
TOP_STANDARD_FIX = (17, 4, 4)

# Patterns indicating a fetch-to-shell cradle in cron / profile / task files.
# Linux shell cradles.
FETCH_TO_SHELL_RE = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(bash|sh)\b"
    r"|base64\s+(-d|--decode)\b[^\n|]*\|\s*(bash|sh)\b"
    r"|\beval\b.*\$\(.*(curl|wget)",
    re.IGNORECASE,
)
# Windows PowerShell / cmd download cradles (provisional). Covers
# `IEX (New-Object Net.WebClient).DownloadString(...)`, `iwr ... | iex`,
# `Invoke-WebRequest ... -OutFile`, `curl/certutil -urlcache`, base64 -enc, etc.
WIN_FETCH_TO_SHELL_RE = re.compile(
    r"(New-Object\s+Net\.WebClient)"
    r"|DownloadString|DownloadFile|DownloadData"
    r"|(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n|]*(\|\s*(iex|Invoke-Expression)|-OutFile)"
    r"|\b(iex|Invoke-Expression)\b"
    r"|certutil(\.exe)?\s+[^\n]*-urlcache"
    r"|-enc(odedcommand)?\b",
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
    privileged: bool = False                 # provider-reported privilege level
    platform_name: str = ""                  # active provider (linux/windows/...)

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
# Host-fact value types yielded by a HostProvider
# --------------------------------------------------------------------------- #

@dataclass
class ProcInfo:
    pid: str
    comm: str = ""          # short process/image name
    cmdline: str = ""       # full command line (space-joined)
    exe: str = ""           # resolved executable path, if known


@dataclass
class SockInfo:
    proto: str              # "tcp" / "tcp6"
    laddr: str              # local host (dotted/bracketless)
    lport: int
    raddr: str              # remote host
    rport: int
    state: str              # normalized: "LISTEN", "ESTAB", ... (provider-normalized)


@dataclass
class JobInfo:
    source: str             # label: cron file path or scheduled-task name
    lines: list = field(default_factory=list)   # text lines to scan


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


def _run(cmd: list, timeout: int = 20) -> Optional[str]:
    """Run a read-only host command and return stdout text, or None on any
    failure. Used only by the Windows provider to query the OS (tasklist,
    netstat, reg, schtasks). Never raises."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        return proc.stdout.decode("utf-8", "replace")
    except Exception:
        return None


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


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# status + size immediately after the quoted "..request.." in CLF/combined logs.
_STATUS_SIZE_RE = re.compile(r'"\s+(\d{3})\s+(\d+|-)')


def _parse_clf_fields(line: str):
    """Best-effort extract (client_ip, status, size) from an access-log line.

    Handles both the plain CLF shape (`IP - - [ts] "req" status size`) and the
    vhost-prefixed shape (`host:port IP - - [ts] ...`) seen on the target host,
    by taking the last IPv4 token appearing before the `[timestamp]`. Returns
    None for any field that cannot be parsed; never raises. size may be None
    when the server logged `-`."""
    ip = status = size = None
    m_ts = _APACHE_TS_RE.search(line)
    prefix = line[:m_ts.start()] if m_ts else line
    ips = _IPV4_RE.findall(prefix)
    if ips:
        ip = ips[-1]                       # client IP sits just before the [ts]
    m = _STATUS_SIZE_RE.search(line)
    if m:
        status = m.group(1)
        size = None if m.group(2) == "-" else int(m.group(2))
    return (ip, status, size)


# --------------------------------------------------------------------------- #
# W3C Extended log format (IIS) -> synthetic CLF adapter
# --------------------------------------------------------------------------- #
#
# IIS logs in W3C Extended format: '#'-prefixed directives (including a
# `#Fields:` line that names the columns) followed by space-delimited data rows
# with UTC timestamps. Rather than re-implement classification/timing/aggregation
# for a second format, we convert each W3C row into a synthetic CLF/combined line
# carrying the SAME information (client IP, full decoded request with query
# string, status, a bracketed timestamp) and feed it through the existing
# _classify_log_line / parse_apache_time / _parse_clf_fields pipeline unchanged.
# That keeps the attack signature logic single-sourced across Apache and IIS.

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _w3c_to_clf(fields: list, row: list) -> Optional[str]:
    """Build a synthetic combined-log line from a W3C field map + data row.
    Returns None if the essential columns are absent."""
    idx = {name.lower(): i for i, name in enumerate(fields)}

    def get(col):
        i = idx.get(col)
        if i is None or i >= len(row):
            return None
        val = row[i]
        return None if val == "-" else val

    ip = get("c-ip") or "-"
    method = get("cs-method") or "GET"
    stem = get("cs-uri-stem") or "/"
    query = get("cs-uri-query")
    status = get("sc-status") or "-"
    ua = get("cs(user-agent)") or "-"
    uri = stem if not query else f"{stem}?{query}"

    # Timestamp: W3C logs date + time as UTC (e.g. 2026-10-07 / 12:34:56).
    date = get("date")
    time = get("time")
    ts = ""
    if date and time:
        try:
            y, mo, d = (int(x) for x in date.split("-"))
            ts = f"[{d:02d}/{_MONTHS[mo - 1]}/{y:04d}:{time} +0000]"
        except (ValueError, IndexError):
            ts = ""
    # Mirror the combined-log shape _parse_clf_fields/_classify_log_line expect:
    #   IP - - [ts] "METHOD uri HTTP/1.1" status - "-" "UA"
    size = "-"
    return f'{ip} - - {ts} "{method} {uri} HTTP/1.1" {status} {size} "-" "{ua}"'


def _is_w3c_log(first_lines: list) -> bool:
    for ln in first_lines:
        s = ln.lstrip("\ufeff").strip()
        if s.startswith("#Fields:") or s.startswith("#Software: Microsoft Internet"):
            return True
        if s and not s.startswith("#"):
            return False      # first data line without a W3C directive -> not W3C
    return False


def iter_clf_lines(path: str) -> Iterable[str]:
    """Yield combined-log-shaped lines from an access log, transparently
    converting IIS W3C Extended logs to the CLF shape. Apache/nginx CLF lines
    pass through verbatim. Never raises; silently yields nothing on failure."""
    fh = open_maybe_gzip(path)
    if fh is None:
        raise OSError("unreadable")       # caller counts this as unreadable
    try:
        # Peek enough header lines to classify the format.
        head = []
        for ln in fh:
            head.append(ln)
            if len(head) >= 20:
                break
        w3c = _is_w3c_log(head)
        if not w3c:
            for ln in head:
                yield ln
            for ln in fh:
                yield ln
            return
        # W3C: track the active #Fields: directive; convert data rows.
        fields = []
        for ln in _chain(head, fh):
            s = ln.lstrip("\ufeff")
            st = s.strip()
            if not st:
                continue
            if st.startswith("#"):
                if st[1:].lstrip().lower().startswith("fields:"):
                    after = st.split(":", 1)[1] if ":" in st else ""
                    fields = after.split()
                continue
            if not fields:
                continue
            row = st.split()
            syn = _w3c_to_clf(fields, row)
            if syn is not None:
                yield syn
    finally:
        fh.close()


def _chain(*iters):
    for it in iters:
        for x in it:
            yield x


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

    Two malicious patterns are flagged as exploit-shaped (see the IOC block):

      1. DataImportController reached via the unauthenticated survey `__passthru`
         -- the report's RCE sink. Flagged at any encoding.
      2. ANY internal <name>Controller reached via a `__passthru` whose
         `index.php` was DOUBLE-ENCODED (e.g. %2569ndex.php). Legitimate survey
         traffic sends a plain, literal `index.php`, so the double-encoding is
         the campaign signature that generalizes beyond one controller name.

    Normal REDCap survey traffic also uses `__passthru=index.php` to reach benign
    controllers (PdfController, SendItController, ExternalModules, ...), so
    neither `__passthru` nor `index.php` nor `route=` is an indicator on its own
    and we never match on them alone.

    This function is web-server- and OS-agnostic: it reads only the request URL,
    so Apache (Linux or Windows) and IIS (via the W3C->CLF adapter) are handled
    identically."""
    exploit, recon = [], []
    once = urllib.parse.unquote(line).lower()       # single decode round
    full = _url_unquote_recursive(line).lower()     # full (defeats double-encode)

    has_passthru = "__passthru" in full
    # (1) DataImportController -- the RCE sink -- at any encoding.
    if has_passthru and "route=dataimportcontroller" in full:
        exploit.append("survey __passthru -> DataImportController (RCE sink)")
    # (2) Double-encoded __passthru -> any internal controller.
    #     Obfuscation test: `index.php` is present only after the FULL decode,
    #     i.e. it was not literal after a single round (so it was multiply
    #     encoded, as in %2569ndex.php). Plain single-encoded/legit traffic has
    #     `index.php` already present once-decoded and is not matched here.
    if has_passthru and "index.php" in full and "index.php" not in once:
        m = INTERNAL_CONTROLLER_RE.search(full)
        ctrl = m.group(1) if m else "an internal controller"
        if ctrl.lower() != "dataimportcontroller":   # avoid duplicate reason
            exploit.append(
                f"obfuscated survey __passthru -> {ctrl} "
                "(double-encoded index.php)")
    # Exact attacker survey hash from the report sample.
    if IOC_ATTACKER_SURVEY_HASH.lower() in line.lower():
        exploit.append(f"attacker survey hash {IOC_ATTACKER_SURVEY_HASH}")

    # Known attacker source IP. Not exploit-shaped on its own -> reconnaissance.
    if IOC_SOURCE_IP in line:
        recon.append(f"contact from known attacker IP {IOC_SOURCE_IP}")

    return (_dedup(exploit), _dedup(recon))


def _line_is_suspicious(line: str, extra_res: Iterable) -> bool:
    """True if a cron/profile/task line matches a fetch-to-shell cradle (the
    provider supplies the platform-appropriate regex[es]) or references a known
    cross-platform IOC (pool domain, source IP, payload filename)."""
    low = line.lower()
    for rx in extra_res:
        if rx.search(line):
            return True
    if IOC_POOL_DOMAIN in low or IOC_SOURCE_IP in line:
        return True
    if any(name in low for name in (n.lower() for n in IOC_PAYLOAD_NAMES)):
        return True
    return False


# --------------------------------------------------------------------------- #
# Host providers: everything OS-specific lives behind this seam.
# The checks below consume only HostProvider methods, so adding an OS is a
# matter of adding a provider, never touching the detection logic.
# --------------------------------------------------------------------------- #

class HostProvider:
    """Read-only, exception-safe access to OS-specific host facts.

    The base class is a safe, empty default: every method returns nothing and
    is_privileged() is False. Concrete providers override what they can.
    """
    name = "base"
    #: whether this provider's host-state IOCs match the documented campaign
    #: (Linux) or are provisional/generic heuristics (Windows).
    host_state_confidence = "provisional"

    # ---- privilege / locations -------------------------------------------- #
    def is_privileged(self) -> bool:
        return False

    def staging_dirs(self) -> list:
        return []

    def exec_from_dirs(self) -> tuple:
        return tuple(self.staging_dirs())

    def home_dirs(self, extra) -> list:
        homes = []
        for d in extra or []:
            if d not in homes:
                homes.append(d)
        return [h for h in homes if os.path.isdir(h)]

    def default_log_dirs(self) -> list:
        return []

    def log_globs(self) -> list:
        return ["*access*", "*access*.gz"]

    # ---- fetch-to-shell dialect ------------------------------------------- #
    def fetch_to_shell_res(self) -> list:
        return [FETCH_TO_SHELL_RE]

    # ---- host-state fact sources (override as supported) ------------------ #
    def iter_processes(self) -> Iterable[ProcInfo]:
        return []

    def iter_sockets(self) -> Iterable[SockInfo]:
        return []

    def iter_scheduled_jobs(self) -> Iterable[JobInfo]:
        return []

    def iter_authorized_keys(self, homes) -> Iterable[Tuple[str, list]]:
        return []

    def iter_persistence_rc(self, homes) -> Iterable[Tuple[str, list]]:
        return []

    def history_suppression(self, homes) -> list:
        """Return evidence strings for shell/console history tampering."""
        return []

    def masquerade_findings(self, procs) -> list:
        """Return evidence strings for processes masquerading as system daemons.
        Campaign-specific on Linux; a generic heuristic on Windows."""
        return []

    def can_enumerate_processes(self) -> bool:
        return False

    def can_enumerate_sockets(self) -> bool:
        return False


class LinuxHostProvider(HostProvider):
    """Debian- and RHEL-family Linux. Matches the documented Unit 42 campaign."""
    name = "linux"
    host_state_confidence = "documented"

    _STAGING = ["/var/tmp", "/dev/shm", "/tmp"]

    def is_privileged(self) -> bool:
        return is_root()

    def staging_dirs(self) -> list:
        return list(self._STAGING)

    def exec_from_dirs(self) -> tuple:
        return ("/var/tmp", "/dev/shm", "/tmp")

    def home_dirs(self, extra) -> list:
        homes = []
        if os.path.isdir("/root"):
            homes.append("/root")
        homes.extend(sorted(glob.glob("/home/*")))
        for d in extra or []:
            if d not in homes:
                homes.append(d)
        return [h for h in homes if os.path.isdir(h)]

    def default_log_dirs(self) -> list:
        return ["/var/log/apache2", "/var/log/httpd", "/var/log/nginx"]

    def can_enumerate_processes(self) -> bool:
        return os.path.isdir("/proc")

    def can_enumerate_sockets(self) -> bool:
        return os.path.exists("/proc/net/tcp") or os.path.exists("/proc/net/tcp6")

    def iter_processes(self) -> Iterable[ProcInfo]:
        if not os.path.isdir("/proc"):
            return
        for entry in glob.glob("/proc/[0-9]*"):
            pid = os.path.basename(entry)
            comm = (read_text(os.path.join(entry, "comm")) or "").strip()
            cmdline_raw = read_text(os.path.join(entry, "cmdline")) or ""
            cmdline = cmdline_raw.replace("\x00", " ").strip()
            try:
                exe = os.readlink(os.path.join(entry, "exe"))
            except (OSError, PermissionError):
                exe = ""
            yield ProcInfo(pid=pid, comm=comm, cmdline=cmdline, exe=exe)

    def iter_sockets(self) -> Iterable[SockInfo]:
        for fam, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
            if not os.path.exists(path):
                continue
            for line in read_lines(path)[1:]:       # skip header
                parts = line.split()
                if len(parts) < 4:
                    continue
                lhost, lport = parse_procnet_addr(parts[1])
                rhost, rport = parse_procnet_addr(parts[2])
                state = "LISTEN" if parts[3].upper() == "0A" else parts[3].upper()
                yield SockInfo(fam, lhost, lport, rhost, rport, state)

    def iter_scheduled_jobs(self) -> Iterable[JobInfo]:
        cron_files = ["/etc/crontab"]
        cron_files += glob.glob("/etc/cron.d/*")
        for sub in ("hourly", "daily", "weekly", "monthly"):
            cron_files += glob.glob(f"/etc/cron.{sub}/*")
        cron_files += glob.glob("/var/spool/cron/crontabs/*")
        cron_files += glob.glob("/var/spool/cron/*")
        for path in cron_files:
            if not os.path.isfile(path):
                continue
            txt = read_text(path)
            if txt is None:
                yield JobInfo(source=path, lines=None)   # signal unreadable
                continue
            yield JobInfo(source=path, lines=txt.splitlines())

    def iter_authorized_keys(self, homes) -> Iterable[Tuple[str, list]]:
        for home in homes:
            for name in ("authorized_keys", "authorized_keys2"):
                path = os.path.join(home, ".ssh", name)
                if not os.path.exists(path):
                    continue
                lines = read_lines(path)
                if not lines and read_text(path) is None:
                    yield (path, None)                   # unreadable
                else:
                    yield (path, lines)

    def iter_persistence_rc(self, homes) -> Iterable[Tuple[str, list]]:
        rc_names = (".profile", ".bashrc", ".bash_profile", ".bash_login")
        for home in homes:
            for name in rc_names:
                path = os.path.join(home, name)
                if os.path.isfile(path):
                    yield (path, read_lines(path))

    def history_suppression(self, homes) -> list:
        hits = []
        rc_names = (".profile", ".bashrc", ".bash_profile", ".bash_login")
        for home in homes:
            for name in rc_names:
                path = os.path.join(home, name)
                if not os.path.isfile(path):
                    continue
                for i, line in enumerate(read_lines(path), 1):
                    s = line.strip()
                    if re.search(r"\bunset\s+HISTFILE\b", s) or \
                            re.search(r"\bHISTFILE\s*=\s*(/dev/null)?\s*$", s) or \
                            "HISTFILE=/dev/null" in s:
                        hits.append(f"{path}:{i}: {s[:160]}")
            hist = os.path.join(home, ".bash_history")
            try:
                if os.path.islink(hist) and os.path.realpath(hist) == "/dev/null":
                    hits.append(f"{hist} -> /dev/null (history suppressed)")
            except OSError:
                pass
        return hits

    def masquerade_findings(self, procs) -> list:
        # The miner is launched via exec -a with syslog-style names; the real
        # daemon's comm is 'syslog-ng', not 'syslog-ng-<hash>'.
        hits = []
        for p in procs:
            if p.comm.startswith("syslog-ng-"):
                hits.append(f"pid {p.pid}: comm={p.comm!r} exe={p.exe or '?'}")
        return hits


class WindowsHostProvider(HostProvider):
    """REDCap on Windows (IIS or Apache/XAMPP). BEST-EFFORT, UNVALIDATED.

    The documented campaign is Linux-only, so these host-state checks look for
    GENERIC post-exploitation and have not been run against a live Windows host
    (see the module WINDOWS SUPPORT note). Every primitive is guarded so that,
    on a non-Windows box (e.g. when forced via --platform for a dry run), it
    simply returns nothing rather than running a same-named Linux binary.
    Stdlib only: subprocess to tasklist/netstat/schtasks/reg + file reads.
    """
    name = "windows"
    host_state_confidence = "provisional"

    def _on_windows(self) -> bool:
        return os.name == "nt"

    def is_privileged(self) -> bool:
        if not self._on_windows():
            return False
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            # Fallback: `net session` succeeds only when elevated.
            return _run(["net", "session"]) is not None

    def staging_dirs(self) -> list:
        dirs = []
        for env in ("TEMP", "TMP", "PUBLIC", "ProgramData", "SystemRoot"):
            val = os.environ.get(env)
            if val:
                dirs.append(val)
        # SystemRoot\Temp and a couple of fixed spots the campaign class favors.
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        dirs.append(os.path.join(sysroot, "Temp"))
        dirs.append(r"C:\Windows\Temp")
        dirs.append(r"C:\ProgramData")
        # De-dup preserving order.
        return _dedup([d for d in dirs if d])

    def exec_from_dirs(self) -> tuple:
        return tuple(self.staging_dirs())

    def home_dirs(self, extra) -> list:
        homes = []
        users = os.environ.get("SystemDrive", "C:") + r"\Users"
        try:
            for name in sorted(os.listdir(users)):
                p = os.path.join(users, name)
                if os.path.isdir(p) and name.lower() not in ("default", "default user",
                                                             "all users", "public"):
                    homes.append(p)
        except (OSError, PermissionError):
            pass
        for d in extra or []:
            if d not in homes:
                homes.append(d)
        return [h for h in homes if os.path.isdir(h)]

    def default_log_dirs(self) -> list:
        sysdrive = os.environ.get("SystemDrive", "C:")
        return [
            sysdrive + r"\inetpub\logs\LogFiles",       # IIS (W3C), per-site subdirs
            sysdrive + r"\xampp\apache\logs",            # XAMPP (CLF)
            sysdrive + r"\Apache24\logs",                # Apache Lounge (CLF)
        ]

    def log_globs(self) -> list:
        # IIS: u_exYYMMDD.log / u_in*.log under W3SVC<n> subdirs; Apache: access.log
        return ["*.log", "u_ex*.log", "*access*", "*.log.gz", "*access*.gz"]

    def fetch_to_shell_res(self) -> list:
        return [WIN_FETCH_TO_SHELL_RE, FETCH_TO_SHELL_RE]

    def can_enumerate_processes(self) -> bool:
        return self._on_windows()

    def can_enumerate_sockets(self) -> bool:
        return self._on_windows()

    def iter_processes(self) -> Iterable[ProcInfo]:
        if not self._on_windows():
            return
        # Prefer PowerShell CIM (gives PID, Name, Path, CommandLine as CSV);
        # fall back to wmic, then tasklist (name+pid only).
        out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-CimInstance Win32_Process | "
                    "Select-Object ProcessId,Name,ExecutablePath,CommandLine | "
                    "ConvertTo-Csv -NoTypeInformation"])
        if out:
            import csv
            import io
            try:
                rdr = csv.DictReader(io.StringIO(out))
                for row in rdr:
                    yield ProcInfo(
                        pid=(row.get("ProcessId") or "").strip(),
                        comm=(row.get("Name") or "").strip(),
                        cmdline=(row.get("CommandLine") or "").strip(),
                        exe=(row.get("ExecutablePath") or "").strip())
                return
            except Exception:
                pass
        out = _run(["wmic", "process", "get",
                    "ProcessId,Name,ExecutablePath,CommandLine", "/format:csv"])
        if out:
            import csv
            import io
            try:
                for row in csv.DictReader(io.StringIO(out.strip())):
                    yield ProcInfo(
                        pid=(row.get("ProcessId") or "").strip(),
                        comm=(row.get("Name") or "").strip(),
                        cmdline=(row.get("CommandLine") or "").strip(),
                        exe=(row.get("ExecutablePath") or "").strip())
                return
            except Exception:
                pass
        out = _run(["tasklist", "/fo", "csv", "/nh"])
        if out:
            import csv
            import io
            for row in csv.reader(io.StringIO(out)):
                if len(row) >= 2:
                    yield ProcInfo(pid=row[1].strip(), comm=row[0].strip())

    def iter_sockets(self) -> Iterable[SockInfo]:
        if not self._on_windows():
            return
        out = _run(["netstat", "-ano", "-p", "TCP"]) or _run(["netstat", "-ano"])
        if not out:
            return
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0].upper() not in ("TCP", "TCP6"):
                continue
            proto = "tcp6" if ":" in parts[1] and parts[1].count(":") > 1 else "tcp"
            lhost, lport = _split_host_port(parts[1])
            rhost, rport = _split_host_port(parts[2])
            raw_state = parts[3].upper()
            state = "LISTEN" if raw_state == "LISTENING" else raw_state
            yield SockInfo(proto, lhost, lport, rhost, rport, state)

    def iter_scheduled_jobs(self) -> Iterable[JobInfo]:
        if not self._on_windows():
            return
        # Read the Task Scheduler job XML directly (read-only) and surface the
        # command/arguments text for cradle/IOC matching.
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        tasks_root = os.path.join(sysroot, "System32", "Tasks")
        try:
            import xml.etree.ElementTree as ET
        except Exception:
            ET = None
        for dirpath, _dirs, files in os.walk(tasks_root):
            for fn in files:
                path = os.path.join(dirpath, fn)
                txt = read_text(path)
                if txt is None:
                    yield JobInfo(source=path, lines=None)
                    continue
                lines = []
                if ET is not None:
                    try:
                        root = ET.fromstring(txt)
                        for el in root.iter():
                            tag = el.tag.split("}")[-1].lower()
                            if tag in ("command", "arguments") and el.text:
                                lines.append(el.text.strip())
                    except Exception:
                        lines = txt.splitlines()
                else:
                    lines = txt.splitlines()
                yield JobInfo(source=path, lines=lines)

    def iter_authorized_keys(self, homes) -> Iterable[Tuple[str, list]]:
        # Windows OpenSSH: per-user %USERPROFILE%\.ssh\authorized_keys plus the
        # shared administrators_authorized_keys under %ProgramData%\ssh.
        paths = []
        for home in homes:
            paths.append(os.path.join(home, ".ssh", "authorized_keys"))
        progdata = os.environ.get("ProgramData", r"C:\ProgramData")
        paths.append(os.path.join(progdata, "ssh", "administrators_authorized_keys"))
        for path in paths:
            if not os.path.exists(path):
                continue
            lines = read_lines(path)
            if not lines and read_text(path) is None:
                yield (path, None)
            else:
                yield (path, lines)

    def iter_persistence_rc(self, homes) -> Iterable[Tuple[str, list]]:
        # PowerShell profiles are the closest analogue to shell rc files.
        rel = [
            os.path.join("Documents", "WindowsPowerShell", "profile.ps1"),
            os.path.join("Documents", "WindowsPowerShell",
                         "Microsoft.PowerShell_profile.ps1"),
            os.path.join("Documents", "PowerShell", "profile.ps1"),
            os.path.join("Documents", "PowerShell",
                         "Microsoft.PowerShell_profile.ps1"),
        ]
        for home in homes:
            for r in rel:
                path = os.path.join(home, r)
                if os.path.isfile(path):
                    yield (path, read_lines(path))
        # All-hosts system profile.
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        for p in (os.path.join(sysroot, "System32", "WindowsPowerShell", "v1.0",
                               "profile.ps1"),):
            if os.path.isfile(p):
                yield (p, read_lines(p))
        # Registry Run keys (read-only via `reg query`), surfaced as pseudo-files.
        if self._on_windows():
            for hive in (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                         r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"):
                out = _run(["reg", "query", hive])
                if out:
                    yield (hive, out.splitlines())

    def history_suppression(self, homes) -> list:
        hits = []
        for home in homes:
            for r in (os.path.join("Documents", "WindowsPowerShell", "profile.ps1"),
                      os.path.join("Documents", "PowerShell", "profile.ps1")):
                path = os.path.join(home, r)
                if not os.path.isfile(path):
                    continue
                for i, line in enumerate(read_lines(path), 1):
                    s = line.strip()
                    if re.search(r"HistorySaveStyle\s+SaveNothing", s, re.IGNORECASE) \
                            or re.search(r"\bClear-History\b", s, re.IGNORECASE) \
                            or re.search(r"Remove-Item[^\n]*ConsoleHost_history",
                                         s, re.IGNORECASE):
                        hits.append(f"{path}:{i}: {s[:160]}")
        return hits

    def masquerade_findings(self, procs) -> list:
        # Generic Windows heuristic (provisional): a core system image name
        # running from outside System32/SysWOW64 is a classic masquerade.
        system_names = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
                        "winlogon.exe", "smss.exe", "explorer.exe"}
        ok_dirs = (r"c:\windows\system32", r"c:\windows\syswow64", r"c:\windows\sysnative")
        hits = []
        for p in procs:
            nm = (p.comm or "").lower()
            if nm in system_names and p.exe:
                low = p.exe.lower()
                if not any(low.startswith(d) for d in ok_dirs):
                    hits.append(f"pid {p.pid}: {p.comm!r} runs from {p.exe} "
                                "(system image outside System32)")
        return hits


def _split_host_port(hostport: str) -> tuple:
    """Split a netstat 'addr:port' token (IPv4 'ip:port' or IPv6 '[::1]:port')."""
    s = hostport.strip()
    if s.startswith("["):
        # [ipv6]:port
        close = s.rfind("]")
        host = s[1:close] if close != -1 else s
        rest = s[close + 1:]
        port = rest.lstrip(":")
    else:
        idx = s.rfind(":")
        host = s[:idx] if idx != -1 else s
        port = s[idx + 1:] if idx != -1 else ""
    try:
        return (host, int(port))
    except ValueError:
        return (host, 0)


def select_provider(platform_opt: str) -> HostProvider:
    """Pick a HostProvider from --platform (auto|linux|windows)."""
    if platform_opt == "linux":
        return LinuxHostProvider()
    if platform_opt == "windows":
        return WindowsHostProvider()
    # auto
    if os.name == "nt":
        return WindowsHostProvider()
    return LinuxHostProvider()


# --------------------------------------------------------------------------- #
# Checks (platform-neutral; all host access goes through the provider)
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


# (Deliberately no web-shell-by-extension check: see the IOC-block note on
# `.bladec`. REDCap/BladeOne writes hash-named `.bladec` files to temp/cache as
# normal output, so flagging the extension produced false positives. Known-bad
# files in temp/cache are still detected by content hash in check_hashes().)


def check_staging(rep: Report, host: HostProvider) -> None:
    hits = []
    # Exact documented archive path (Linux campaign artifact).
    if os.path.exists(IOC_MINER_ARCHIVE):
        hits.append((SEV_CRITICAL, f"{IOC_MINER_ARCHIVE} (mtime {mtime_str(IOC_MINER_ARCHIVE)})"))
    # Masquerading .syslog-* staging dirs and stray xmrig archives.
    for base in host.staging_dirs():
        for p in glob.glob(os.path.join(base, ".syslog-*")):
            hits.append((SEV_HIGH, f"{p} (mtime {mtime_str(p)})"))
        for p in glob.glob(os.path.join(base, "**", "xmrig*"), recursive=True):
            hits.append((SEV_HIGH, f"{p} (mtime {mtime_str(p)})"))
    if hits:
        rep.add(Finding(max(hits, key=lambda h: _SEV_RANK[h[0]])[0], "staging",
                        "Miner staging artifact(s) found",
                        "Files/dirs matching the XMRig staging pattern.",
                        evidence=[h[1] for h in hits]))
    # Competitor-removal dirs locked to 000 (Linux-specific permission TTP).
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


def _hash_candidates(full: bool, redcap_root: str, host: HostProvider) -> Iterable[str]:
    seen = set()
    roots = [os.path.join(redcap_root, "temp", "cache")] + host.staging_dirs()
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


def check_hashes(rep: Report, redcap_root: str, full: bool, host: HostProvider) -> None:
    matched = []
    count = 0
    for path in _hash_candidates(full, redcap_root, host):
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


def check_processes(rep: Report, host: HostProvider) -> None:
    if not host.can_enumerate_processes():
        rep.note("Process enumeration unavailable on this host; process check skipped.")
        return
    procs = list(host.iter_processes())
    fromtmp, miner = [], []
    exec_dirs = tuple(d.lower() for d in host.exec_from_dirs())
    for p in procs:
        low = (p.comm + " " + p.cmdline).lower()
        exe_low = (p.exe or "").lower()
        if exec_dirs and exe_low.startswith(exec_dirs):
            fromtmp.append(f"pid {p.pid}: exe={p.exe} comm={p.comm!r}")
        if any(tok in low for tok in MINER_CMD_TOKENS):
            miner.append(f"pid {p.pid}: comm={p.comm!r} cmd={p.cmdline[:200]!r}")

    masq = host.masquerade_findings(procs)

    if miner:
        rep.add(Finding(SEV_CRITICAL, "process",
                        "Cryptominer process indicator(s) running",
                        "Process name/args reference XMRig, the pool, or the wallet.",
                        evidence=miner))
    if fromtmp:
        rep.add(Finding(SEV_HIGH, "process",
                        "Process(es) executing from a temp directory",
                        "Executables under a temp/staging directory are a strong "
                        "indicator of the in-memory dropper / miner.",
                        evidence=fromtmp))
    if masq:
        detail = ("The miner is launched via exec -a with syslog-style names; "
                  "the real daemon's comm is 'syslog-ng', not 'syslog-ng-<hash>'.")
        if host.host_state_confidence != "documented":
            detail += (" (Provisional Windows heuristic: a system image running "
                       "from outside System32 -- confirm manually.)")
        rep.add(Finding(SEV_HIGH, "process",
                        "Masquerading system-process name(s)", detail,
                        evidence=masq))
    if not host.is_privileged():
        rep.note("Process check ran without privilege; some process metadata may be hidden.")


def check_sockets(rep: Report, host: HostProvider) -> None:
    if not host.can_enumerate_sockets():
        rep.note("Socket enumeration unavailable on this host; socket check skipped.")
        return
    listen, connected = [], []
    for s in host.iter_sockets():
        if s.state == "LISTEN" and s.lport == IOC_MINER_API_PORT and \
                s.laddr in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            listen.append(f"{s.proto} LISTEN {s.laddr}:{s.lport}")
        if s.raddr == IOC_SOURCE_IP:
            connected.append(f"{s.proto} {s.state} -> {s.raddr}:{s.rport}")
    if listen:
        rep.add(Finding(SEV_HIGH, "socket",
                        f"Local XMRig JSON-RPC API on :{IOC_MINER_API_PORT}",
                        "A listener on the miner's documented local control port.",
                        evidence=listen))
    if connected:
        rep.add(Finding(SEV_HIGH, "socket",
                        f"Active connection involving exploit source {IOC_SOURCE_IP}",
                        "Current socket to/from the documented attacker IP.",
                        evidence=connected))


def check_cron(rep: Report, host: HostProvider) -> None:
    res = host.fetch_to_shell_res()
    evidence = []
    unreadable = 0
    for job in host.iter_scheduled_jobs():
        if job.lines is None:
            unreadable += 1
            continue
        for lineno, line in enumerate(job.lines, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if _line_is_suspicious(line, res):
                evidence.append(f"{job.source}:{lineno}: {line.strip()[:200]}")
    if evidence:
        rep.add(Finding(SEV_HIGH, "cron",
                        "Suspicious scheduled-job entry(ies) (fetch-to-shell / IOC)",
                        "Scheduled-task/cron content matches the campaign's remote-"
                        "payload pull or references a known IOC. Review before acting.",
                        evidence=evidence))
    if unreadable and not host.is_privileged():
        rep.note(f"{unreadable} scheduled-job file(s) were unreadable without "
                 "privilege; scheduled-job check partial.")


def _ssh_fingerprint(blob: str) -> Optional[str]:
    try:
        raw = base64.b64decode(blob, validate=False)
        digest = hashlib.sha256(raw).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    except Exception:
        return None


def check_authorized_keys(rep: Report, host: HostProvider, homes: list) -> None:
    # Only report keys that match the IOC backdoor fingerprint. We deliberately
    # do NOT list or ask anyone to "review" the other keys: on a normal host
    # they belong to real user accounts and are not independently verifiable,
    # so listing them is pure noise.
    matched, unreadable = [], 0
    for path, lines in host.iter_authorized_keys(homes):
        if lines is None:
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
    if unreadable and not host.is_privileged():
        rep.note(f"{unreadable} authorized_keys file(s) unreadable without "
                 "privilege; SSH check partial.")


def check_profiles(rep: Report, host: HostProvider, homes: list) -> None:
    res = host.fetch_to_shell_res()
    evidence = []
    for path, lines in host.iter_persistence_rc(homes):
        for lineno, line in enumerate(lines, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if _line_is_suspicious(line, res):
                evidence.append(f"{path}:{lineno}: {line.strip()[:200]}")
    histfile_hits = host.history_suppression(homes)
    if evidence:
        rep.add(Finding(SEV_HIGH, "profile",
                        "Startup/profile file contains fetch-to-shell / IOC content",
                        "Injected startup code matching the campaign's persistence.",
                        evidence=evidence))
    if histfile_hits:
        rep.add(Finding(SEV_MEDIUM, "profile",
                        "Shell/console history suppression detected (anti-forensics)",
                        "History is unset/nulled or redirected. The campaign disables "
                        "history to hide its tracks.",
                        evidence=histfile_hits))


def check_access_logs(rep: Report, log_dirs: list, host: HostProvider,
                      mitigation_date=None, max_matches=MAX_LOG_MATCHES) -> None:
    # max_matches is how many example entries to list per category; None = all.
    # Matched attack lines are kept VERBATIM (untruncated) -- the full request,
    # status, and user-agent are exactly what makes them worth reading.
    # Apache/nginx CLF and IIS W3C logs are both handled here: iter_clf_lines()
    # transparently converts W3C rows to the combined-log shape, so everything
    # below is format-agnostic.
    unlimited = max_matches is None
    files = []
    for d in log_dirs:
        if not os.path.isdir(d):
            continue
        for pat in host.log_globs():
            files += glob.glob(os.path.join(d, pat))
            files += glob.glob(os.path.join(d, "**", pat), recursive=True)
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
    by_ip = {}                               # per-source-IP behaviour aggregate
    for path in files:
        try:
            line_iter = iter_clf_lines(path)
        except OSError:
            unreadable += 1
            continue
        try:
            for line in line_iter:
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

                ip, status, size = _parse_clf_fields(line)
                agg = by_ip.setdefault(ip, {
                    "exploit": 0, "recon": 0, "controllers": set(),
                    "statuses": {}, "doubled_path_404": 0,
                    "first": tstr, "last": tstr})
                agg["last"] = tstr
                if status:
                    agg["statuses"][status] = agg["statuses"].get(status, 0) + 1
                if ("surveys/redcap/surveys" in line or
                        "surveys/surveys" in line) and status == "404":
                    agg["doubled_path_404"] += 1

                if ex:
                    exploit_total += 1
                    agg["exploit"] += 1
                    m = INTERNAL_CONTROLLER_RE.search(_url_unquote_recursive(line))
                    if m:
                        agg["controllers"].add(m.group(1))
                    # Rank by status: a 2xx means the passthru REACHED the
                    # controller unauthenticated -- reachability, NOT proof that
                    # code executed or that the host was compromised. Anything
                    # else is an attempt that did not reach.
                    if status and status.startswith("2"):
                        rank = (f"reached the controller (HTTP {status}) -- "
                                "endpoint reachable unauthenticated; "
                                "reachability, not proof of code execution or "
                                "compromise")
                    elif status:
                        rank = f"attempt -- did not reach (HTTP {status})"
                    else:
                        rank = "attempt (status not parseable)"
                    if unlimited or len(exploit_ev) < max_matches:
                        exploit_ev.append(
                            f"{path} [{tstr}]: [{'; '.join(ex + rc)}] "
                            f"[{rank}] {line.strip()}")
                else:
                    recon_total += 1
                    agg["recon"] += 1
                    if unlimited or len(recon_ev) < max_matches:
                        recon_ev.append(f"{path} [{tstr}]: [{'; '.join(rc)}] {line.strip()}")
        except Exception:
            unreadable += 1

    # Distinct source IPs that issued exploit-shaped requests (the "other
    # attackers" surfaced by pattern, not by the known IOC IP).
    exploit_ips = sorted(ip for ip, a in by_ip.items()
                         if ip and a["exploit"] > 0)
    other_ips = [ip for ip in exploit_ips if ip != IOC_SOURCE_IP]

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
            "distinct_exploit_ips": exploit_ips,
            "by_ip": {
                ip: {
                    "exploit": a["exploit"],
                    "recon": a["recon"],
                    "controllers": sorted(a["controllers"]),
                    "statuses": a["statuses"],
                    "doubled_path_404": a["doubled_path_404"],
                    "first": a["first"],
                    "last": a["last"],
                }
                for ip, a in by_ip.items() if ip and a["exploit"] > 0
            },
        }

    if not unlimited and exploit_total > max_matches:
        exploit_ev.append(f"... (+{exploit_total - max_matches} more exploit-shaped "
                          "request(s); pass --max-log-matches all to list every one)")
    if not unlimited and recon_total > max_matches:
        recon_ev.append(f"... (+{recon_total - max_matches} more request(s) from the "
                        "attacker IP; pass --max-log-matches all to list every one)")

    if exploit_ev:
        detail = ("Request(s) reaching an internal controller via the "
                  "unauthenticated survey __passthru -- either DataImportController "
                  "(the report's RCE sink) or any controller reached through a "
                  "double-encoded index.php (the campaign's generalizable "
                  "signature), or using the known attacker survey hash. This is an "
                  "exploitation ATTEMPT in the logs -- a 2xx means the passthru "
                  "REACHED the controller unauthenticated (reachability), NOT that "
                  "code executed; the host-state checks above (miner, persistence, "
                  "known-bad file hashes) are what confirm an actual compromise.")
        if len(exploit_ips) > 1 or (exploit_ips and exploit_ips[0] != IOC_SOURCE_IP):
            detail += (f" Distinct source IP(s) issuing exploit-shaped requests: "
                       f"{', '.join(exploit_ips)}.")
        if other_ips:
            detail += (f" NOTE: {len(other_ips)} source IP(s) beyond the documented "
                       f"IOC ({IOC_SOURCE_IP}) issued exploit-shaped requests: "
                       f"{', '.join(other_ips)}.")
        rep.add(Finding(SEV_HIGH, "weblog",
                        "CVE-2026-90817 exploit-attempt signature in access logs",
                        detail, evidence=exploit_ev))
    if recon_ev:
        rep.add(Finding(SEV_MEDIUM, "weblog",
                        f"Traffic from the known attacker source IP ({IOC_SOURCE_IP})",
                        "Request(s) from the documented exploit source IP that were NOT "
                        "exploit-shaped (e.g. GET / or /surveys/ probes) -- most likely "
                        "reconnaissance. Worth noting that the host was targeted, but "
                        "not evidence of exploitation on its own.",
                        evidence=recon_ev))
    if unreadable and not host.is_privileged():
        rep.note(f"{unreadable} log file(s) unreadable without privilege; log check partial.")


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
    host_state = {"staging", "hash", "process", "socket",
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
    out.append(f"platform:    {rep.platform_name or 'unknown'}")
    out.append(f"time:        {datetime.datetime.now().isoformat(timespec='seconds')}")
    out.append(f"redcap root: {args.redcap_root}")
    out.append(f"redcap ver:  {rep.redcap_version or 'unknown'}")
    mit = rep.mitigation_date or "unknown"
    if rep.mitigation_source:
        mit += f"  ({rep.mitigation_source})"
    out.append(f"mitigation:  {mit}")
    out.append(f"privileges:  {'privileged' if rep.privileged else 'UNPRIVILEGED (scan is partial)'}")
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
        by_ip = s.get("by_ip") or {}
        if by_ip and not args.quiet:
            out.append("  source IPs issuing exploit-shaped requests:")
            for ip in s.get("distinct_exploit_ips", []):
                a = by_ip.get(ip)
                if not a:
                    continue
                ctrls = ", ".join(a["controllers"]) or "-"
                sts = ", ".join(f"{k}x{v}" for k, v in sorted(a["statuses"].items()))
                extra = (f", doubled-path 404s={a['doubled_path_404']}"
                         if a["doubled_path_404"] else "")
                flag = "  <-- NOT the documented IOC IP" if ip != IOC_SOURCE_IP else ""
                out.append(f"    {ip}  exploit={a['exploit']}  "
                           f"controllers=[{ctrls}]  status=[{sts}]{extra}{flag}")
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

    # On a provisional provider (Windows), remind the reader the host-state
    # checks are generic/unvalidated, so a clean host-state result is weaker.
    if rep.platform_name == "windows":
        out.append("NOTE (Windows): host-state compromise checks are PROVISIONAL "
                   "generic heuristics,")
        out.append("      not the documented Linux campaign IOCs, and are not yet "
                   "validated on")
        out.append("      real hardware. The version and web-log findings are "
                   "fully supported.")
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
        "platform": rep.platform_name,
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "redcap_root": args.redcap_root,
        "redcap_version": rep.redcap_version,
        "privileges": "privileged" if rep.privileged else "unprivileged",
        "partial_scan": rep.partial or not rep.privileged,
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
    # Clean so far. If the scan was partial (unprivileged/errors), we cannot
    # fully assert "clean" -> exit 2. Otherwise 0.
    if rep.partial or not rep.privileged or any(f.severity == SEV_ERROR for f in rep.findings):
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
                        "Default: platform-specific (Apache/nginx on Linux, "
                        "IIS/Apache on Windows).")
    p.add_argument("--home-dir", action="append", default=None,
                   help="Extra home dir to scan for SSH keys / rc files (repeatable).")
    p.add_argument("--platform", choices=("auto", "linux", "windows"), default="auto",
                   help="Host platform to assume (default: auto-detect). Forcing a "
                        "platform selects that provider; the OS-specific host-state "
                        "probes still only run on the matching live OS.")
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


def run_scan(args, host: HostProvider) -> Report:
    """Run every check against the given provider and return the Report.
    Separated from main() so tests can drive it with an injected provider."""
    log_dirs = args.log_dir or host.default_log_dirs()
    homes = host.home_dirs(args.home_dir)

    rep = Report()
    rep.platform_name = host.name
    rep.privileged = host.is_privileged()
    if not rep.privileged:
        rep.partial = True

    # Resolve the mitigation date: explicit flag wins, else infer from the
    # install mtime of the earliest patched redcap_vX.Y.Z directory.
    mitigation_date = None
    if args.mitigation_date:
        try:
            mitigation_date = datetime.date.fromisoformat(args.mitigation_date)
            rep.mitigation_source = "provided via --mitigation-date"
        except ValueError:
            raise ValueError(f"--mitigation-date must be YYYY-MM-DD (got "
                             f"{args.mitigation_date!r})")
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
            raise ValueError(f"--max-log-matches must be an integer or 'all' (got "
                             f"{args.max_log_matches!r})")

    # Each check is isolated so one failure never aborts the scan.
    checks = [
        ("version", lambda: check_version(rep, args.redcap_root)),
        ("staging", lambda: check_staging(rep, host)),
        ("hash", lambda: check_hashes(rep, args.redcap_root, args.full_hash_scan, host)),
        ("process", lambda: check_processes(rep, host)),
        ("socket", lambda: check_sockets(rep, host)),
        ("cron", lambda: check_cron(rep, host)),
        ("ssh", lambda: check_authorized_keys(rep, host, homes)),
        ("profile", lambda: check_profiles(rep, host, homes)),
        ("weblog", lambda: check_access_logs(rep, log_dirs, host, mitigation_date, max_matches)),
    ]
    for name, fn in checks:
        try:
            fn()
        except Exception as exc:  # defensive: never crash the whole scan
            rep.add(Finding(SEV_ERROR, name, f"check '{name}' raised an error",
                            str(exc)))
            rep.partial = True
    return rep


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    host = select_provider(args.platform)
    try:
        rep = run_scan(args, host)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = render_json(rep, args) if args.json else render_text(rep, args)
    print(out)
    return compute_exit_code(rep)


if __name__ == "__main__":
    sys.exit(main())
