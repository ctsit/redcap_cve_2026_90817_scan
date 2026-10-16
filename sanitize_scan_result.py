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
"""Sanitize a redcap_cve_2026_90817_scan.py result for sharing.

Two substitutions, nothing else is altered:

  1. Hostname  -- every occurrence of the scanned host's name (auto-detected
     from the report's `host:` header, or given with --hostname) is replaced
     with redcap.example.org (override with --replacement).

  2. Survey hashes -- every survey access token in a URL (`?s=<hash>` or
     `&s=<hash>`) is replaced with a freshly generated token of the SAME length
     and SAME character shape (an uppercase letter stays an uppercase letter, a
     lowercase letter a lowercase letter, a digit a digit). The mapping is
     CONSISTENT across the whole file: one input hash always maps to the same
     output hash, so you can still follow repeated attacks against the same
     survey -- you just can no longer recover the real token.

Attacker IP addresses, timestamps, controller names, file paths and everything
else are left untouched: those are indicators worth sharing, not secrets. The
`s=` match is anchored to the URL query parameter, so a documented public IOC
hash mentioned in prose (e.g. "attacker survey hash s=...") is not disturbed.

The tool reads the input read-only and never overwrites it in place; output goes
to stdout (or -o FILE). Stdlib only, Python 3.7+.

Usage:
    python3 -I sanitize_scan_result.py scan_result.txt -o sanitized_scan_result.txt
    python3 -I sanitize_scan_result.py < scan_result.txt > sanitized.txt
    python3 -I sanitize_scan_result.py scan4.txt --map-out mapping.txt
"""

import argparse
import random
import re
import string
import sys

DEFAULT_REPLACEMENT_HOST = "redcap.example.org"

# The scanner prints `host:        <name>` in its report header.
_HOST_HEADER_RE = re.compile(r"^host:\s+(\S+)\s*$", re.MULTILINE)
# A survey token as a URL query parameter: the `?s=` / `&s=` anchor keeps us
# from touching the same letters elsewhere (prose, paths, user-agents).
_SURVEY_HASH_RE = re.compile(r"(?<=[?&]s=)([A-Za-z0-9]+)")


def same_shape_token(original: str, rng: random.Random) -> str:
    """Return a token of identical length whose every character is a random
    character of the same class (digit/upper/lower) as the original's."""
    out = []
    for ch in original:
        if ch.isdigit():
            out.append(rng.choice(string.digits))
        elif ch.isupper():
            out.append(rng.choice(string.ascii_uppercase))
        elif ch.islower():
            out.append(rng.choice(string.ascii_lowercase))
        else:                       # should not occur for [A-Za-z0-9]+
            out.append(ch)
    return "".join(out)


def build_hash_mapping(text: str, rng: random.Random) -> dict:
    """Map each distinct survey hash in `text` to a fresh same-shape token,
    guaranteeing the replacement is unique and differs from every original."""
    originals = sorted(set(_SURVEY_HASH_RE.findall(text)))
    mapping = {}
    used = set(originals)           # never reuse an original as a replacement
    for original in originals:
        for _ in range(1000):
            candidate = same_shape_token(original, rng)
            if candidate not in used:
                break
        mapping[original] = candidate
        used.add(candidate)
    return mapping


def detect_hostname(text: str):
    m = _HOST_HEADER_RE.search(text)
    return m.group(1) if m else None


def sanitize(text: str, hostnames, replacement_host: str, rng: random.Random):
    """Return (sanitized_text, hash_mapping, hostnames_replaced)."""
    hash_mapping = build_hash_mapping(text, rng)
    if hash_mapping:
        text = _SURVEY_HASH_RE.sub(lambda m: hash_mapping[m.group(1)], text)

    replaced_hosts = []
    for host in hostnames:
        if host and host != replacement_host and host in text:
            text = text.replace(host, replacement_host)
            replaced_hosts.append(host)
    return text, hash_mapping, replaced_hosts


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Sanitize a CVE-2026-90817 scan result (hostname + survey "
                    "hashes) for sharing.")
    p.add_argument("input", nargs="?", default="-",
                   help="Scan-result file to read (default: stdin).")
    p.add_argument("-o", "--output", default="-",
                   help="Where to write the sanitized result (default: stdout).")
    p.add_argument("--hostname", action="append", metavar="NAME",
                   help="Hostname to replace. Repeatable. If omitted, it is "
                        "auto-detected from the report's 'host:' header.")
    p.add_argument("--replacement", default=DEFAULT_REPLACEMENT_HOST,
                   metavar="NAME",
                   help=f"Replacement hostname (default: {DEFAULT_REPLACEMENT_HOST}).")
    p.add_argument("--seed", type=int, default=None,
                   help="Seed the RNG for reproducible output (default: random).")
    p.add_argument("--map-out", metavar="FILE",
                   help="Also write the hostname/hash substitution map to FILE "
                        "(keep this private; it reverses the sanitization).")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        if args.input == "-":
            text = sys.stdin.read()
        else:
            with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError as e:
        print(f"error: cannot read input: {e}", file=sys.stderr)
        return 2

    hostnames = list(args.hostname) if args.hostname else []
    if not hostnames:
        detected = detect_hostname(text)
        if detected:
            hostnames = [detected]
        else:
            print("warning: no 'host:' header found and no --hostname given; "
                  "hostname will NOT be replaced.", file=sys.stderr)

    rng = random.Random(args.seed)
    sanitized, hash_mapping, replaced_hosts = sanitize(
        text, hostnames, args.replacement, rng)

    try:
        if args.output == "-":
            sys.stdout.write(sanitized)
        else:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(sanitized)
    except OSError as e:
        print(f"error: cannot write output: {e}", file=sys.stderr)
        return 2

    if args.map_out:
        try:
            with open(args.map_out, "w", encoding="utf-8") as fh:
                for host in replaced_hosts:
                    fh.write(f"host\t{host}\t{args.replacement}\n")
                for original, new in sorted(hash_mapping.items()):
                    fh.write(f"hash\t{original}\t{new}\n")
        except OSError as e:
            print(f"error: cannot write map: {e}", file=sys.stderr)
            return 2

    print(f"sanitized: {len(replaced_hosts)} hostname(s), "
          f"{len(hash_mapping)} distinct survey hash(es) replaced.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
