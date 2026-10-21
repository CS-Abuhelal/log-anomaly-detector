"""
test_detectors.py
------------------
Basic sanity tests for the detectors, run against the sample log files.

These aren't exhaustive - they're here to prove each detector fires on
the pattern it's meant to catch, and stays quiet on normal logs. Run
with:

    python -m pytest tests/
or simply:
    python tests/test_detectors.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from loganomaly.parsers import load_logs, COLUMNS
from loganomaly import detectors
from loganomaly.report import Finding, build_report, sanitize_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "sample_logs")


def categories(findings):
    return {f.category for f in findings}


def run_all_detectors(df):
    findings = []
    findings += detectors.detect_brute_force(df)
    findings += detectors.detect_unusual_hours(df)
    findings += detectors.detect_new_accounts(df)
    findings += detectors.detect_privilege_escalation(df)
    findings += detectors.detect_unusual_processes(df)
    return findings


class TestDetectors(unittest.TestCase):

    def test_normal_windows_log_has_no_findings(self):
        df = load_logs([os.path.join(SAMPLES, "windows_normal.csv")])
        self.assertEqual(run_all_detectors(df), [])

    def test_normal_linux_log_has_no_findings(self):
        df = load_logs([os.path.join(SAMPLES, "linux_auth_normal.log")])
        self.assertEqual(run_all_detectors(df), [])

    def test_brute_force_detected_windows(self):
        df = load_logs([os.path.join(SAMPLES, "windows_bruteforce.csv")])
        findings = detectors.detect_brute_force(df)
        self.assertEqual(len(findings), 1)
        self.assertGreaterEqual(findings[0].risk_score, 70)

    def test_brute_force_detected_linux(self):
        df = load_logs([os.path.join(SAMPLES, "linux_auth_bruteforce.log")])
        findings = detectors.detect_brute_force(df)
        self.assertEqual(len(findings), 1)
        self.assertGreaterEqual(findings[0].risk_score, 70)

    def test_unusual_hours_detected(self):
        df = load_logs([os.path.join(SAMPLES, "windows_unusual_hours.csv")])
        findings = detectors.detect_unusual_hours(df)
        self.assertEqual(len(findings), 2)
        accounts = {f.details["account"] for f in findings}
        self.assertEqual(accounts, {"jsmith", "ktaylor"})

    def test_new_account_detected(self):
        df = load_logs([os.path.join(SAMPLES, "windows_new_account.csv")])
        findings = detectors.detect_new_accounts(df)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].details["off_hours"])

    def test_privilege_escalation_detected(self):
        df = load_logs([os.path.join(SAMPLES, "windows_privilege_escalation.csv")])
        findings = detectors.detect_privilege_escalation(df)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_suspicious_process_detected(self):
        df = load_logs([os.path.join(SAMPLES, "windows_suspicious_process.csv")])
        findings = detectors.detect_unusual_processes(df)
        # notepad.exe should NOT be flagged - common and run multiple times.
        process_names = {f.details["process_name"] for f in findings}
        self.assertNotIn("notepad.exe", process_names)
        self.assertIn("powershell.exe", process_names)
        self.assertIn("backup_tool42.exe", process_names)

    def test_mixed_files_trigger_all_categories(self):
        df = load_logs([
            os.path.join(SAMPLES, "mixed_windows.csv"),
            os.path.join(SAMPLES, "mixed_linux.log"),
        ])
        findings = run_all_detectors(df)
        cats = categories(findings)
        self.assertIn("Brute Force", cats)
        self.assertIn("Unusual Login Hour", cats)
        self.assertIn("New Account Created", cats)
        self.assertIn("Privilege Escalation", cats)
        self.assertIn("Suspicious Process Execution", cats)


class TestUnknownAccountEvents(unittest.TestCase):
    """Regression tests: pandas groupby drops NaN group keys by default,
    which used to make events with an unparseable account silently vanish
    from the detectors - even a mimikatz execution."""

    def test_watchlist_hit_with_unknown_account_is_still_flagged(self):
        df = pd.DataFrame([{
            "timestamp": pd.Timestamp("2026-06-01 09:00:00"),
            "source": "windows",
            "event_type": "process_execution",
            "account": None,
            "source_ip": None,
            "target_account": None,
            "process_name": "mimikatz.exe",
            "details": "mimikatz.exe sekurlsa::logonpasswords",
        }], columns=COLUMNS)

        findings = detectors.detect_unusual_processes(df)
        self.assertEqual(len(findings), 1)
        self.assertIn("mimikatz", findings[0].message)
        self.assertIn("unknown account", findings[0].message)

    def test_rare_hour_login_with_unknown_account_is_still_flagged(self):
        # 9 daytime logins to build a baseline, plus one 03:00 login whose
        # account failed to parse - that one must still be reported.
        rows = [{
            "timestamp": pd.Timestamp(f"2026-06-01 {9 + (i % 3)}:00:00"),
            "source": "linux", "event_type": "logon_success",
            "account": "ahmed", "source_ip": "192.168.1.50",
            "target_account": None, "process_name": None, "details": "",
        } for i in range(9)]
        rows.append({
            "timestamp": pd.Timestamp("2026-06-02 03:00:00"),
            "source": "linux", "event_type": "logon_success",
            "account": None, "source_ip": "203.0.113.66",
            "target_account": None, "process_name": None, "details": "",
        })
        df = pd.DataFrame(rows, columns=COLUMNS)

        findings = detectors.detect_unusual_hours(df)
        self.assertTrue(
            any(f.details["hour_of_day"] == 3 for f in findings),
            "the 3am login must be flagged even though its account is unknown",
        )


class TestReportSafety(unittest.TestCase):

    def test_sanitize_strips_terminal_escapes(self):
        self.assertEqual(sanitize_text("\x1b[2J\x1b[31mroot\x1b[0m"), "root")
        self.assertEqual(sanitize_text("line1\r\nline2"), "line1 line2")

    def test_log_content_cannot_forge_report_lines(self):
        # Windows CSV Message fields may legally contain embedded newlines,
        # so a logged command line could try to fake its own report entry.
        evil = Finding(
            risk_score=90,
            category="Suspicious Process Execution",
            message="'evil.exe' run by attacker\x1b[2J matches a known attack pattern.",
            details={
                "example_command":
                    "evil.exe\r\n  [Risk   1/100 - INFO] Forged: nothing suspicious here",
            },
        )
        report = build_report(["fake.log"], 1, [evil])
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\n  [Risk   1/100", report)


if __name__ == "__main__":
    unittest.main()
