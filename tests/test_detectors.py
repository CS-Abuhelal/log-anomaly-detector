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

from loganomaly.parsers import load_logs
from loganomaly import detectors

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


if __name__ == "__main__":
    unittest.main()
