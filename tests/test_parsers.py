"""
test_parsers.py
----------------
Tests for the Windows Event Viewer "Save All Events As..." CSV format -
the GUI export, which has a well-known header/data column mismatch (see
parsers.py docstring). These use a small synthetic fixture built in-memory
so no real machine's log data needs to be committed to the repo.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loganomaly.parsers import load_logs, _looks_like_eventviewer_export

# A minimal Event Viewer GUI export: 5 header names, 6 fields per data row
# (the trailing Message field has no column name - the real-world quirk
# this parser exists to handle). One row deliberately has an *empty*
# "New Process Name" field, which used to make a greedy \s* regex bleed
# into the next line - the regression this fixture guards against.
FIXTURE_CSV = (
    "Keywords,Date and Time,Source,Event ID,Task Category\n"
    'Audit Success,6/1/2026 9:00:00 AM,Microsoft-Windows-Security-Auditing,4624,Logon,'
    '"An account was successfully logged on.\r\n\r\n'
    'Subject:\r\n\tSecurity ID:\t\tSYSTEM\r\n\tAccount Name:\t\tHOST$\r\n\r\n'
    'New Logon:\r\n\tSecurity ID:\t\tS-1-5-21\r\n\tAccount Name:\t\ttestuser\r\n\r\n'
    'Network Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t10.0.0.5\r\n"\n'
    'Audit Failure,6/1/2026 9:05:00 AM,Microsoft-Windows-Security-Auditing,4625,Logon,'
    '"An account failed to log on.\r\n\r\n'
    'Account For Which Logon Failed:\r\n\tSecurity ID:\t\tNULL SID\r\n\tAccount Name:\t\tbadguess\r\n\r\n'
    'Network Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t203.0.113.9\r\n"\n'
    'Audit Success,6/1/2026 9:10:00 AM,Microsoft-Windows-Security-Auditing,4688,Process Creation,'
    '"A new process has been created.\r\n\r\n'
    'Creator Subject:\r\n\tSecurity ID:\t\tSYSTEM\r\n\tAccount Name:\t\t-\r\n\r\n'
    'Process Information:\r\n\tNew Process ID:\t\t0xbc\r\n\tNew Process Name:\t\r\n'
    '\tToken Elevation Type:\tTokenElevationTypeDefault (1)\r\n\tProcess Command Line:\t\r\n\r\n'
    'Token Elevation Type indicates the type of token that was assigned to the new process.\r\n"\n'
    'Audit Success,6/1/2026 9:15:00 AM,Microsoft-Windows-Security-Auditing,4688,Process Creation,'
    '"A new process has been created.\r\n\r\n'
    'Creator Subject:\r\n\tSecurity ID:\t\tSYSTEM\r\n\tAccount Name:\t\ttestuser\r\n\r\n'
    'Process Information:\r\n\tNew Process ID:\t\t0x1a4\r\n\tNew Process Name:\tC:\\Windows\\System32\\mimikatz.exe\r\n'
    '\tProcess Command Line:\tmimikatz.exe ""sekurlsa::logonpasswords""\r\n"\n'
)


class TestEventViewerParser(unittest.TestCase):

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(FIXTURE_CSV)

    def tearDown(self):
        os.remove(self.path)

    def test_format_is_detected(self):
        self.assertTrue(_looks_like_eventviewer_export(self.path))

    def test_logon_success_fields(self):
        df = load_logs([self.path])
        row = df[df["event_type"] == "logon_success"].iloc[0]
        self.assertEqual(row["account"], "testuser")
        self.assertEqual(row["source_ip"], "10.0.0.5")

    def test_logon_failed_fields(self):
        df = load_logs([self.path])
        row = df[df["event_type"] == "logon_failed"].iloc[0]
        self.assertEqual(row["account"], "badguess")
        self.assertEqual(row["source_ip"], "203.0.113.9")

    def test_empty_field_does_not_bleed_into_next_line(self):
        """Regression test: a blank 'New Process Name:' value must not be
        read as the *next* line's content (e.g. 'Token Elevation Type...')."""
        df = load_logs([self.path])
        processes = df[df["event_type"] == "process_execution"]
        empty_name_row = processes[processes["process_name"].isna()]
        self.assertEqual(len(empty_name_row), 1)

    def test_process_name_and_command_line_extracted(self):
        df = load_logs([self.path])
        processes = df[df["event_type"] == "process_execution"]
        mimikatz_row = processes[processes["process_name"] == "mimikatz.exe"].iloc[0]
        self.assertIn("sekurlsa::logonpasswords", mimikatz_row["details"])
        self.assertEqual(mimikatz_row["account"], "testuser")


if __name__ == "__main__":
    unittest.main()
