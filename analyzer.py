#!/usr/bin/env python3
"""
analyzer.py
-----------
Command-line entry point for the Log Anomaly Detector.

Usage:
    python analyzer.py sample_logs/windows_bruteforce.csv
    python analyzer.py sample_logs/linux_auth_bruteforce.log
    python analyzer.py sample_logs/*.csv sample_logs/*.log --output report.txt

You can pass any mix of Windows Security Event CSV exports (.csv) and
Linux auth.log files (anything else) - they all get parsed into one
combined timeline and analyzed together.

What it does, step by step:
    1. Parse each log file into a common table of events (see
       loganomaly/parsers.py for the exact schema).
    2. Run each detector function from loganomaly/detectors.py against
       that table. Every detector returns a list of "Finding" objects,
       each with a 0-100 risk score.
    3. Combine all the findings and build a human-readable report,
       sorted from highest to lowest risk.
    4. Print the report to the screen (and optionally save it to a file).
"""

import argparse
import os
import sys

from loganomaly.parsers import load_logs
from loganomaly import detectors
from loganomaly.report import build_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze Windows Security Event / Linux auth.log files for suspicious activity.",
    )
    parser.add_argument(
        "log_files",
        nargs="+",
        help="One or more log files to analyze (.csv = Windows Security Event export, anything else = Linux auth.log)",
    )
    parser.add_argument(
        "--output",
        help="Optional path to also save the report as a text file",
    )

    # Detection thresholds - tweakable since "normal" looks different on
    # every network.
    parser.add_argument("--window-minutes", type=int, default=5,
                         help="Sliding window size (minutes) for brute-force burst detection (default: 5)")
    parser.add_argument("--count-threshold", type=int, default=5,
                         help="Failed logins inside the window that counts as a brute-force burst (default: 5)")
    parser.add_argument("--hour-z-threshold", type=float, default=-1.5,
                         help="Z-score below which a login hour is considered statistically rare (default: -1.5)")

    return parser.parse_args()


def main():
    args = parse_args()

    for path in args.log_files:
        if not os.path.isfile(path):
            print(f"Error: file not found: {path}", file=sys.stderr)
            sys.exit(1)

    print(f"Reading {len(args.log_files)} log file(s)...")
    events = load_logs(args.log_files)
    print(f"Parsed {len(events)} recognized events. Running detectors...")

    findings = []
    findings += detectors.detect_brute_force(
        events, window_minutes=args.window_minutes, count_threshold=args.count_threshold,
    )
    findings += detectors.detect_unusual_hours(events, z_threshold=args.hour_z_threshold)
    findings += detectors.detect_new_accounts(events)
    findings += detectors.detect_privilege_escalation(events)
    findings += detectors.detect_unusual_processes(events)

    report_text = build_report(args.log_files, len(events), findings)
    print()
    print(report_text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
