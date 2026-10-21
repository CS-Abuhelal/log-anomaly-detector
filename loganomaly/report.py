"""
report.py
---------
Defines the `Finding` data structure (one suspicious thing we noticed)
and helper functions to turn a list of Findings into a readable,
risk-ranked text report.

Every Finding carries a numeric `risk_score` from 0-100 instead of a
hand-picked severity label. The severity label (CRITICAL/HIGH/MEDIUM/
LOW/INFO) shown in the report is *derived* from that score, so a
detector never has to remember to keep a label and a score in sync -
it just has to produce one honest number.
"""

import re
from dataclasses import dataclass, field
from collections import Counter
from datetime import datetime

# Finding messages and details quote raw log content (command lines,
# account names, Windows event descriptions) - all of it ultimately
# attacker-writable. Windows CSV Message fields can even contain quoted
# embedded newlines. Before any of it reaches the report, strip ANSI
# escape sequences and control characters (so a crafted log entry can't
# rewrite what the analyst's terminal shows) and collapse newlines (so
# one value can't forge extra report lines).
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_text(value) -> str:
    """Make a possibly attacker-controlled value safe to print."""
    text = _ANSI_CSI.sub("", str(value))
    return _CONTROL_CHARS.sub(" ", text).strip()

# Score -> label thresholds. A score of 92 is CRITICAL, a score of 55 is
# MEDIUM, and so on. Tweak these in one place if you want the report to
# be more or less alarmist.
SEVERITY_THRESHOLDS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (15, "LOW"),
    (0, "INFO"),
]


def score_to_severity(score: int) -> str:
    """Turn a 0-100 risk score into a human severity label."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


@dataclass
class Finding:
    """
    One suspicious observation made while analyzing the logs.

    risk_score:  0-100, how worrying this finding is. Higher = worse.
    category:    short label for the *type* of detection, e.g. "Brute Force"
    message:     one-line, human-readable description of what was found
    details:     optional dict of extra evidence (account, IP, counts, etc.)
    """
    risk_score: int
    category: str
    message: str
    details: dict = field(default_factory=dict)

    @property
    def severity(self) -> str:
        return score_to_severity(self.risk_score)


def sort_findings(findings):
    """Sort findings highest risk first."""
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)


def _format_details(details: dict) -> str:
    if not details:
        return ""
    lines = [f"      - {key}: {sanitize_text(value)}" for key, value in details.items()]
    return "\n".join(lines)


def build_report(log_files, event_count, findings, generated_at=None) -> str:
    """
    Build the full text report as a single string.

    log_files:   list of file paths that were analyzed
    event_count: total number of normalized log events parsed
    findings:    list of Finding objects produced by the detectors
    """
    generated_at = generated_at or datetime.now()
    findings = sort_findings(findings)
    severity_counts = Counter(f.severity for f in findings)

    lines = []
    lines.append("=" * 70)
    lines.append("  LOG ANOMALY DETECTOR - SUMMARY REPORT")
    lines.append("=" * 70)
    lines.append(f"  Files analyzed  : {', '.join(str(p) for p in log_files)}")
    lines.append(f"  Generated at    : {generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Events parsed   : {event_count}")
    lines.append(f"  Total findings  : {len(findings)}")
    lines.append("")
    lines.append("  Findings by severity:")
    for _, sev in SEVERITY_THRESHOLDS:
        if severity_counts.get(sev):
            lines.append(f"      {sev:<9}: {severity_counts[sev]}")
    lines.append("=" * 70)
    lines.append("")

    if not findings:
        lines.append("No suspicious activity detected. Logs look normal.")
        lines.append("")
        return "\n".join(lines)

    current_severity = None
    for finding in findings:
        if finding.severity != current_severity:
            current_severity = finding.severity
            lines.append(f"--- {current_severity} " + "-" * (66 - len(current_severity)))
        lines.append(f"  [Risk {finding.risk_score:>3}/100 - {finding.severity}] "
                      f"{finding.category}: {sanitize_text(finding.message)}")
        detail_text = _format_details(finding.details)
        if detail_text:
            lines.append(detail_text)
        lines.append("")

    return "\n".join(lines)
