"""
detectors.py
------------
The "detective work" lives here. Each function takes the unified events
DataFrame produced by parsers.py (plus some configurable thresholds) and
returns a list of Finding objects.

All statistics use only pandas and numpy - no scikit-learn, no heavy ML.
The two statistical ideas used throughout this file are:

  1. Sliding-window counting: "how many of X happened in the last N
     minutes?" - used for brute-force burst detection.
  2. Z-scores: "how many standard deviations away from the average is
     this value?" - used to decide whether a login hour, or a process
     name's rarity, is unusual enough to flag.
     z = (value - mean) / standard_deviation
     A z-score of -2 means "two standard deviations below average" -
     i.e. unusually low/rare.

Every detector returns a risk_score from 0-100 instead of picking a
severity label directly - report.py turns that score into a label.
"""

import re
from collections import defaultdict

import numpy as np
import pandas as pd

from .report import Finding


def _clamp(value, low=0, high=100):
    return max(low, min(high, int(round(value))))


# ---------------------------------------------------------------------------
# Shared helper: how rare is each hour-of-day in a set of events?
# ---------------------------------------------------------------------------

def _hourly_rarity(df, event_type):
    """
    Build a 24-bin histogram of which hour of the day a given event type
    happens in, then compute the average and standard deviation across
    the hours that actually have activity.

    We deliberately exclude hours with zero events from the mean/std
    calculation. Most networks have a dozen+ hours overnight with no
    logins at all - if we included those always-empty bins, they'd drag
    the average down so far that any hour with even one login would look
    like a spike *above* average instead of a rare event. Comparing only
    against the hours people are actually active in (e.g. 8am-6pm) is
    what lets a single 3am login show up as a clear negative outlier.

    Returns (counts_per_hour, mean, std) or None if there isn't enough
    data to say anything statistically meaningful.
    """
    subset = df[df["event_type"] == event_type].dropna(subset=["timestamp"])
    if len(subset) < 5:
        return None

    hours = subset["timestamp"].dt.hour
    counts = hours.value_counts().reindex(range(24), fill_value=0).sort_index()

    active_hours = counts[counts > 0]
    if len(active_hours) < 3:
        return None  # too few distinct active hours to judge "rare"

    mean = float(np.mean(active_hours.values))
    std = float(np.std(active_hours.values))
    if std == 0:
        return None  # every active hour looks identical - nothing to compare against

    return counts, mean, std


# ---------------------------------------------------------------------------
# 1. FAILED LOGIN BURSTS (BRUTE FORCE)
# ---------------------------------------------------------------------------
# For each source IP, we look at every failed login and ask: "how many
# failed logins happened in the N minutes before this one?" using a
# sliding window. If that count ever crosses the threshold, it's flagged
# as a likely brute-force burst.
# ---------------------------------------------------------------------------

def detect_brute_force(df, window_minutes=5, count_threshold=5):
    findings = []
    failed = df[(df["event_type"] == "logon_failed") & df["source_ip"].notna()]
    if failed.empty:
        return findings

    window = np.timedelta64(window_minutes, "m")

    for source_ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].values

        # For every failed login, find the earliest other failed login
        # from the same IP that's still inside the trailing time window.
        # np.searchsorted does this in one vectorized pass instead of a
        # slow Python loop.
        left_idx = np.searchsorted(times, times - window, side="left")
        counts_in_window = np.arange(len(times)) - left_idx + 1

        peak_count = int(counts_in_window.max())
        if peak_count < count_threshold:
            continue

        peak_end = int(counts_in_window.argmax())
        peak_start = int(left_idx[peak_end])
        window_events = group.iloc[peak_start:peak_end + 1]
        distinct_accounts = window_events["account"].dropna().unique()

        # Score: starts at 40 once we cross the threshold, then climbs
        # with how far over the threshold we are, plus a bonus if the
        # attacker tried many different account names (password spraying
        # rather than guessing one account's password).
        score = 40 + (peak_count - count_threshold) * 8
        if len(distinct_accounts) >= 3:
            score += 15

        findings.append(Finding(
            risk_score=_clamp(score),
            category="Brute Force",
            message=f"{source_ip} made {peak_count} failed login attempts within "
                    f"{window_minutes} minutes (targeting {len(distinct_accounts)} "
                    f"distinct account(s)).",
            details={
                "source_ip": source_ip,
                "failed_attempts_in_window": peak_count,
                "window_minutes": window_minutes,
                "accounts_targeted": sorted(str(a) for a in distinct_accounts)[:10],
                "window_start": str(pd.Timestamp(window_events["timestamp"].iloc[0])),
                "window_end": str(pd.Timestamp(window_events["timestamp"].iloc[-1])),
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 2. LOGINS AT UNUSUAL HOURS
# ---------------------------------------------------------------------------
# We build a histogram of which hour of the day successful logins
# normally happen in, then flag individual logins that happened in an
# hour that's statistically rare compared to the rest of the day.
# ---------------------------------------------------------------------------

def detect_unusual_hours(df, z_threshold=-1.5):
    findings = []
    stats = _hourly_rarity(df, "logon_success")
    if stats is None:
        return findings
    counts, mean, std = stats

    successes = df[(df["event_type"] == "logon_success") & df["timestamp"].notna()].copy()
    successes["hour"] = successes["timestamp"].dt.hour
    successes["z"] = successes["hour"].apply(lambda h: (counts[h] - mean) / std)

    rare_logins = successes[successes["z"] <= z_threshold]
    if rare_logins.empty:
        return findings

    # Group by (account, hour) so one account logging in at 3am five
    # times produces one finding, not five.
    for (account, hour), group in rare_logins.groupby(["account", "hour"]):
        z = float(group["z"].iloc[0])
        score = 40 + abs(z) * 15
        findings.append(Finding(
            risk_score=_clamp(score),
            category="Unusual Login Hour",
            message=f"{account or 'Unknown account'} logged in at {hour:02d}:00, "
                    f"an hour when logins are statistically rare on this network "
                    f"(z-score {z:.2f}).",
            details={
                "account": account,
                "hour_of_day": int(hour),
                "occurrences": int(len(group)),
                "z_score": round(z, 2),
                "typical_logins_in_this_hour": int(counts[hour]),
                "average_logins_per_hour": round(mean, 1),
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 3. NEW USER ACCOUNT CREATION
# ---------------------------------------------------------------------------

def detect_new_accounts(df):
    findings = []
    created = df[df["event_type"] == "account_created"]
    if created.empty:
        return findings

    stats = _hourly_rarity(df, "logon_success")

    for _, row in created.iterrows():
        score = 50  # any new account is worth a SOC analyst's attention
        off_hours = False

        if pd.notna(row["timestamp"]):
            hour = row["timestamp"].hour
            if stats is not None:
                counts, mean, std = stats
                z = (counts[hour] - mean) / std
                if z <= -1.0:
                    off_hours = True
            elif hour < 6 or hour >= 22:
                off_hours = True  # fallback heuristic when we have no baseline

        if off_hours:
            score += 20

        findings.append(Finding(
            risk_score=_clamp(score),
            category="New Account Created",
            message=f"New account '{row['target_account'] or 'unknown'}' was created"
                     + (f" by {row['account']}" if pd.notna(row["account"]) else "")
                     + (" during an unusual hour." if off_hours else "."),
            details={
                "new_account": row["target_account"],
                "created_by": row["account"],
                "timestamp": str(row["timestamp"]),
                "off_hours": off_hours,
                "evidence": row["details"],
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 4. PRIVILEGE ESCALATION
# ---------------------------------------------------------------------------
# Flags accounts being added to privileged groups (Administrators, sudo,
# wheel, Domain Admins, etc). Membership in a high-value group scores
# higher than a generic group change.
# ---------------------------------------------------------------------------

_HIGH_VALUE_GROUPS = re.compile(
    r"administrators|domain admins|enterprise admins|sudo|wheel|root",
    re.IGNORECASE,
)


def detect_privilege_escalation(df):
    findings = []
    changes = df[df["event_type"] == "privilege_change"]

    for _, row in changes.iterrows():
        evidence = row["details"] or ""
        is_high_value = bool(_HIGH_VALUE_GROUPS.search(evidence))
        score = 90 if is_high_value else 72

        findings.append(Finding(
            risk_score=_clamp(score),
            category="Privilege Escalation",
            message=f"Account '{row['target_account'] or 'unknown'}' was added to "
                     f"a {'highly privileged' if is_high_value else ''} group "
                     f"({evidence}).".replace("  ", " "),
            details={
                "account": row["target_account"],
                "changed_by": row["account"],
                "timestamp": str(row["timestamp"]),
                "high_value_group": is_high_value,
                "evidence": evidence,
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 5. UNUSUAL PROCESS EXECUTION
# ---------------------------------------------------------------------------
# Two signals are combined:
#   - A watchlist of process names/command-line patterns commonly used by
#     attackers (credential dumping tools, "living off the land" binaries
#     used to download or run things, reverse shells, etc).
#   - Statistical rarity: a process that only appears once or twice in
#     the whole log is unusual purely by virtue of being rare, even if
#     it isn't on the watchlist.
# ---------------------------------------------------------------------------

# (pattern, score, reason) - checked in order, first match wins.
PROCESS_WATCHLIST = [
    (re.compile(r"mimikatz", re.I), 97, "Known credential-dumping tool"),
    (re.compile(r"vssadmin.*delete\s+shadows", re.I), 95, "Shadow copy deletion - common ransomware precursor"),
    (re.compile(r"\bnc(\.exe)?\b.*-e\b", re.I), 90, "Netcat used to spawn a reverse shell"),
    (re.compile(r"psexec", re.I), 88, "Remote execution tool often used for lateral movement"),
    (re.compile(r"powershell.*(-enc\b|-e\b|-encodedcommand)", re.I), 85, "Obfuscated/encoded PowerShell command"),
    (re.compile(r"certutil.*-urlcache", re.I), 85, "certutil abused to download files (LOLBin technique)"),
    (re.compile(r"regsvr32.*(/i:|scrobj)", re.I), 85, "regsvr32 'Squiblydoo' technique for running remote scripts"),
    (re.compile(r"wmic.*process\s+call\s+create", re.I), 80, "WMIC used for remote/local process execution"),
    (re.compile(r"bitsadmin.*\/transfer", re.I), 78, "BITS abused to download a payload"),
    (re.compile(r"net\s+(user|localgroup\s+administrators).*\/add", re.I), 70, "Command-line account/admin-group manipulation"),
    (re.compile(r"whoami\s+/priv", re.I), 55, "Privilege enumeration - common reconnaissance step"),
]

RARE_PROCESS_THRESHOLD = 1  # a process seen this many times (or fewer) is "rare"
RARE_PROCESS_SCORE = 35


def _watchlist_match(text):
    for pattern, score, reason in PROCESS_WATCHLIST:
        if pattern.search(text):
            return score, reason
    return None


def detect_unusual_processes(df):
    findings = []
    processes = df[(df["event_type"] == "process_execution") & df["process_name"].notna()]
    if processes.empty:
        return findings

    frequency = processes["process_name"].str.lower().value_counts()

    # Group identical (account, process_name) pairs together so a process
    # that ran many times produces one finding instead of a flood of them.
    for (account, process_name), group in processes.groupby(["account", "process_name"]):
        combined_text = f"{process_name} {' '.join(group['details'].dropna().astype(str))}"
        match = _watchlist_match(combined_text)
        run_count = int(len(group))
        first_seen = group["timestamp"].min()

        if match:
            score, reason = match
            findings.append(Finding(
                risk_score=_clamp(score),
                category="Suspicious Process Execution",
                message=f"'{process_name}' run by {account or 'unknown account'} "
                        f"matches a known attack pattern: {reason}.",
                details={
                    "account": account,
                    "process_name": process_name,
                    "times_seen": run_count,
                    "first_seen": str(first_seen),
                    "matched_pattern_reason": reason,
                    "example_command": group["details"].dropna().iloc[0] if not group["details"].dropna().empty else None,
                },
            ))
            continue

        rarity = int(frequency.get(process_name.lower(), 0))
        if rarity <= RARE_PROCESS_THRESHOLD:
            findings.append(Finding(
                risk_score=_clamp(RARE_PROCESS_SCORE),
                category="Suspicious Process Execution",
                message=f"'{process_name}' run by {account or 'unknown account'} is "
                        f"statistically rare - only seen {rarity} time(s) in this log.",
                details={
                    "account": account,
                    "process_name": process_name,
                    "times_seen_in_log": rarity,
                    "first_seen": str(first_seen),
                },
            ))

    return findings
