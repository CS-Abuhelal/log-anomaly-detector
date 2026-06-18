"""
parsers.py
----------
Turns raw log files into one common pandas DataFrame so the detectors in
detectors.py never have to care whether the data originally came from a
Windows Event Log export or a Linux auth.log file.

Every parser produces rows with these columns:

    timestamp       - datetime of the event
    source          - "windows" or "linux" (which log this came from)
    event_type      - one of: logon_success, logon_failed, account_created,
                       privilege_change, process_execution
    account         - the account that performed the action (logging in,
                       running sudo, etc.)
    source_ip       - the IP address involved, if any
    target_account  - the account being affected (e.g. the new user that
                       was created, or the user added to an admin group)
    process_name    - the program/command that was run, if applicable
    details         - free-text evidence (the original log message/command)

----------------------------------------------------------------------
Windows input format
----------------------------------------------------------------------
This tool expects Windows Security Event Log data exported as CSV with
these columns (this is the kind of file you get from
`Get-WinEvent -LogName Security | Export-Csv` after trimming it down to
the fields below, or from Event Viewer's "Save Filtered Log File As..."
with a bit of cleanup):

    TimeCreated,EventID,Account,SourceIP,TargetAccount,ProcessName,CommandLine,Message

Event IDs this tool understands:
    4624 - An account successfully logged on               -> logon_success
    4625 - An account failed to log on                     -> logon_failed
    4720 - A user account was created                      -> account_created
    4732 - A member was added to a security-enabled group  -> privilege_change
    4688 - A new process has been created                  -> process_execution

----------------------------------------------------------------------
Linux input format
----------------------------------------------------------------------
Standard syslog-style /var/log/auth.log lines, e.g.:

    Jun 18 03:14:12 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
    Jun 18 03:14:15 host sshd[1234]: Accepted password for ahmed from 192.168.1.50 port 51240 ssh2
    Jun 18 09:00:01 host useradd[2345]: new user: name=backdoor, UID=1001
    Jun 18 09:00:05 host usermod[2345]: add 'backdoor' to group 'sudo'
    Jun 18 09:05:00 host sudo:    ahmed : TTY=pts/0 ; PWD=/home/ahmed ; USER=root ; COMMAND=/usr/bin/whoami
"""

import re
import os
from datetime import datetime

import pandas as pd

COLUMNS = [
    "timestamp", "source", "event_type",
    "account", "source_ip", "target_account",
    "process_name", "details",
]

WINDOWS_EVENT_MAP = {
    4624: "logon_success",
    4625: "logon_failed",
    4720: "account_created",
    4732: "privilege_change",
    4688: "process_execution",
}


def parse_windows_csv(path) -> pd.DataFrame:
    """Read a Windows Security Event CSV export (see module docstring for
    the expected columns) and normalize it into the common schema."""
    raw = pd.read_csv(path)
    rows = []

    for _, row in raw.iterrows():
        event_id = int(row.get("EventID", 0))
        event_type = WINDOWS_EVENT_MAP.get(event_id)
        if event_type is None:
            continue  # not an event ID this tool knows how to interpret

        timestamp = pd.to_datetime(row.get("TimeCreated"))
        message = str(row.get("Message", "")) if not pd.isna(row.get("Message", "")) else ""
        command_line = row.get("CommandLine")
        details = message
        if event_type == "process_execution" and isinstance(command_line, str) and command_line:
            details = command_line

        rows.append({
            "timestamp": timestamp,
            "source": "windows",
            "event_type": event_type,
            "account": _clean(row.get("Account")),
            "source_ip": _clean(row.get("SourceIP")),
            "target_account": _clean(row.get("TargetAccount")),
            "process_name": _clean(row.get("ProcessName")),
            "details": details,
        })

    return pd.DataFrame(rows, columns=COLUMNS)


def _clean(value):
    """pandas turns empty CSV cells into NaN (a float); normalize those to None."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    return str(value)


# ---------------------------------------------------------------------------
# Linux auth.log parsing
# ---------------------------------------------------------------------------
# Each pattern is checked in order against the part of the line that comes
# after "host process[pid]: ". The first one that matches wins.

_RE_FAILED_PASSWORD = re.compile(
    r"Failed password for (invalid user )?(?P<account>\S+) from (?P<ip>\S+) port \d+"
)
_RE_ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<account>\S+) from (?P<ip>\S+) port \d+"
)
_RE_NEW_USER = re.compile(
    r"new user: name=(?P<account>[^,]+)"
)
_RE_GROUP_ADD = re.compile(
    r"add '(?P<account>[^']+)' to group '(?P<group>[^']+)'"
)
_RE_SUDO_COMMAND = re.compile(
    r"^\s*(?P<account>\S+)\s*:.*COMMAND=(?P<command>.+)$"
)

# "Jun 18 03:14:12 host sshd[1234]: <message>"
_RE_SYSLOG_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(\[\d+\])?:\s*(?P<message>.*)$"
)


def parse_linux_auth_log(path, year=None) -> pd.DataFrame:
    """Read a Linux auth.log file and normalize it into the common schema.

    year: syslog timestamps don't include a year, so we assume the
    current year unless one is given explicitly.
    """
    year = year or datetime.now().year
    rows = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue

            match = _RE_SYSLOG_LINE.match(line)
            if not match:
                continue

            timestamp_str = f"{match.group('month')} {match.group('day')} {year} {match.group('time')}"
            try:
                timestamp = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
            except ValueError:
                continue

            message = match.group("message")
            process = match.group("process")

            row = _parse_linux_message(process, message)
            if row is None:
                continue
            row["timestamp"] = timestamp
            row["source"] = "linux"
            rows.append(row)

    return pd.DataFrame(rows, columns=COLUMNS)


def _parse_linux_message(process, message):
    failed = _RE_FAILED_PASSWORD.search(message)
    if failed:
        return {
            "event_type": "logon_failed",
            "account": failed.group("account"),
            "source_ip": failed.group("ip"),
            "target_account": None,
            "process_name": None,
            "details": message,
        }

    accepted = _RE_ACCEPTED_PASSWORD.search(message)
    if accepted:
        return {
            "event_type": "logon_success",
            "account": accepted.group("account"),
            "source_ip": accepted.group("ip"),
            "target_account": None,
            "process_name": None,
            "details": message,
        }

    if process == "useradd":
        new_user = _RE_NEW_USER.search(message)
        if new_user:
            return {
                "event_type": "account_created",
                "account": None,
                "source_ip": None,
                "target_account": new_user.group("account").strip(),
                "process_name": None,
                "details": message,
            }

    if process == "usermod":
        group_add = _RE_GROUP_ADD.search(message)
        if group_add:
            return {
                "event_type": "privilege_change",
                "account": None,
                "source_ip": None,
                "target_account": group_add.group("account"),
                "process_name": None,
                "details": f"added to group '{group_add.group('group')}'",
            }

    if process == "sudo":
        sudo_cmd = _RE_SUDO_COMMAND.search(message)
        if sudo_cmd:
            command = sudo_cmd.group("command").strip()
            process_name = command.split()[0] if command else None
            return {
                "event_type": "process_execution",
                "account": sudo_cmd.group("account"),
                "source_ip": None,
                "target_account": None,
                "process_name": process_name,
                "details": command,
            }

    return None


# ---------------------------------------------------------------------------
def load_logs(paths) -> pd.DataFrame:
    """Load one or more log files (mixing Windows CSVs and Linux auth.log
    files is fine) and return a single combined, time-sorted DataFrame."""
    frames = []
    for path in paths:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            frames.append(parse_windows_csv(path))
        else:
            frames.append(parse_linux_auth_log(path))

    if not frames:
        return pd.DataFrame(columns=COLUMNS)

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.sort_values("timestamp").reset_index(drop=True)
    return combined
