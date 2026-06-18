# Log Anomaly Detector

A beginner-friendly Python tool that scans Windows Security Event logs
and Linux `auth.log` files for suspicious patterns, using simple
statistics (just `pandas` and `numpy` - no heavy ML libraries) instead
of a black-box model. Every finding gets a **0-100 risk score** so you
can quickly triage what matters most.

## What it detects

| Detection | What it looks for |
|---|---|
| **Failed login bursts (brute force)** | Many failed logins from one source IP within a short sliding time window - whether hammering one account or "spraying" many |
| **Logins at unusual hours** | Successful logins that happen during hours that are statistically rare for that network, using a z-score against the hours that normally see activity |
| **New user account creation** | Every new account is surfaced, with extra risk added if it was created outside normal hours |
| **Privilege escalation** | Accounts added to privileged groups (Administrators, sudo, wheel, Domain Admins, etc.) |
| **Unusual process execution** | A watchlist of known attacker tools/techniques (Mimikatz, encoded PowerShell, PsExec, reverse shells, etc.) plus statistically rare one-off processes |

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/CS-Abuhelal/log-anomaly-detector.git
cd log-anomaly-detector
pip install -r requirements.txt
```

The only dependencies are `pandas` and `numpy` - this is deliberately
*not* a machine-learning tool. All the detection logic below is plain
counting, sliding time windows, and z-scores, which keeps it fast,
transparent, and easy to reason about (you can always explain *why*
something was flagged).

## Quick start

Ten sample log files are included in `sample_logs/` so you can try the
tool immediately:

```bash
python analyzer.py sample_logs/mixed_windows.csv sample_logs/mixed_linux.log
```

You can pass any mix of Windows CSV exports and Linux auth.log files in
one run - they get parsed into a single combined timeline and analyzed
together. To save the report to a file:

```bash
python analyzer.py sample_logs/mixed_windows.csv sample_logs/mixed_linux.log --output report.txt
```

### Sample output

```
======================================================================
  LOG ANOMALY DETECTOR - SUMMARY REPORT
======================================================================
  Files analyzed  : sample_logs/mixed_windows.csv, sample_logs/mixed_linux.log
  Events parsed   : 65
  Total findings  : 6

  Findings by severity:
      CRITICAL : 3
      HIGH     : 2
      MEDIUM   : 1
======================================================================

--- CRITICAL ----------------------------------------------------------
  [Risk  97/100 - CRITICAL] Suspicious Process Execution: 'mimikatz.exe' run by
  backup_svc2 matches a known attack pattern: Known credential-dumping tool.

  [Risk  90/100 - CRITICAL] Privilege Escalation: Account 'backup_svc2' was added
  to a highly privileged group (Group: Administrators).

  [Risk  90/100 - CRITICAL] Suspicious Process Execution: '/bin/nc' run by diego
  matches a known attack pattern: Netcat used to spawn a reverse shell.

--- HIGH --------------------------------------------------------------
  [Risk  74/100 - HIGH] Unusual Login Hour: diego logged in at 04:00, an hour
  when logins are statistically rare on this network (z-score -2.24).

  [Risk  70/100 - HIGH] New Account Created: New account 'backup_svc2' was
  created by svc_admin during an unusual hour.

--- MEDIUM ------------------------------------------------------------
  [Risk  63/100 - MEDIUM] Brute Force: 203.0.113.40 made 6 failed login
  attempts within 5 minutes (targeting 6 distinct account(s)).
```

## Input log formats

### Windows (`.csv`)

Two Windows CSV formats are supported and auto-detected:

**1. Event Viewer's GUI export** ("Save All Events As..." / "Save
Filtered Log File As...") - just export your Security log and point the
tool at the file directly, no manual reformatting needed. This format
has a well-known quirk: its header only names 5 columns
(`Keywords, Date and Time, Source, Event ID, Task Category`) but every
row actually has 6 fields - the event description has no column name.
Reading it naively (e.g. opening in Excel/pandas with default settings)
silently shifts every column over by one. This tool detects that header
and reads it correctly, then extracts the account/IP/process details it
needs straight out of the structured `Field Name:	value` text Windows
always writes into the description.

**2. A simplified, documented schema** - useful if you're building CSVs
by hand, from `Get-WinEvent`, or for testing:

```
TimeCreated,EventID,Account,SourceIP,TargetAccount,ProcessName,CommandLine,Message
```

Event IDs both formats understand:

| Event ID | Meaning | Mapped to |
|---|---|---|
| 4624 | An account successfully logged on | `logon_success` |
| 4625 | An account failed to log on | `logon_failed` |
| 4720 | A user account was created | `account_created` |
| 4732 | A member was added to a security-enabled group | `privilege_change` |
| 4688 | A new process has been created | `process_execution` |

Everything else is parsed but ignored - only these five event types feed
the detectors.

### Linux (anything not `.csv`)

Standard syslog-style `/var/log/auth.log` lines, e.g.:

```
Jun 18 03:14:12 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
Jun 18 03:14:15 host sshd[1234]: Accepted password for ahmed from 192.168.1.50 port 51240 ssh2
Jun 18 09:00:01 host useradd[2345]: new user: name=backdoor, UID=1001
Jun 18 09:00:05 host usermod[2345]: add 'backdoor' to group 'sudo'
Jun 18 09:05:00 host sudo:    ahmed : TTY=pts/0 ; PWD=/home/ahmed ; USER=root ; COMMAND=/usr/bin/whoami
```

Both formats get normalized into one internal table (see
`loganomaly/parsers.py`) so every detector works the same way
regardless of where the data came from.

## Sample log files

| File | Demonstrates |
|---|---|
| `windows_normal.csv` / `linux_auth_normal.log` | Clean baselines - business-hours logins only. Produce **zero** findings, by design. |
| `windows_bruteforce.csv` / `linux_auth_bruteforce.log` | A burst of failed logins from one IP, fast enough to cross the brute-force threshold |
| `windows_unusual_hours.csv` | A solid daytime baseline plus two off-hours logins that stand out statistically |
| `windows_new_account.csv` | A new account created at 2:30 AM |
| `windows_privilege_escalation.csv` | An account added to the Administrators group |
| `windows_suspicious_process.csv` | A normal, frequently-run process (ignored) next to an encoded PowerShell command and a one-off rare tool (both flagged) |
| `mixed_windows.csv` + `mixed_linux.log` | A combined incident scenario touching all five detection categories at once - the example above |

Regenerate any of these at any time with:

```bash
python sample_logs/generate_samples.py
```

Every account name, IP address, and command line in these files is
synthetic - no real hosts, users, or credentials are involved. External
IPs use the `203.0.113.0/24` range, which [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737)
reserves specifically for documentation/examples and which isn't
routable on the real internet.

## Tuning detection thresholds

```bash
python analyzer.py mylog.csv \
  --window-minutes 10 \
  --count-threshold 8 \
  --hour-z-threshold -2.0
```

| Flag | Default | Meaning |
|---|---|---|
| `--window-minutes` | 5 | Sliding window size for brute-force burst detection |
| `--count-threshold` | 5 | Failed logins inside the window that counts as a burst |
| `--hour-z-threshold` | -1.5 | Z-score below which a login hour is considered statistically rare (more negative = stricter) |
| `--output` | *(none)* | Also save the report to this file |

## How each detector works (for the curious)

- **Brute force** (`detect_brute_force`): for each source IP, sorts its
  failed logins by time and uses `numpy.searchsorted` to find, for every
  attempt, how many other attempts from that IP happened in the
  preceding N minutes. If that count ever crosses the threshold, it's a
  burst. A bonus is added if the attacker tried 3+ different account
  names (password spraying, not just one guessed account).
- **Unusual hours** (`detect_unusual_hours`): builds a 24-bin histogram
  of which hour successful logins normally happen in, but - importantly
  - computes the mean/standard deviation only over hours that actually
  have activity (otherwise the dozen+ always-empty overnight hours
  would skew the math so badly that any login at all looks like a
  "spike" instead of an outlier). A login is flagged if its hour's
  z-score is below the threshold.
- **New accounts** (`detect_new_accounts`): flags every account
  creation event, adding risk if it happened during a statistically
  rare hour (using the same calculation as above).
- **Privilege escalation** (`detect_privilege_escalation`): flags group
  membership changes, scoring higher when the destination group name
  matches a high-value pattern (Administrators, sudo, wheel, Domain
  Admins, etc).
- **Unusual processes** (`detect_unusual_processes`): checks each
  executed process/command against a watchlist of known attacker
  techniques (Mimikatz, encoded PowerShell, PsExec, certutil/regsvr32/
  bitsadmin LOLBins, reverse shells via netcat, etc). Anything not on
  the watchlist is still flagged if it's statistically rare - i.e. it
  only appears once or twice in the whole log.

## Running the tests

```bash
python tests/test_detectors.py -v
# or, if you have pytest installed:
python -m pytest tests/ -v
```

## Limitations

This is an educational project, not a production SIEM correlation rule
set:

- All analysis is **offline**, on static log files - no live tailing or
  real-time alerting.
- The statistical baselines (hourly rarity, process rarity) need a
  reasonable amount of data to mean anything; a tiny log file won't give
  reliable z-scores.
- The Windows CSV schema is a simplified, documented format chosen for
  clarity - real-world `Get-WinEvent` exports will need their columns
  mapped to match it (or `parsers.py` extended to read them directly).
- The process watchlist is illustrative, not exhaustive - it won't
  catch every attacker tool, especially custom/renamed binaries.

## License

MIT
