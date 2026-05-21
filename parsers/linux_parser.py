"""
parsers/linux_parser.py
========================
Parses Linux authentication logs:
  /var/log/auth.log   — Debian/Ubuntu
  /var/log/secure     — RHEL/CentOS/Fedora
  /var/log/syslog     — general system log

Log line format:
  Apr  3 14:22:31 hostname sshd[12345]: Failed password for user from 1.2.3.4 port 22 ssh2

Patterns we detect:
  - Failed password       → failed login attempt
  - Accepted password     → successful login
  - Failed publickey      → failed SSH key auth
  - Invalid user          → login with non-existent username
  - sudo:                 → sudo command used
  - pam_unix(sudo:auth)   → sudo authentication
  - FAILED su             → failed su attempt
  - account locked        → PAM account lock
  - session opened for    → new session (privilege context)

Each parsed event is normalised into:
  {
    "event_id"   : string label e.g. "LINUX_FAILED_LOGIN",
    "timestamp"  : datetime object,
    "source"     : "linux",
    "computer"   : hostname,
    "user"       : username,
    "ip_address" : source IP (if SSH),
    "port"       : source port (if SSH),
    "process"    : sshd | sudo | su | PAM,
    "description": human-readable summary,
    "raw"        : original log line
  }
"""

import re
from datetime import datetime
from colorama import Fore


# ─────────────────────────────────────────────
# Regex patterns for each log event type
# ─────────────────────────────────────────────

# Timestamp at start of line: "Apr  3 14:22:31" or "2026-04-03T14:22:31"
TS_STANDARD = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
TS_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
)

# Hostname after timestamp
HOSTNAME_RE = re.compile(
    r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+"
)

# SSH failed password: "Failed password for [invalid user] USERNAME from IP port PORT"
FAILED_PW_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d\.a-fA-F:]+) port (\d+)"
)

# SSH accepted password
ACCEPTED_PW_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d\.a-fA-F:]+) port (\d+)"
)

# SSH invalid user (no password attempt yet)
INVALID_USER_RE = re.compile(
    r"Invalid user (\S+) from ([\d\.a-fA-F:]+)"
)

# sudo command
SUDO_RE = re.compile(
    r"sudo:\s+(\S+)\s*:.*COMMAND=(.*)"
)

# Failed sudo
SUDO_FAIL_RE = re.compile(
    r"sudo:\s+(\S+)\s*:.*authentication failure"
)

# su to root
SU_RE = re.compile(
    r"su\S*:\s+(?:Successful|FAILED)\s+su\s+for\s+(\S+)\s+by\s+(\S+)"
)

# PAM account locked
LOCKED_RE = re.compile(
    r"pam_tally|account.*locked|pam_faillock.*deny"
)

# New session opened (tracks who got a session)
SESSION_OPEN_RE = re.compile(
    r"pam_unix\(\S+:session\): session opened for user (\S+)"
)

# Disconnect
DISCONNECT_RE = re.compile(
    r"Disconnected from.*?([\d\.a-fA-F:]+) port (\d+)"
)

# Current year for timestamp reconstruction
CURRENT_YEAR = datetime.now().year


def _parse_timestamp(line: str) -> datetime:
    """
    Extract and parse the timestamp from a log line.
    Handles both 'Apr  3 14:22:31' and ISO 8601 formats.
    """
    # Try ISO format first
    m = TS_ISO.match(line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass

    # Try standard syslog format
    m = TS_STANDARD.match(line)
    if m:
        ts_str = m.group(1).strip()
        # Normalise double spaces: "Apr  3" → "Apr 3"
        ts_str = " ".join(ts_str.split())
        try:
            dt = datetime.strptime(f"{ts_str} {CURRENT_YEAR}", "%b %d %H:%M:%S %Y")
            return dt
        except ValueError:
            pass

    return datetime.now()


def _get_hostname(line: str) -> str:
    """Extract hostname from log line."""
    m = HOSTNAME_RE.match(line)
    return m.group(1) if m else "unknown"


def _classify_line(line: str) -> dict | None:
    """
    Classify a single log line into an event dict.
    Returns None if the line doesn't match any pattern we care about.
    """
    timestamp = _parse_timestamp(line)
    hostname  = _get_hostname(line)

    # ── Failed SSH login ─────────────────────────────────────────────
    m = FAILED_PW_RE.search(line)
    if m:
        return {
            "event_id"   : "LINUX_FAILED_LOGIN",
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : m.group(1),
            "ip_address" : m.group(2),
            "port"       : m.group(3),
            "process"    : "sshd",
            "description": f"Failed SSH login for '{m.group(1)}' from {m.group(2)}",
            "raw"        : line.strip(),
        }

    # ── Invalid user (pre-auth rejection) ────────────────────────────
    m = INVALID_USER_RE.search(line)
    if m:
        return {
            "event_id"   : "LINUX_INVALID_USER",
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : m.group(1),
            "ip_address" : m.group(2),
            "port"       : "",
            "process"    : "sshd",
            "description": f"SSH login attempt with invalid username '{m.group(1)}' from {m.group(2)}",
            "raw"        : line.strip(),
        }

    # ── Successful SSH login ──────────────────────────────────────────
    m = ACCEPTED_PW_RE.search(line)
    if m:
        return {
            "event_id"   : "LINUX_SUCCESSFUL_LOGIN",
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : m.group(1),
            "ip_address" : m.group(2),
            "port"       : m.group(3),
            "process"    : "sshd",
            "description": f"Successful SSH login for '{m.group(1)}' from {m.group(2)}",
            "raw"        : line.strip(),
        }

    # ── sudo command (privilege escalation) ──────────────────────────
    m = SUDO_RE.search(line)
    if m:
        return {
            "event_id"   : "LINUX_SUDO_COMMAND",
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : m.group(1),
            "ip_address" : "",
            "port"       : "",
            "process"    : "sudo",
            "command"    : m.group(2).strip(),
            "description": f"sudo command by '{m.group(1)}': {m.group(2).strip()[:60]}",
            "raw"        : line.strip(),
        }

    # ── Failed sudo authentication ────────────────────────────────────
    m = SUDO_FAIL_RE.search(line)
    if m and "authentication failure" in line:
        user = m.group(1) if m else "unknown"
        return {
            "event_id"   : "LINUX_SUDO_FAIL",
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : user,
            "ip_address" : "",
            "port"       : "",
            "process"    : "sudo",
            "description": f"Failed sudo authentication by '{user}'",
            "raw"        : line.strip(),
        }

    # ── su to another account ─────────────────────────────────────────
    m = SU_RE.search(line)
    if m:
        status  = "Successful" if "Successful" in line else "FAILED"
        eid     = "LINUX_SU_SUCCESS" if status == "Successful" else "LINUX_SU_FAIL"
        return {
            "event_id"   : eid,
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : m.group(2),
            "target_user": m.group(1),
            "ip_address" : "",
            "port"       : "",
            "process"    : "su",
            "description": f"{status} su from '{m.group(2)}' to '{m.group(1)}'",
            "raw"        : line.strip(),
        }

    # ── Account locked by PAM ─────────────────────────────────────────
    if LOCKED_RE.search(line):
        # Try to extract username
        user_m = re.search(r"user[=\s]+(\S+)", line, re.IGNORECASE)
        user   = user_m.group(1) if user_m else "unknown"
        return {
            "event_id"   : "LINUX_ACCOUNT_LOCKED",
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : user,
            "ip_address" : "",
            "port"       : "",
            "process"    : "pam",
            "description": f"Account locked by PAM for '{user}'",
            "raw"        : line.strip(),
        }

    # ── New session opened ────────────────────────────────────────────
    m = SESSION_OPEN_RE.search(line)
    if m:
        return {
            "event_id"   : "LINUX_SESSION_OPEN",
            "timestamp"  : timestamp,
            "source"     : "linux",
            "computer"   : hostname,
            "user"       : m.group(1),
            "ip_address" : "",
            "port"       : "",
            "process"    : "pam",
            "description": f"Session opened for user '{m.group(1)}'",
            "raw"        : line.strip(),
        }

    return None   # Line not relevant to our detection rules


def parse_linux_logs(file_path: str, verbose: bool = False) -> list:
    """
    Parse a Linux auth.log or syslog file line by line.

    Parameters
    ----------
    file_path : str  — path to log file
    verbose   : bool — print each parsed event

    Returns
    -------
    list of normalised event dicts
    """
    events = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except IOError as e:
        print(f"{Fore.RED}[!] Cannot read {file_path}: {e}")
        return events

    from collections import Counter
    type_counts = Counter()

    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue

        parsed = _classify_line(line)
        if parsed:
            events.append(parsed)
            type_counts[parsed["event_id"]] += 1

            if verbose:
                print(
                    f"{Fore.CYAN}    [linux] {parsed['timestamp'].strftime('%H:%M:%S')} "
                    f"{parsed['event_id']} "
                    f"User:{parsed['user'] or 'N/A'} "
                    f"IP:{parsed['ip_address'] or 'N/A'}"
                )

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])

    # Summary
    for eid, cnt in sorted(type_counts.items()):
        print(f"{Fore.CYAN}    {eid}: {cnt:>4} event(s)")

    return events
