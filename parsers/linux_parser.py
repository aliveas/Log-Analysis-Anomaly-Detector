import re
from datetime import datetime
from colorama import Fore

TS_STANDARD = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
TS_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
)


HOSTNAME_RE = re.compile(
    r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+"
)


FAILED_PW_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d\.a-fA-F:]+) port (\d+)"
)


ACCEPTED_PW_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d\.a-fA-F:]+) port (\d+)"
)


INVALID_USER_RE = re.compile(
    r"Invalid user (\S+) from ([\d\.a-fA-F:]+)"
)


SUDO_RE = re.compile(
    r"sudo:\s+(\S+)\s*:.*COMMAND=(.*)"
)


SUDO_FAIL_RE = re.compile(
    r"sudo:\s+(\S+)\s*:.*authentication failure"
)


SU_RE = re.compile(
    r"su\S*:\s+(?:Successful|FAILED)\s+su\s+for\s+(\S+)\s+by\s+(\S+)"
)


LOCKED_RE = re.compile(
    r"pam_tally|account.*locked|pam_faillock.*deny"
)


SESSION_OPEN_RE = re.compile(
    r"pam_unix\(\S+:session\): session opened for user (\S+)"
)


DISCONNECT_RE = re.compile(
    r"Disconnected from.*?([\d\.a-fA-F:]+) port (\d+)"
)

CURRENT_YEAR = datetime.now().year


def _parse_timestamp(line: str) -> datetime:
   
    m = TS_ISO.match(line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass

  
    m = TS_STANDARD.match(line)
    if m:
        ts_str = m.group(1).strip()
        
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
   
    timestamp = _parse_timestamp(line)
    hostname  = _get_hostname(line)

   
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


    if LOCKED_RE.search(line):
      
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

    return None   

def parse_linux_logs(file_path: str, verbose: bool = False) -> list:
    
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

   
    events.sort(key=lambda e: e["timestamp"])

    for eid, cnt in sorted(type_counts.items()):
        print(f"{Fore.CYAN}    {eid}: {cnt:>4} event(s)")

    return events
