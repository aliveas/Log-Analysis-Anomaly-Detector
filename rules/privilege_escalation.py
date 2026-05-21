"""
rules/privilege_escalation.py
==============================
Detects privilege escalation attempts and successes.

MITRE ATT&CK:
  T1078   — Valid Accounts (special privilege logon)
  T1548.003 — Abuse Elevation Control (sudo abuse)
  T1543   — Create or Modify System Process (new service/task)

Windows patterns:
  4672 — Special privileges assigned to new logon
         (SeDebugPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege etc.)
  4698 — Scheduled task created (persistence + priv esc vector)
  7045 — New service installed
  4756 — Member added to privileged group

Linux patterns:
  LINUX_SUDO_COMMAND — sudo used (especially for sensitive commands)
  LINUX_SU_SUCCESS   — successful su to root or other account
  LINUX_SESSION_OPEN — root session opened

Each finding:
  {
    "rule"      : rule name,
    "mitre"     : technique ID,
    "username"  : who escalated,
    "computer"  : on which host,
    "timestamp" : when,
    "detail"    : what happened,
    "severity"  : "Critical" | "High" | "Medium" | "Low",
    "events"    : list of raw event dicts
  }
"""

from colorama import Fore


# Windows special privileges that indicate high-level access
DANGEROUS_PRIVILEGES = {
    "SeDebugPrivilege"          : "Allows debugging any process — used by mimikatz",
    "SeTcbPrivilege"            : "Act as part of the OS — highest level",
    "SeLoadDriverPrivilege"     : "Load kernel drivers — rootkit vector",
    "SeBackupPrivilege"         : "Read any file bypassing ACLs",
    "SeRestorePrivilege"        : "Write any file bypassing ACLs",
    "SeTakeOwnershipPrivilege"  : "Take ownership of any object",
    "SeImpersonatePrivilege"    : "Impersonate any token — used in potato attacks",
    "SeAssignPrimaryTokenPrivilege": "Assign primary token — privilege escalation",
    "SeCreateTokenPrivilege"    : "Create arbitrary tokens",
}

# Linux sudo commands that indicate root or sensitive access
DANGEROUS_SUDO_COMMANDS = [
    "/bin/bash", "/bin/sh", "/usr/bin/bash",  # shell escalation
    "chmod 777", "chmod +s",                   # dangerous permission changes
    "passwd",                                   # password change
    "/etc/passwd", "/etc/shadow",               # sensitive file access
    "visudo", "/etc/sudoers",                   # sudoers modification
    "useradd", "usermod", "userdel",            # account manipulation
    "crontab",                                  # persistence via cron
    "nc ", "netcat", "ncat",                   # reverse shell tools
    "wget ", "curl ",                           # file download
    "python -c", "perl -e", "ruby -e",         # code execution
    "dd if=", "dd of=",                         # disk operations
    "iptables", "ufw",                          # firewall changes
    "systemctl",                                # service control
]

# Windows Event IDs for this rule
PRIV_WINDOWS_IDS = {4672, 4698, 7045, 4756}

# Linux event types for this rule
PRIV_LINUX_IDS = {
    "LINUX_SUDO_COMMAND",
    "LINUX_SU_SUCCESS",
    "LINUX_SESSION_OPEN",
}


def _check_dangerous_privilege(privileges: str) -> list:
    """Return list of dangerous privileges found in the privilege string."""
    if not privileges:
        return []
    found = []
    for priv, desc in DANGEROUS_PRIVILEGES.items():
        if priv in privileges:
            found.append((priv, desc))
    return found


def _check_dangerous_sudo(command: str) -> str | None:
    """Return the matched dangerous pattern if sudo command is suspicious."""
    if not command:
        return None
    cmd_lower = command.lower()
    for pattern in DANGEROUS_SUDO_COMMANDS:
        if pattern.lower() in cmd_lower:
            return pattern
    return None


def detect_privilege_escalation(
    events  : list,
    verbose : bool = False,
) -> list:
    """
    Scan all events for privilege escalation indicators.

    Parameters
    ----------
    events  : list of normalised event dicts
    verbose : bool

    Returns
    -------
    list of finding dicts
    """
    findings = []

    for event in events:
        eid    = event.get("event_id")
        source = event.get("source", "")

        # ── Windows: Special privileges assigned (4672) ───────────────
        if eid == 4672:
            privileges = event.get("privileges", "")
            dangerous  = _check_dangerous_privilege(privileges)

            if dangerous:
                priv_list = ", ".join(p[0] for p in dangerous)
                reasons   = "; ".join(f"{p[0]}: {p[1]}" for p in dangerous)
                severity  = "Critical" if "SeDebugPrivilege" in privileges or \
                             "SeTcbPrivilege" in privileges else "High"
                detail = (
                    f"Dangerous privileges assigned to '{event.get('user', 'unknown')}' "
                    f"on {event.get('computer', 'unknown')}: {priv_list}. "
                    f"Reason: {reasons}"
                )
                if verbose:
                    print(f"{Fore.RED}    [privesc] {detail}")
                findings.append({
                    "rule"      : "Dangerous Privilege Assignment",
                    "mitre"     : "T1078",
                    "mitre_name": "Valid Accounts",
                    "username"  : event.get("user", "unknown"),
                    "computer"  : event.get("computer", "unknown"),
                    "timestamp" : event["timestamp"],
                    "detail"    : detail,
                    "severity"  : severity,
                    "events"    : [event],
                })
            else:
                # Even without dangerous privs, 4672 is worth noting at Low
                if event.get("user") and event["user"].lower() not in (
                    "system", "local service", "network service", ""
                ):
                    detail = (
                        f"Special privileges assigned to '{event.get('user')}' "
                        f"on {event.get('computer')} at {event['timestamp'].strftime('%H:%M:%S')}"
                    )
                    if verbose:
                        print(f"{Fore.BLUE}    [privesc] {detail}")
                    findings.append({
                        "rule"      : "Special Privilege Logon",
                        "mitre"     : "T1078",
                        "mitre_name": "Valid Accounts",
                        "username"  : event.get("user", "unknown"),
                        "computer"  : event.get("computer", "unknown"),
                        "timestamp" : event["timestamp"],
                        "detail"    : detail,
                        "severity"  : "Low",
                        "events"    : [event],
                    })

        # ── Windows: Scheduled task created (4698) ────────────────────
        elif eid == 4698:
            detail = (
                f"Scheduled task created by '{event.get('user', 'unknown')}' "
                f"on {event.get('computer', 'unknown')} — common persistence technique."
            )
            if verbose:
                print(f"{Fore.YELLOW}    [privesc] {detail}")
            findings.append({
                "rule"      : "Scheduled Task Created",
                "mitre"     : "T1053.005",
                "mitre_name": "Scheduled Task/Job",
                "username"  : event.get("user", "unknown"),
                "computer"  : event.get("computer", "unknown"),
                "timestamp" : event["timestamp"],
                "detail"    : detail,
                "severity"  : "Medium",
                "events"    : [event],
            })

        # ── Windows: Member added to security-enabled group (4756) ────
        elif eid == 4756:
            grp = event.get("group_name") or "unknown"
            adminish = any(
                x in grp.lower()
                for x in ("admin", "domain admins", "enterprise admins", "schema")
            )
            detail = (
                f"Member added to privileged group '{grp}' on "
                f"{event.get('computer', 'unknown')} (actor: '{event.get('user', 'unknown')}')."
            )
            if verbose:
                print(f"{Fore.YELLOW}    [privesc] {detail}")
            findings.append({
                "rule"      : "Privileged Group Membership Change",
                "mitre"     : "T1098",
                "mitre_name": "Account Manipulation",
                "username"  : event.get("user", "unknown"),
                "computer"  : event.get("computer", "unknown"),
                "timestamp" : event["timestamp"],
                "detail"    : detail,
                "severity"  : "High" if adminish else "Medium",
                "events"    : [event],
            })

        # ── Windows: New service installed (7045) ─────────────────────
        elif eid == 7045:
            svc = event.get("service_name", "unknown")
            detail = (
                f"New service '{svc}' installed on {event.get('computer', 'unknown')} "
                f"by '{event.get('user', 'unknown')}' — potential malware persistence."
            )
            if verbose:
                print(f"{Fore.YELLOW}    [privesc] {detail}")
            findings.append({
                "rule"      : "New Service Installed",
                "mitre"     : "T1543.003",
                "mitre_name": "Windows Service",
                "username"  : event.get("user", "unknown"),
                "computer"  : event.get("computer", "unknown"),
                "timestamp" : event["timestamp"],
                "detail"    : detail,
                "severity"  : "High",
                "events"    : [event],
            })

        # ── Linux: Sudo command used ───────────────────────────────────
        elif eid == "LINUX_SUDO_COMMAND":
            command  = event.get("command", "")
            matched  = _check_dangerous_sudo(command)
            severity = "High" if matched else "Low"

            detail = (
                f"sudo command by '{event.get('user', 'unknown')}' "
                f"on {event.get('computer', 'unknown')}: {command[:80]}"
            )
            if matched:
                detail += f" — Dangerous pattern matched: '{matched}'"

            if matched or verbose:
                color = Fore.RED if matched else Fore.BLUE
                if verbose:
                    print(f"{color}    [privesc] {detail}")

            if matched:
                findings.append({
                    "rule"      : "Suspicious Sudo Command",
                    "mitre"     : "T1548.003",
                    "mitre_name": "Sudo and Sudo Caching",
                    "username"  : event.get("user", "unknown"),
                    "computer"  : event.get("computer", "unknown"),
                    "timestamp" : event["timestamp"],
                    "detail"    : detail,
                    "severity"  : severity,
                    "events"    : [event],
                })

        # ── Linux: Successful su to root ──────────────────────────────
        elif eid == "LINUX_SU_SUCCESS":
            target = event.get("target_user", "unknown")
            severity = "High" if target == "root" else "Medium"
            detail = (
                f"Successful su by '{event.get('user', 'unknown')}' "
                f"to '{target}' on {event.get('computer', 'unknown')}"
            )
            if verbose:
                print(f"{Fore.YELLOW}    [privesc] {detail}")
            findings.append({
                "rule"      : "Successful Account Switching (su)",
                "mitre"     : "T1548",
                "mitre_name": "Abuse Elevation Control",
                "username"  : event.get("user", "unknown"),
                "computer"  : event.get("computer", "unknown"),
                "timestamp" : event["timestamp"],
                "detail"    : detail,
                "severity"  : severity,
                "events"    : [event],
            })

        # ── Linux: Root session opened ────────────────────────────────
        elif eid == "LINUX_SESSION_OPEN":
            user = event.get("user", "")
            if user == "root":
                detail = (
                    f"Root session opened on {event.get('computer', 'unknown')} "
                    f"— direct root login detected."
                )
                if verbose:
                    print(f"{Fore.RED}    [privesc] {detail}")
                findings.append({
                    "rule"      : "Direct Root Login",
                    "mitre"     : "T1078.003",
                    "mitre_name": "Local Accounts",
                    "username"  : "root",
                    "computer"  : event.get("computer", "unknown"),
                    "timestamp" : event["timestamp"],
                    "detail"    : detail,
                    "severity"  : "High",
                    "events"    : [event],
                })

    return findings
