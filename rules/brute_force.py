"""
rules/brute_force.py
=====================
Detects brute force / password spray attacks.

MITRE ATT&CK: T1110 — Brute Force

Logic:
  Group all failed login events by (source_ip, username) pair.
  If a source IP exceeds the threshold number of failures
  within the time window → raise a brute force alert.

  Also detects:
  - Username enumeration (many different usernames from one IP)
  - Distributed brute force (same username from many IPs)

Windows Event IDs: 4625 (failed logon)
Linux events    : LINUX_FAILED_LOGIN, LINUX_INVALID_USER

Each finding returned:
  {
    "rule"       : "Brute Force",
    "mitre"      : "T1110",
    "source_ip"  : attacker IP,
    "username"   : targeted account,
    "count"      : number of failures,
    "first_seen" : datetime,
    "last_seen"  : datetime,
    "os_source"  : "windows" | "linux" | "both",
    "events"     : list of raw event dicts,
    "severity"   : "Critical" | "High" | "Medium",
    "detail"     : description string
  }
"""

from collections import defaultdict
from datetime import timedelta
from colorama import Fore


# Event IDs / types that indicate a failed login
FAILED_LOGIN_IDS = {
    4625,                   # Windows: failed logon
    "LINUX_FAILED_LOGIN",   # Linux: SSH failed password
    "LINUX_INVALID_USER",   # Linux: invalid username attempt
    "LINUX_SUDO_FAIL",      # Linux: failed sudo
    "LINUX_SU_FAIL",        # Linux: failed su
}


def _is_failed_login(event: dict) -> bool:
    eid = event.get("event_id")
    return eid in FAILED_LOGIN_IDS


def _severity_from_count(count: int, threshold: int) -> str:
    """Determine severity based on how far count exceeds threshold."""
    ratio = count / threshold
    if ratio >= 10:
        return "Critical"
    if ratio >= 5:
        return "High"
    return "Medium"


def detect_brute_force(
    events        : list,
    threshold     : int = 5,
    window_minutes: int = 10,
    verbose       : bool = False,
) -> list:
    """
    Scan all events for brute force patterns.

    Parameters
    ----------
    events         : list of normalised event dicts from parsers
    threshold      : number of failures before alerting
    window_minutes : sliding time window in minutes
    verbose        : print detail per finding

    Returns
    -------
    list of finding dicts
    """
    findings   = []
    window     = timedelta(minutes=window_minutes)

    # ── Group failed logins by IP ─────────────────────────────────────
    # Key: source_ip → list of events
    by_ip = defaultdict(list)
    # Key: (source_ip, username) → list of events
    by_ip_user = defaultdict(list)
    # Key: username → set of source IPs (for password spray detection)
    by_user_ips = defaultdict(set)

    for event in events:
        if not _is_failed_login(event):
            continue

        ip   = event.get("ip_address", "unknown") or "unknown"
        user = event.get("user", "unknown")        or "unknown"

        # Skip local/empty IPs for brute force (not network attacks)
        if ip in ("local", "unknown", "", "::1", "127.0.0.1"):
            ip = "local"

        by_ip[ip].append(event)
        by_ip_user[(ip, user)].append(event)
        by_user_ips[user].add(ip)

    already_reported = set()

    # ── Check each (IP, username) pair with sliding window ────────────
    for (ip, user), ip_user_events in by_ip_user.items():
        ip_user_events.sort(key=lambda e: e["timestamp"])

        # Sliding window: find max failures in any window_minutes period
        max_in_window = 0
        window_start_idx = 0

        for i, event in enumerate(ip_user_events):
            # Move window start forward
            while (event["timestamp"] - ip_user_events[window_start_idx]["timestamp"]) > window:
                window_start_idx += 1
            count_in_window = i - window_start_idx + 1
            max_in_window   = max(max_in_window, count_in_window)

        if max_in_window >= threshold:
            key = (ip, user)
            if key in already_reported:
                continue
            already_reported.add(key)

            severity = _severity_from_count(max_in_window, threshold)
            os_src   = set(e["source"] for e in ip_user_events)
            os_label = "/".join(sorted(os_src))

            detail = (
                f"{max_in_window} failed login attempts for account '{user}' "
                f"from IP {ip} within {window_minutes} minutes. "
                f"Threshold: {threshold}. OS: {os_label}."
            )

            if verbose:
                color = Fore.RED if severity in ("Critical", "High") else Fore.YELLOW
                print(f"{color}    [brute] {detail}")

            findings.append({
                "rule"       : "Brute Force Login",
                "mitre"      : "T1110",
                "mitre_name" : "Brute Force",
                "source_ip"  : ip,
                "username"   : user,
                "count"      : max_in_window,
                "first_seen" : ip_user_events[0]["timestamp"],
                "last_seen"  : ip_user_events[-1]["timestamp"],
                "os_source"  : os_label,
                "events"     : ip_user_events,
                "severity"   : severity,
                "detail"     : detail,
            })

    # ── Detect username enumeration (many unique usernames from one IP) ─
    for ip, ip_events in by_ip.items():
        unique_users = set(e.get("user") for e in ip_events)
        if len(unique_users) >= 5 and ip not in ("local", "unknown"):
            key = (ip, "__enum__")
            if key not in already_reported:
                already_reported.add(key)
                detail = (
                    f"Username enumeration suspected: IP {ip} tried "
                    f"{len(unique_users)} different usernames "
                    f"({len(ip_events)} total attempts)."
                )
                if verbose:
                    print(f"{Fore.YELLOW}    [brute] {detail}")
                findings.append({
                    "rule"       : "Username Enumeration",
                    "mitre"      : "T1110.003",
                    "mitre_name" : "Password Spraying",
                    "source_ip"  : ip,
                    "username"   : f"{len(unique_users)} unique users",
                    "count"      : len(ip_events),
                    "first_seen" : min(e["timestamp"] for e in ip_events),
                    "last_seen"  : max(e["timestamp"] for e in ip_events),
                    "os_source"  : "mixed",
                    "events"     : ip_events[:10],
                    "severity"   : "High",
                    "detail"     : detail,
                })

    # ── Detect password spray (one user, many IPs) ────────────────────
    for user, ip_set in by_user_ips.items():
        if len(ip_set) >= 3 and user not in ("unknown", ""):
            key = ("__spray__", user)
            if key not in already_reported:
                already_reported.add(key)
                spray_events = [
                    e for e in events
                    if _is_failed_login(e) and e.get("user") == user
                ]
                detail = (
                    f"Password spray suspected: account '{user}' targeted from "
                    f"{len(ip_set)} different IP addresses "
                    f"({len(spray_events)} total attempts)."
                )
                if verbose:
                    print(f"{Fore.YELLOW}    [brute] {detail}")
                findings.append({
                    "rule"       : "Password Spray",
                    "mitre"      : "T1110.003",
                    "mitre_name" : "Password Spraying",
                    "source_ip"  : f"{len(ip_set)} IPs",
                    "username"   : user,
                    "count"      : len(spray_events),
                    "first_seen" : min(e["timestamp"] for e in spray_events),
                    "last_seen"  : max(e["timestamp"] for e in spray_events),
                    "os_source"  : "mixed",
                    "events"     : spray_events[:10],
                    "severity"   : "High",
                    "detail"     : detail,
                })

    return findings
