

from collections import defaultdict
from colorama import Fore


LOCKOUT_IDS = {
    4740,                    
    "LINUX_ACCOUNT_LOCKED",  

UNLOCK_IDS = {
    4767,                    
}


def detect_account_lockout(
    events  : list,
    verbose : bool = False,
) -> list:
    
    findings = []

    # Group lockout events by username
    lockouts_by_user = defaultdict(list)
    unlocks_by_user  = defaultdict(list)

    for event in events:
        eid = event.get("event_id")
        if eid in LOCKOUT_IDS:
            user = event.get("user", "unknown") or "unknown"
            lockouts_by_user[user].append(event)
        elif eid in UNLOCK_IDS:
            user = event.get("user", "unknown") or "unknown"
            unlocks_by_user[user].append(event)

    for user, lockout_events in lockouts_by_user.items():
        count     = len(lockout_events)
        first     = min(e["timestamp"] for e in lockout_events)
        last      = max(e["timestamp"] for e in lockout_events)
        computers = list(set(e.get("computer", "unknown") for e in lockout_events))
        unlocked  = len(unlocks_by_user.get(user, []))

        # Multiple lockouts on multiple machines = high severity
        severity = "High" if count > 1 or len(computers) > 1 else "Medium"

        detail = (
            f"Account '{user}' locked out {count} time(s) "
            f"between {first.strftime('%H:%M:%S')} and {last.strftime('%H:%M:%S')}. "
            f"Affected host(s): {', '.join(computers[:3])}. "
        )
        if unlocked:
            detail += f"Account was unlocked {unlocked} time(s) during this period."

        if verbose:
            color = Fore.RED if severity == "High" else Fore.YELLOW
            print(f"{color}    [lockout] {detail}")

        findings.append({
            "rule"          : "Account Lockout",
            "mitre"         : "T1110.001",
            "mitre_name"    : "Password Guessing",
            "username"      : user,
            "computer"      : computers[0] if computers else "unknown",
            "timestamp"     : first,
            "last_seen"     : last,
            "lockout_count" : count,
            "unlock_count"  : unlocked,
            "computers"     : computers,
            "detail"        : detail,
            "severity"      : severity,
            "events"        : lockout_events,
        })

    return findings
