
from datetime import datetime


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _infer_alert_source(finding: dict) -> str:
    """Derive OS label for dashboard badges (windows / linux / both)."""
    if finding.get("os_source"):
        return finding["os_source"]
    events = finding.get("events") or []
    parts = sorted({e.get("source", "") for e in events if e.get("source")})
    return "/".join(parts) if parts else finding.get("source", "unknown")


def _format_alert(finding: dict, alert_type: str) -> dict:
    """Convert a raw finding dict into a standard alert dict."""
    ts = finding.get("timestamp") or finding.get("first_seen") or datetime.now()

    return {
        "type"      : alert_type,
        "rule"      : finding.get("rule", "Unknown"),
        "mitre"     : finding.get("mitre", ""),
        "mitre_name": finding.get("mitre_name", ""),
        "severity"  : finding.get("severity", "Low"),
        "summary"   : _short_summary(finding),
        "detail"    : finding.get("detail", ""),
        "source"    : _infer_alert_source(finding),
        "username"  : finding.get("username", ""),
        "source_ip" : finding.get("source_ip", ""),
        "computer"  : finding.get("computer", ""),
        "timestamp" : ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts),
        "count"     : finding.get("count", finding.get("lockout_count", 1)),
        "events"    : finding.get("events", [])[:5],  # keep first 5 raw events
    }


def _short_summary(finding: dict) -> str:
    """Generate a one-line alert summary."""
    rule = finding.get("rule", "")
    user = finding.get("username", "")
    ip   = finding.get("source_ip", "")
    cnt  = finding.get("count", finding.get("lockout_count", 0))

    if "Brute Force" in rule:
        return f"{cnt} failed logins for '{user}' from {ip}"
    if "Enumeration" in rule:
        return f"Username enumeration from {ip} - {cnt} attempts"
    if "Spray" in rule:
        return f"Password spray against '{user}' from {ip}"
    if "Lockout" in rule:
        lc = finding.get("lockout_count", 1)
        return f"Account '{user}' locked out {lc} time(s)"
    if "Privilege" in rule or "Sudo" in rule or "Root" in rule or "su" in rule.lower():
        comp = finding.get("computer", "")
        return f"Privilege escalation by '{user}' on {comp}"
    if "Service" in rule:
        return f"New service installed by '{user}'"
    if "Task" in rule:
        return f"Scheduled task created by '{user}'"
    if "Group" in rule and "Membership" in rule:
        return f"Privileged group change on {finding.get('computer', '')}"
    return finding.get("detail", rule)[:80]


def build_alerts(
    bf_findings : list,
    pe_findings : list,
    al_findings : list,
) -> list:
    
    alerts = []

    for f in bf_findings:
        alerts.append(_format_alert(f, "brute_force"))

    for f in pe_findings:
        alerts.append(_format_alert(f, "privilege_escalation"))

    for f in al_findings:
        alerts.append(_format_alert(f, "account_lockout"))

    # Sort by severity (Critical first) then by timestamp descending
    alerts.sort(key=lambda a: (
        SEVERITY_ORDER.get(a["severity"], 99),
        a["timestamp"],
    ))

    return alerts
