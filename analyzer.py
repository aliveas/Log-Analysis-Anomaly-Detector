"""
Log Analysis & Anomaly Detector
================================
Main CLI entry point — parses Windows Event Logs and Linux syslogs,
runs all three detection rules, and generates an HTML alert dashboard.

Usage:
    python analyzer.py --windows windows_events.xml
    python analyzer.py --linux   linux_auth.log
    python analyzer.py --windows windows_events.xml --linux linux_auth.log
    python analyzer.py --windows windows_events.xml --output my_report.html --verbose
"""

import argparse
import datetime
import os
import sys
import time

from colorama import Fore, Style, init

from parsers.windows_parser      import parse_windows_events
from parsers.linux_parser        import parse_linux_logs
from rules.brute_force           import detect_brute_force
from rules.privilege_escalation  import detect_privilege_escalation
from rules.account_lockout       import detect_account_lockout
from alerts.alert_engine         import build_alerts
from report.generator            import generate_report

init(autoreset=True)


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────

def print_banner():
    print(f"""
{Fore.CYAN}+------------------------------------------------------+
|        Log Analysis & Anomaly Detector  v1.0         |
|           SOC Analysis Toolkit  2026                 |
+------------------------------------------------------+{Style.RESET_ALL}
""")


# ─────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Log Analysis & Anomaly Detector — SOC Educational Tool"
    )
    parser.add_argument(
        "--windows", metavar="FILE",
        help="Path to Windows Event Log file (.evtx or .xml)"
    )
    parser.add_argument(
        "--linux", metavar="FILE",
        help="Path to Linux auth.log or syslog file"
    )
    parser.add_argument(
        "--output", default="report.html",
        help="HTML report filename (default: report.html)"
    )
    parser.add_argument(
        "--threshold-brute", type=int, default=5,
        help="Failed login attempts before brute force alert (default: 5)"
    )
    parser.add_argument(
        "--window-minutes", type=int, default=10,
        help="Time window in minutes for brute force detection (default: 10)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print detailed output for every event parsed"
    )
    return parser.parse_args()


# ─────────────────────────────────────────────
# Section printer
# ─────────────────────────────────────────────

def section(title: str, color=Fore.CYAN):
    print(f"\n{color}{'-' * 54}")
    print(f"  {title}")
    print(f"{'-' * 54}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
# Print alert summary to terminal
# ─────────────────────────────────────────────

def print_alerts(alerts: list):
    if not alerts:
        print(f"{Fore.GREEN}  [OK] No alerts triggered.")
        return
    for alert in alerts:
        color = (Fore.RED    if alert["severity"] == "Critical" else
                 Fore.RED    if alert["severity"] == "High"     else
                 Fore.YELLOW if alert["severity"] == "Medium"   else
                 Fore.BLUE)
        print(f"{color}  [{alert['severity'].upper()}] {alert['rule']} - {alert['summary']}")
        print(f"           Source: {alert['source']} | Count: {alert['count']}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print_banner()
    args = parse_args()

    if not args.windows and not args.linux:
        print(f"{Fore.RED}[!] Provide at least one log file.")
        print(f"    --windows path/to/events.xml")
        print(f"    --linux   path/to/auth.log")
        sys.exit(1)

    scan_time  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_time = time.time()

    print(f"{Fore.CYAN}[*] Started : {scan_time}")

    all_events = []

    # ══════════════════════════════════════════
    # STEP 1 — Parse Windows logs
    # ══════════════════════════════════════════
    windows_events = []
    if args.windows:
        section("STEP 1 - Parsing Windows Event Logs")
        if not os.path.isfile(args.windows):
            print(f"{Fore.RED}[!] File not found: {args.windows}")
        else:
            windows_events = parse_windows_events(
                args.windows, verbose=args.verbose
            )
            print(f"{Fore.GREEN}[+] Parsed {len(windows_events)} Windows events")
            all_events.extend(windows_events)

    # ══════════════════════════════════════════
    # STEP 2 — Parse Linux logs
    # ══════════════════════════════════════════
    linux_events = []
    if args.linux:
        section("STEP 2 - Parsing Linux Auth Logs")
        if not os.path.isfile(args.linux):
            print(f"{Fore.RED}[!] File not found: {args.linux}")
        else:
            linux_events = parse_linux_logs(
                args.linux, verbose=args.verbose
            )
            print(f"{Fore.GREEN}[+] Parsed {len(linux_events)} Linux events")
            all_events.extend(linux_events)

    if not all_events:
        print(f"{Fore.RED}[!] No events parsed. Check your log file paths.")
        sys.exit(1)

    print(f"\n{Fore.CYAN}[*] Total events to analyse: {len(all_events)}")

    # ══════════════════════════════════════════
    # STEP 3 — Run detection rules
    # ══════════════════════════════════════════
    section("STEP 3 - Running Detection Rules")

    print(f"{Fore.CYAN}  [*] Rule 1 - Brute Force / Failed Logins (MITRE T1110)")
    bf_findings = detect_brute_force(
        all_events,
        threshold=args.threshold_brute,
        window_minutes=args.window_minutes,
        verbose=args.verbose,
    )
    print(f"{Fore.GREEN}      Found: {len(bf_findings)} finding(s)")

    print(f"{Fore.CYAN}  [*] Rule 2 - Privilege Escalation (MITRE T1078)")
    pe_findings = detect_privilege_escalation(
        all_events, verbose=args.verbose
    )
    print(f"{Fore.GREEN}      Found: {len(pe_findings)} finding(s)")

    print(f"{Fore.CYAN}  [*] Rule 3 - Account Lockouts (MITRE T1110.001)")
    al_findings = detect_account_lockout(
        all_events, verbose=args.verbose
    )
    print(f"{Fore.GREEN}      Found: {len(al_findings)} finding(s)")

    # ══════════════════════════════════════════
    # STEP 4 — Build alerts
    # ══════════════════════════════════════════
    section("STEP 4 - Building Alert Summary")
    alerts = build_alerts(bf_findings, pe_findings, al_findings)

    print_alerts(alerts)

    # ══════════════════════════════════════════
    # STEP 5 — Generate report
    # ══════════════════════════════════════════
    section("STEP 5 - Generating HTML Report", Fore.GREEN)
    os.makedirs("output", exist_ok=True)
    output_path = os.path.join("output", args.output)
    elapsed     = round(time.time() - start_time, 1)

    generate_report(
        output_path    = output_path,
        scan_time      = scan_time,
        elapsed        = elapsed,
        windows_file   = args.windows or "",
        linux_file     = args.linux or "",
        total_events   = len(all_events),
        windows_count  = len(windows_events),
        linux_count    = len(linux_events),
        alerts         = alerts,
        bf_findings    = bf_findings,
        pe_findings    = pe_findings,
        al_findings    = al_findings,
    )

    critical = sum(1 for a in alerts if a["severity"] in ("Critical", "High"))
    medium   = sum(1 for a in alerts if a["severity"] == "Medium")
    low      = sum(1 for a in alerts if a["severity"] == "Low")

    print(f"\n{Fore.CYAN}[*] Analysis complete in {elapsed}s")
    print(f"[*] Total alerts : {len(alerts)}")
    print(f"    {Fore.RED}Critical/High : {critical}")
    print(f"    {Fore.YELLOW}Medium        : {medium}")
    print(f"    {Fore.BLUE}Low           : {low}")
    print(f"\n{Fore.GREEN}[*] Report saved to: {output_path}")
    print(f"    Open in your browser to view the dashboard.\n")


if __name__ == "__main__":
    main()
