"""
parsers/windows_parser.py
==========================
Parses Windows Event Log files in XML format.

Supports:
  - Exported .evtx converted to XML (via wevtutil or Event Viewer)
  - Direct XML exports from Windows Event Viewer
  - Single-event and multi-event XML files

Key Event IDs we care about:
  4624  — Successful logon
  4625  — Failed logon           → brute force detection
  4634  — Logoff
  4648  — Logon with explicit credentials
  4672  — Special privileges assigned  → privilege escalation
  4673  — Privileged service called
  4698  — Scheduled task created       → persistence indicator
  4720  — User account created
  4726  — User account deleted
  4740  — Account locked out           → lockout detection
  4756  — Member added to security group
  7045  — New service installed        → persistence indicator

Each parsed event is normalised into a dict:
  {
    "event_id"   : int,
    "timestamp"  : datetime object,
    "source"     : "windows",
    "channel"    : "Security" | "System" | ...,
    "computer"   : hostname string,
    "user"       : username (if present),
    "ip_address" : source IP (if present),
    "logon_type" : int (if logon event),
    "raw"        : original XML string snippet,
    "description": human-readable summary
  }
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from colorama import Fore


# ─────────────────────────────────────────────
# Event ID descriptions
# ─────────────────────────────────────────────

EVENT_DESCRIPTIONS = {
    4624: "Successful logon",
    4625: "Failed logon attempt",
    4634: "User logoff",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned to new logon",
    4673: "Privileged service called",
    4698: "Scheduled task created",
    4720: "User account created",
    4726: "User account deleted",
    4740: "User account locked out",
    4756: "Member added to security-enabled group",
    7045: "New service installed on system",
}

# Windows XML namespace
NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Logon type meanings
LOGON_TYPES = {
    2:  "Interactive (local keyboard)",
    3:  "Network (e.g. file share)",
    4:  "Batch (scheduled task)",
    5:  "Service",
    7:  "Unlock",
    8:  "NetworkCleartext",
    9:  "NewCredentials (runas)",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse Windows event timestamp string to datetime object."""
    if not ts_str:
        return datetime.now()
    # Windows format: 2026-03-29T14:22:31.123456789Z
    ts_str = ts_str.split(".")[0].replace("T", " ").replace("Z", "")
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.now()


def _find_first(parent, qname: str, plain: str | None = None):
    """Like find() but never use Element in boolean context (Python 3.13+ leaf elements are falsy)."""
    el = parent.find(qname, NS)
    if el is not None:
        return el
    if plain:
        return parent.find(plain)
    return None


def _get_data_value(event_data, name: str) -> str:
    """
    Extract a named Data element from EventData or UserData.
    Windows stores event details as <Data Name="FieldName">value</Data>
    """
    for data in event_data:
        if data.get("Name") == name:
            return (data.text or "").strip()
    return ""


def _parse_single_event(event_elem) -> dict | None:
    """Parse a single <Event> XML element into our normalised dict."""
    try:
        # System section — always present
        system = _find_first(event_elem, "w:System", "System")
        if system is None:
            return None

        # Event ID
        eid_elem = _find_first(system, "w:EventID", "EventID")
        if eid_elem is None:
            return None
        event_id = int(eid_elem.text or 0)

        # Timestamp
        time_created = _find_first(system, "w:TimeCreated", "TimeCreated")
        ts_str = time_created.get("SystemTime", "") if time_created is not None else ""
        timestamp = _parse_timestamp(ts_str)

        # Channel
        channel_elem = _find_first(system, "w:Channel", "Channel")
        channel = channel_elem.text if channel_elem is not None else "Unknown"

        # Computer
        computer_elem = _find_first(system, "w:Computer", "Computer")
        computer = computer_elem.text if computer_elem is not None else "Unknown"

        # EventData — the specific fields for this event type
        event_data = _find_first(event_elem, "w:EventData", "EventData")
        data_items = list(event_data) if event_data is not None else []

        # Extract common fields
        user       = _get_data_value(data_items, "TargetUserName") or \
                     _get_data_value(data_items, "SubjectUserName") or ""
        ip_address = _get_data_value(data_items, "IpAddress") or \
                     _get_data_value(data_items, "SourceAddress") or ""
        domain     = _get_data_value(data_items, "TargetDomainName") or \
                     _get_data_value(data_items, "SubjectDomainName") or ""

        # Logon type (events 4624, 4625)
        lt_str     = _get_data_value(data_items, "LogonType")
        logon_type = int(lt_str) if lt_str.isdigit() else 0

        # Privileges (event 4672)
        privileges = _get_data_value(data_items, "PrivilegeList")

        # Group name (event 4756 — prefer GroupName over TargetUserName)
        group_name = _get_data_value(data_items, "GroupName") or \
                     _get_data_value(data_items, "TargetUserName") or ""

        # Service name (event 7045)
        service_name = _get_data_value(data_items, "ServiceName") or ""

        # Clean up IP
        if ip_address in ("-", "::1", "127.0.0.1", "LOCAL"):
            ip_address = "local"

        description = EVENT_DESCRIPTIONS.get(event_id, f"Event {event_id}")

        return {
            "event_id"   : event_id,
            "timestamp"  : timestamp,
            "source"     : "windows",
            "channel"    : channel,
            "computer"   : computer,
            "user"       : user,
            "domain"     : domain,
            "ip_address" : ip_address,
            "logon_type" : logon_type,
            "logon_type_desc": LOGON_TYPES.get(logon_type, ""),
            "privileges" : privileges,
            "group_name" : group_name,
            "service_name": service_name,
            "description": description,
        }

    except Exception as e:
        return None


def parse_windows_events(file_path: str, verbose: bool = False) -> list:
    """
    Parse a Windows Event Log XML file.

    Handles two formats:
      1. Full export with <Events> root element containing multiple <Event> tags
      2. Single <Event> root element

    Parameters
    ----------
    file_path : str  — path to .xml file
    verbose   : bool — print each parsed event

    Returns
    -------
    list of normalised event dicts
    """
    events = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"{Fore.RED}[!] XML parse error in {file_path}: {e}")
        return events

    # Strip namespace from tag for comparison
    tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag

    if tag == "Events":
        # Multi-event export
        event_elems = root.findall("w:Event", NS)
        if not event_elems:
            event_elems = root.findall("Event")
    elif tag == "Event":
        # Single event
        event_elems = [root]
    else:
        # Try finding Event elements anywhere in the tree
        event_elems = root.findall(".//Event")

    for elem in event_elems:
        parsed = _parse_single_event(elem)
        if parsed:
            events.append(parsed)
            if verbose:
                print(
                    f"{Fore.CYAN}    [win] {parsed['timestamp'].strftime('%H:%M:%S')} "
                    f"EventID:{parsed['event_id']} "
                    f"User:{parsed['user'] or 'N/A'} "
                    f"IP:{parsed['ip_address'] or 'N/A'}"
                )

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])

    # Print event ID summary
    from collections import Counter
    counts = Counter(e["event_id"] for e in events)
    for eid, cnt in sorted(counts.items()):
        desc = EVENT_DESCRIPTIONS.get(eid, f"Unknown event")
        print(f"{Fore.CYAN}    EventID {eid}: {cnt:>4} event(s)  - {desc}")

    return events
