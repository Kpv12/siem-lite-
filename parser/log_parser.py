"""
SIEM Lite — Phase 1: Log Parser
================================
Parses raw Linux log files into normalized, structured event objects.

Supports:
  - /var/log/auth.log  (SSH login events, sudo usage)
  - Apache/Nginx access.log (HTTP requests)

Each parsed event becomes a Python dict with a consistent schema:
  {
    "timestamp": "2026-05-12 10:21:01",
    "source_ip": "45.33.32.156",
    "event_type": "SSH_FAILED_LOGIN",
    "user": "root",
    "status": "FAILURE",
    "raw": "<original log line>",
    "log_source": "auth"
  }

WHY THIS MATTERS:
  Normalization is the foundation of any SIEM. Once all events share
  the same schema, your detection engine doesn't need to care about
  WHERE the event came from — it just queries the fields it needs.
"""

import re
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────
#  REGEX PATTERNS
#  Each pattern targets a specific log format.
#  We use named groups (?P<name>) so we can
#  reference fields by name, not position.
# ─────────────────────────────────────────────

# auth.log — SSH failed password
# Example: May 12 10:21:01 server sshd[1001]: Failed password for root from 45.33.32.156 port 4444 ssh2
PATTERN_SSH_FAILED = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)"
    r".+Failed password for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# auth.log — SSH accepted login
# Example: May 12 10:22:00 server sshd[1002]: Accepted password for varun from 192.168.1.10 port 22 ssh2
PATTERN_SSH_ACCEPTED = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)"
    r".+Accepted (?:password|publickey) for (?P<user>\S+)"
    r" from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# auth.log — Invalid user attempt
# Example: May 12 10:26:00 server sshd[1006]: Invalid user hacker from 203.0.113.42 port 9999
PATTERN_SSH_INVALID_USER = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)"
    r".+Invalid user (?P<user>\S+)"
    r" from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# auth.log — Sudo command execution
# Example: May 12 10:25:00 server sudo[1005]: varun : ... COMMAND=/bin/bash
PATTERN_SUDO = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)"
    r".+sudo.+?:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)"
)

# access.log — Apache/Nginx HTTP request (Combined Log Format)
# Example: 45.33.32.156 - - [12/May/2026:10:20:01 +0000] "GET /admin HTTP/1.1" 404 512
PATTERN_HTTP = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+).+\[(?P<datetime>[^\]]+)\]"
    r'\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"'
    r'\s+(?P<status_code>\d+)\s+(?P<bytes>\d+)'
)


# ─────────────────────────────────────────────
#  HELPER: Normalize timestamp strings
#  into consistent "YYYY-MM-DD HH:MM:SS" format
# ─────────────────────────────────────────────

MONTH_MAP = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"
}

def normalize_auth_timestamp(month: str, day: str, time: str) -> str:
    """Convert 'May 12 10:21:01' → '2026-05-12 10:21:01'"""
    year = datetime.now().year
    month_num = MONTH_MAP.get(month, "00")
    return f"{year}-{month_num}-{int(day):02d} {time}"

def normalize_http_timestamp(raw: str) -> str:
    """Convert '12/May/2026:10:20:01 +0000' → '2026-05-12 10:20:01'"""
    try:
        dt = datetime.strptime(raw.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw


# ─────────────────────────────────────────────
#  CORE PARSERS
#  Each function handles one log source type.
#  Returns a list of normalized event dicts.
# ─────────────────────────────────────────────

def parse_auth_log(filepath: str) -> list[dict]:
    """
    Parse /var/log/auth.log
    Detects: SSH failures, successes, invalid users, sudo usage
    """
    events = []

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            event = None

            # Try each pattern in priority order
            if m := PATTERN_SSH_FAILED.search(line):
                event = {
                    "timestamp": normalize_auth_timestamp(m["month"], m["day"], m["time"]),
                    "source_ip": m["ip"],
                    "event_type": "SSH_FAILED_LOGIN",
                    "user": m["user"],
                    "status": "FAILURE",
                    "log_source": "auth",
                    "raw": line
                }

            elif m := PATTERN_SSH_ACCEPTED.search(line):
                event = {
                    "timestamp": normalize_auth_timestamp(m["month"], m["day"], m["time"]),
                    "source_ip": m["ip"],
                    "event_type": "SSH_ACCEPTED_LOGIN",
                    "user": m["user"],
                    "status": "SUCCESS",
                    "log_source": "auth",
                    "raw": line
                }

            elif m := PATTERN_SSH_INVALID_USER.search(line):
                event = {
                    "timestamp": normalize_auth_timestamp(m["month"], m["day"], m["time"]),
                    "source_ip": m["ip"],
                    "event_type": "SSH_INVALID_USER",
                    "user": m["user"],
                    "status": "FAILURE",
                    "log_source": "auth",
                    "raw": line
                }

            elif m := PATTERN_SUDO.search(line):
                event = {
                    "timestamp": normalize_auth_timestamp(m["month"], m["day"], m["time"]),
                    "source_ip": "localhost",
                    "event_type": "SUDO_COMMAND",
                    "user": m["user"],
                    "status": "INFO",
                    "detail": m["command"].strip(),
                    "log_source": "auth",
                    "raw": line
                }

            if event:
                events.append(event)

    return events


def parse_http_log(filepath: str) -> list[dict]:
    """
    Parse Apache/Nginx access.log (Combined Log Format)
    Detects: normal requests + flags suspicious paths
    """
    # Patterns in URLs that suggest attack activity
    SUSPICIOUS_PATTERNS = [
        r"(union\s+select|select\s+\*|or\s+'1'='1)",   # SQLi
        r"(<script|javascript:|onerror=)",               # XSS
        r"(\.\./|etc/passwd|/etc/shadow)",               # Path traversal
        r"(\.env|wp-admin|phpmyadmin|\.git)",            # Recon / sensitive files
    ]
    SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)

    events = []

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = PATTERN_HTTP.search(line)
            if not m:
                continue

            status_code = int(m["status_code"])
            path = m["path"]

            # Determine event type
            if SUSPICIOUS_RE.search(path):
                event_type = "HTTP_SUSPICIOUS_REQUEST"
                status = "ALERT"
            elif status_code >= 500:
                event_type = "HTTP_SERVER_ERROR"
                status = "WARNING"
            elif status_code == 404:
                event_type = "HTTP_NOT_FOUND"
                status = "INFO"
            elif status_code >= 400:
                event_type = "HTTP_CLIENT_ERROR"
                status = "WARNING"
            else:
                event_type = "HTTP_REQUEST"
                status = "SUCCESS"

            event = {
                "timestamp": normalize_http_timestamp(m["datetime"]),
                "source_ip": m["ip"],
                "event_type": event_type,
                "method": m["method"],
                "path": path,
                "status_code": status_code,
                "status": status,
                "log_source": "apache",
                "raw": line
            }
            events.append(event)

    return events


# ─────────────────────────────────────────────
#  UNIFIED ENTRY POINT
#  Auto-detects log type and routes to the
#  correct parser based on filename.
# ─────────────────────────────────────────────

def parse_log_file(filepath: str) -> list[dict]:
    """
    Auto-detect log type by filename and parse it.
    Returns a list of normalized event dicts.
    """
    fname = filepath.lower()

    if "auth" in fname:
        return parse_auth_log(filepath)
    elif "access" in fname:
        return parse_http_log(filepath)
    else:
        raise ValueError(f"Unknown log type for file: {filepath}. "
                         f"Filename must contain 'auth' or 'access'.")


# ─────────────────────────────────────────────
#  QUICK SELF-TEST  (run this file directly)
#  python3 parser/log_parser.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import os

    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auth_path   = os.path.join(BASE, "logs", "samples", "auth.log")
    access_path = os.path.join(BASE, "logs", "samples", "access.log")

    print("=" * 60)
    print("AUTH LOG EVENTS")
    print("=" * 60)
    auth_events = parse_auth_log(auth_path)
    for e in auth_events:
        print(json.dumps(e, indent=2))

    print("\n" + "=" * 60)
    print("HTTP LOG EVENTS")
    print("=" * 60)
    http_events = parse_http_log(access_path)
    for e in http_events:
        print(json.dumps(e, indent=2))

    print(f"\n✅ Total events parsed: {len(auth_events) + len(http_events)}")
    print(f"   Auth events : {len(auth_events)}")
    print(f"   HTTP events : {len(http_events)}")
