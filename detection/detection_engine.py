"""
SIEM Lite — Phase 2: Detection Engine
=======================================
Consumes normalized events from the parser and fires alerts
when suspicious patterns are detected.

Detection Rules:
  1. BRUTE_FORCE        — 5+ failed logins from same IP within 60 seconds
  2. CREDENTIAL_STUFF   — same IP trying 3+ different usernames
  3. WEB_RECON          — same IP hitting 5+ 404s within 60 seconds
  4. INJECTION_ATTACK   — SQLi or XSS pattern in HTTP request
  5. PRIV_ESCALATION    — sudo to /bin/bash after SSH login

WHY THIS MATTERS:
  Rule-based detection is the foundation of every SIEM.
  You're essentially writing mini threat detection logic that
  mirrors what Splunk, Microsoft Sentinel, and QRadar do —
  just without the enterprise price tag.
"""

from datetime import datetime
from collections import defaultdict
from typing import List, Dict


# ─────────────────────────────────────────────
#  ALERT STRUCTURE
#  Every fired rule produces one of these.
# ─────────────────────────────────────────────

def make_alert(rule: str, severity: str, source_ip: str, description: str, evidence: list) -> dict:
    return {
        "alert": rule,
        "severity": severity,       # CRITICAL / HIGH / MEDIUM
        "source_ip": source_ip,
        "description": description,
        "evidence": evidence,       # the raw log lines that triggered it
        "fired_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# ─────────────────────────────────────────────
#  HELPER: parse timestamp string → datetime
# ─────────────────────────────────────────────

def to_dt(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────
#  RULE 1: BRUTE FORCE DETECTION
#  Trigger: 5+ SSH failed logins from same IP
#  within a 60 second window
#
#  How it works:
#  Group failures by IP. Slide a time window across
#  the timestamps. If 5 fit inside 60s → alert.
# ─────────────────────────────────────────────

def detect_brute_force(events: List[Dict], threshold=5, window_seconds=60) -> List[Dict]:
    alerts = []

    # Group failed login events by IP
    failures_by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] in ("SSH_FAILED_LOGIN", "SSH_INVALID_USER"):
            failures_by_ip[e["source_ip"]].append(e)

    for ip, failures in failures_by_ip.items():
        # Sort by time
        failures.sort(key=lambda x: x["timestamp"])
        timestamps = [to_dt(f["timestamp"]) for f in failures]

        # Sliding window check
        for i in range(len(timestamps)):
            window = [
                timestamps[j] for j in range(i, len(timestamps))
                if (timestamps[j] - timestamps[i]).total_seconds() <= window_seconds
            ]
            if len(window) >= threshold:
                evidence = [failures[j]["raw"] for j in range(i, i + len(window))]
                alerts.append(make_alert(
                    rule="BRUTE_FORCE",
                    severity="CRITICAL",
                    source_ip=ip,
                    description=f"{len(window)} failed SSH logins from {ip} within {window_seconds}s",
                    evidence=evidence[:5]  # show first 5
                ))
                break  # one alert per IP

    return alerts


# ─────────────────────────────────────────────
#  RULE 2: CREDENTIAL STUFFING
#  Trigger: same IP tries 3+ different usernames
#
#  Different from brute force — attacker is
#  trying known username/password combos across
#  many accounts rather than hammering one account
# ─────────────────────────────────────────────

def detect_credential_stuffing(events: List[Dict], threshold=3) -> List[Dict]:
    alerts = []

    usernames_by_ip = defaultdict(set)
    evidence_by_ip = defaultdict(list)

    for e in events:
        if e["event_type"] in ("SSH_FAILED_LOGIN", "SSH_INVALID_USER"):
            ip = e["source_ip"]
            usernames_by_ip[ip].add(e.get("user", "unknown"))
            evidence_by_ip[ip].append(e["raw"])

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= threshold:
            alerts.append(make_alert(
                rule="CREDENTIAL_STUFFING",
                severity="HIGH",
                source_ip=ip,
                description=f"{ip} attempted {len(usernames)} different usernames: {', '.join(usernames)}",
                evidence=evidence_by_ip[ip]
            ))

    return alerts


# ─────────────────────────────────────────────
#  RULE 3: WEB RECON SWEEP
#  Trigger: same IP hits 5+ 404 pages within 60s
#
#  Attackers scan for hidden paths like /admin,
#  /.env, /backup.zip before exploiting.
#  Rapid 404s = automated scanner or manual recon.
# ─────────────────────────────────────────────

def detect_web_recon(events: List[Dict], threshold=3, window_seconds=60) -> List[Dict]:
    alerts = []

    recon_by_ip = defaultdict(list)
    for e in events:
        if e["event_type"] in ("HTTP_NOT_FOUND", "HTTP_SUSPICIOUS_REQUEST"):
            recon_by_ip[e["source_ip"]].append(e)

    for ip, hits in recon_by_ip.items():
        hits.sort(key=lambda x: x["timestamp"])
        timestamps = [to_dt(h["timestamp"]) for h in hits]

        for i in range(len(timestamps)):
            window = [
                timestamps[j] for j in range(i, len(timestamps))
                if (timestamps[j] - timestamps[i]).total_seconds() <= window_seconds
            ]
            if len(window) >= threshold:
                paths = [hits[j].get("path", "") for j in range(i, i + len(window))]
                evidence = [hits[j]["raw"] for j in range(i, i + len(window))]
                alerts.append(make_alert(
                    rule="WEB_RECON_SWEEP",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"{ip} hit {len(window)} suspicious/missing paths in {window_seconds}s: {', '.join(paths)}",
                    evidence=evidence
                ))
                break

    return alerts


# ─────────────────────────────────────────────
#  RULE 4: INJECTION ATTACK
#  Trigger: HTTP request flagged as suspicious
#  (SQLi, XSS, path traversal already caught
#   by parser — we just escalate them here)
# ─────────────────────────────────────────────

def detect_injection(events: List[Dict]) -> List[Dict]:
    alerts = []

    for e in events:
        if e["event_type"] == "HTTP_SUSPICIOUS_REQUEST":
            path = e.get("path", "")

            # Classify the injection type
            if any(x in path.lower() for x in ["union", "select", "or '1'", "null--"]):
                attack_type = "SQL Injection"
                severity = "CRITICAL"
            elif any(x in path.lower() for x in ["<script", "javascript:", "onerror"]):
                attack_type = "XSS"
                severity = "HIGH"
            elif any(x in path.lower() for x in ["etc/passwd", "etc/shadow", "../"]):
                attack_type = "Path Traversal"
                severity = "CRITICAL"
            else:
                attack_type = "Suspicious Request"
                severity = "MEDIUM"

            alerts.append(make_alert(
                rule="INJECTION_ATTACK",
                severity=severity,
                source_ip=e["source_ip"],
                description=f"{attack_type} attempt from {e['source_ip']} → {path}",
                evidence=[e["raw"]]
            ))

    return alerts


# ─────────────────────────────────────────────
#  RULE 5: PRIVILEGE ESCALATION
#  Trigger: sudo /bin/bash executed
#
#  Running sudo bash gives full root shell.
#  Legitimate admins rarely do this in production.
#  Attackers do it immediately after gaining access.
# ─────────────────────────────────────────────

def detect_privesc(events: List[Dict]) -> List[Dict]:
    alerts = []

    for e in events:
        if e["event_type"] == "SUDO_COMMAND":
            cmd = e.get("detail", "")
            if any(shell in cmd for shell in ["/bin/bash", "/bin/sh", "/bin/zsh"]):
                alerts.append(make_alert(
                    rule="PRIVILEGE_ESCALATION",
                    severity="CRITICAL",
                    source_ip=e["source_ip"],
                    description=f"User '{e['user']}' spawned root shell via sudo: {cmd}",
                    evidence=[e["raw"]]
                ))

    return alerts


# ─────────────────────────────────────────────
#  MASTER FUNCTION
#  Run all rules against a list of events.
#  Returns all alerts sorted by severity.
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

def run_all_rules(events: List[Dict]) -> List[Dict]:
    alerts = []
    alerts += detect_brute_force(events)
    alerts += detect_credential_stuffing(events)
    alerts += detect_web_recon(events)
    alerts += detect_injection(events)
    alerts += detect_privesc(events)

    # Sort by severity
    alerts.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return alerts


# ─────────────────────────────────────────────
#  SELF TEST — python3 detection/detection_engine.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from parser.log_parser import parse_auth_log, parse_http_log

    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auth_events = parse_auth_log(os.path.join(BASE, "logs/samples/auth.log"))
    http_events = parse_http_log(os.path.join(BASE, "logs/samples/access.log"))
    all_events = auth_events + http_events

    print(f"Total events loaded: {len(all_events)}\n")

    alerts = run_all_rules(all_events)

    print("=" * 60)
    print(f"ALERTS FIRED: {len(alerts)}")
    print("=" * 60)

    for a in alerts:
        print(f"\n🚨 [{a['severity']}] {a['alert']}")
        print(f"   IP          : {a['source_ip']}")
        print(f"   Description : {a['description']}")
        print(f"   Fired at    : {a['fired_at']}")
        print(f"   Evidence    :")
        for line in a['evidence'][:2]:
            print(f"     → {line}")
