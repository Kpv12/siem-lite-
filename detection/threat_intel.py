"""
SIEM Lite — Phase 3: Threat Intelligence Enrichment
=====================================================
Takes IPs from fired alerts and enriches them with
real-world threat data from AbuseIPDB.

WHY THIS MATTERS:
  Any IP can show up in your logs. Enrichment tells you
  INSTANTLY if that IP is a known global threat actor —
  saving analysts hours of manual research.
"""

import os
import requests
from dotenv import load_dotenv

# Load API key from .env file — never hardcode keys
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))
API_KEY = os.getenv("ABUSEIPDB_API_KEY")


# ─────────────────────────────────────────────
#  CORE FUNCTION: Check one IP against AbuseIPDB
# ─────────────────────────────────────────────

def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for threat intel on a given IP.
    Returns a dict with enrichment data.
    """

    # Skip private/localhost IPs — no point checking these
    private_prefixes = ("192.168.", "10.", "172.", "127.", "localhost")
    if any(ip.startswith(p) for p in private_prefixes):
        return {
            "ip": ip,
            "is_private": True,
            "abuse_score": 0,
            "total_reports": 0,
            "country": "Private Network",
            "last_reported": "N/A",
            "isp": "Internal",
            "enriched": False
        }

    if not API_KEY:
        return {"ip": ip, "error": "No API key found in .env", "enriched": False}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "is_private": False,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "last_reported": data.get("lastReportedAt", "Never")[:10] if data.get("lastReportedAt") else "Never",
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "enriched": True
            }
        else:
            return {"ip": ip, "error": f"API error {response.status_code}", "enriched": False}

    except requests.exceptions.RequestException as e:
        return {"ip": ip, "error": str(e), "enriched": False}


# ─────────────────────────────────────────────
#  ENRICH ALERTS
#  Takes your alert list from detection engine
#  and adds threat intel to each one.
# ─────────────────────────────────────────────

def enrich_alerts(alerts: list) -> list:
    """
    Add AbuseIPDB data to each alert.
    Deduplicates IP lookups so we don't waste API calls.
    """
    # Cache results so same IP isn't looked up twice
    cache = {}
    enriched = []

    for alert in alerts:
        ip = alert["source_ip"]

        if ip not in cache:
            print(f"   🔍 Looking up {ip}...")
            cache[ip] = check_ip(ip)

        alert["threat_intel"] = cache[ip]
        enriched.append(alert)

    return enriched


# ─────────────────────────────────────────────
#  SEVERITY BOOSTER
#  If AbuseIPDB confirms IP is malicious,
#  upgrade the alert severity automatically.
# ─────────────────────────────────────────────

def boost_severity(alert: dict) -> dict:
    """
    Upgrade severity if threat intel confirms malicious IP.
    MEDIUM → HIGH if abuse score > 50
    HIGH → CRITICAL if abuse score > 80
    """
    intel = alert.get("threat_intel", {})
    score = intel.get("abuse_score", 0)

    if score > 80 and alert["severity"] == "HIGH":
        alert["severity"] = "CRITICAL"
        alert["severity_boosted"] = True
    elif score > 50 and alert["severity"] == "MEDIUM":
        alert["severity"] = "HIGH"
        alert["severity_boosted"] = True
    else:
        alert["severity_boosted"] = False

    return alert


# ─────────────────────────────────────────────
#  SELF TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from parser.log_parser import parse_auth_log, parse_http_log
    from detection.detection_engine import run_all_rules

    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    events = parse_auth_log(os.path.join(BASE, "logs/samples/auth.log"))
    events += parse_http_log(os.path.join(BASE, "logs/samples/access.log"))

    alerts = run_all_rules(events)

    print(f"Enriching {len(alerts)} alerts...\n")
    alerts = enrich_alerts(alerts)
    alerts = [boost_severity(a) for a in alerts]

    print("\n" + "=" * 60)
    print("ENRICHED ALERTS")
    print("=" * 60)

    for a in alerts:
        intel = a.get("threat_intel", {})
        boosted = " ⬆ BOOSTED" if a.get("severity_boosted") else ""
        print(f"\n🚨 [{a['severity']}]{boosted} {a['alert']}")
        print(f"   IP          : {a['source_ip']}")
        print(f"   Description : {a['description']}")
        if intel.get("enriched"):
            print(f"   Abuse Score : {intel['abuse_score']}%")
            print(f"   Reports     : {intel['total_reports']}")
            print(f"   Country     : {intel['country']}")
            print(f"   ISP         : {intel['isp']}")
            print(f"   Last Seen   : {intel['last_reported']}")
        elif intel.get("is_private"):
            print(f"   Intel       : Private/internal IP — skipped")
        else:
            print(f"   Intel       : {intel.get('error', 'unavailable')}")
