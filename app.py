"""
SIEM Lite — Phase 4: Flask Dashboard
======================================
Serves a live web dashboard showing alerts,
threat intel, and event statistics.
"""

import os
import sys
import json
from flask import Flask, render_template, jsonify

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser.log_parser import parse_auth_log, parse_http_log
from detection.detection_engine import run_all_rules
from detection.threat_intel import enrich_alerts, boost_severity

app = Flask(__name__)

BASE = os.path.dirname(os.path.abspath(__file__))


def load_data():
    """Parse logs, run detection, enrich with threat intel."""
    events = parse_auth_log(os.path.join(BASE, "logs/samples/auth.log"))
    events += parse_http_log(os.path.join(BASE, "logs/samples/access.log"))
    alerts = run_all_rules(events)
    alerts = enrich_alerts(alerts)
    alerts = [boost_severity(a) for a in alerts]
    return events, alerts


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/summary")
def api_summary():
    events, alerts = load_data()
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    medium = sum(1 for a in alerts if a["severity"] == "MEDIUM")
    unique_ips = len(set(a["source_ip"] for a in alerts))
    return jsonify({
        "total_events": len(events),
        "total_alerts": len(alerts),
        "critical": critical,
        "high": high,
        "medium": medium,
        "unique_attacker_ips": unique_ips
    })


@app.route("/api/alerts")
def api_alerts():
    _, alerts = load_data()
    # Clean for JSON serialization
    clean = []
    for a in alerts:
        intel = a.get("threat_intel", {})
        clean.append({
            "alert": a["alert"],
            "severity": a["severity"],
            "source_ip": a["source_ip"],
            "description": a["description"],
            "fired_at": a["fired_at"],
            "abuse_score": intel.get("abuse_score", "N/A"),
            "country": intel.get("country", "N/A"),
            "isp": intel.get("isp", "N/A"),
            "total_reports": intel.get("total_reports", "N/A"),
            "evidence": a["evidence"][:1]
        })
    return jsonify(clean)


@app.route("/api/events")
def api_events():
    events, _ = load_data()
    return jsonify(events[:50])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
