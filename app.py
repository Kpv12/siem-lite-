"""
SIEM Lite — Phase 4 (Updated): Flask Dashboard with File Upload
================================================================
"""

import os
import sys
import json
from flask import Flask, render_template, jsonify, request
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser.log_parser import parse_auth_log, parse_http_log
from detection.detection_engine import run_all_rules
from detection.threat_intel import enrich_alerts, boost_severity

app = Flask(__name__)

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE, "logs", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max


def process_logs(auth_path=None, access_path=None):
    """Parse logs, run detection, enrich with threat intel."""
    events = []

    if auth_path and os.path.exists(auth_path):
        events += parse_auth_log(auth_path)
    if access_path and os.path.exists(access_path):
        events += parse_http_log(access_path)

    # Fallback to sample logs if nothing uploaded
    if not events:
        sample_auth = os.path.join(BASE, "logs/samples/auth.log")
        sample_access = os.path.join(BASE, "logs/samples/access.log")
        if os.path.exists(sample_auth):
            events += parse_auth_log(sample_auth)
        if os.path.exists(sample_access):
            events += parse_http_log(sample_access)

    alerts = run_all_rules(events)
    alerts = enrich_alerts(alerts)
    alerts = [boost_severity(a) for a in alerts]
    return events, alerts


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/upload", methods=["POST"])
def upload_logs():
    """Handle log file uploads and return analysis results."""
    auth_path = None
    access_path = None

    if "auth_log" in request.files:
        f = request.files["auth_log"]
        if f.filename:
            filename = secure_filename(f.filename)
            auth_path = os.path.join(app.config["UPLOAD_FOLDER"], "auth.log")
            f.save(auth_path)

    if "access_log" in request.files:
        f = request.files["access_log"]
        if f.filename:
            filename = secure_filename(f.filename)
            access_path = os.path.join(app.config["UPLOAD_FOLDER"], "access.log")
            f.save(access_path)

    events, alerts = process_logs(auth_path, access_path)

    # Build summary
    summary = {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
        "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        "unique_attacker_ips": len(set(a["source_ip"] for a in alerts))
    }

    # Clean alerts for JSON
    clean_alerts = []
    for a in alerts:
        intel = a.get("threat_intel", {})
        clean_alerts.append({
            "alert": a["alert"],
            "severity": a["severity"],
            "source_ip": a["source_ip"],
            "description": a["description"],
            "fired_at": a["fired_at"],
            "abuse_score": intel.get("abuse_score", 0),
            "country": intel.get("country", "N/A"),
            "isp": intel.get("isp", "N/A"),
            "total_reports": intel.get("total_reports", 0),
            "evidence": a["evidence"][:1]
        })

    return jsonify({"summary": summary, "alerts": clean_alerts})


@app.route("/api/summary")
def api_summary():
    events, alerts = process_logs()
    return jsonify({
        "total_events": len(events),
        "total_alerts": len(alerts),
        "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
        "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        "unique_attacker_ips": len(set(a["source_ip"] for a in alerts))
    })


@app.route("/api/alerts")
def api_alerts():
    _, alerts = process_logs()
    clean = []
    for a in alerts:
        intel = a.get("threat_intel", {})
        clean.append({
            "alert": a["alert"],
            "severity": a["severity"],
            "source_ip": a["source_ip"],
            "description": a["description"],
            "fired_at": a["fired_at"],
            "abuse_score": intel.get("abuse_score", 0),
            "country": intel.get("country", "N/A"),
            "isp": intel.get("isp", "N/A"),
            "total_reports": intel.get("total_reports", 0),
            "evidence": a["evidence"][:1]
        })
    return jsonify(clean)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
