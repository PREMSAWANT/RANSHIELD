import os
import sys
import time
from flask import Flask, render_template, jsonify, send_file, request, make_response

from ranshield.config import DB_PATH, DEFAULT_WATCH_DIR
import ranshield.database as db

app = Flask(__name__)

# Ensure database is accessible
db.init_db()

@app.route('/')
def index():
    """Renders the main real-time dashboard."""
    return render_template('index.html')

@app.route('/dfir')
def dfir():
    """Renders the Digital Forensics and Incident Response view."""
    return render_template('dfir.html')

@app.route('/api/stats')
def api_stats():
    """Returns high-level statistics for the dashboard widgets."""
    try:
        stats = db.get_stats()
        # Add default directory info
        stats["watch_dir"] = DEFAULT_WATCH_DIR
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/events')
def api_events():
    """Returns the most recent file events."""
    try:
        limit = request.args.get('limit', 50, type=int)
        events = db.get_recent_events(limit)
        return jsonify(events)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/timeline')
def api_timeline():
    """Returns aggregated process metrics for the timeline graph."""
    try:
        timeline = db.get_process_timeline()
        return jsonify(timeline)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Returns historical threat containment alerts."""
    try:
        alerts = db.get_alerts()
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reset', methods=['POST'])
def api_reset():
    """Clears all monitoring data to reset the system for a new run."""
    try:
        db.clear_db()
        return jsonify({"status": "success", "message": "Database successfully reset."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/dfir/export')
def dfir_export():
    """Generates and downloads a structured Markdown forensic incident report."""
    try:
        alerts = db.get_alerts()
        events = db.get_recent_events(100)
        calibrated = db.get_process_timeline()
        
        report_lines = [
            "# RANSHIELD DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) REPORT",
            f"Generated At: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}",
            "========================================================================\n",
            "## 1. INCIDENT SUMMARY",
            f"Total Alerts Triggered: {len(alerts)}",
            f"Total File Events Captured: {len(events)}",
            f"Unique Processes Monitored: {len(calibrated)}\n",
            "## 2. CONTAINED THREATS"
        ]
        
        if not alerts:
            report_lines.append("No security threats or ransomware activities detected on this system.")
        else:
            for alert in alerts:
                ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert['timestamp']))
                report_lines.append(f"### [ALERT] Process PID {alert['pid']} - {os.path.basename(alert['exe_path'])}")
                report_lines.append(f"- **Timestamp:** {ts_str}")
                report_lines.append(f"- **Executable Path:** {alert['exe_path']}")
                report_lines.append(f"- **Threat Score (Sp):** {alert['threat_score']:.2f}")
                report_lines.append(f"- **Reason:** {alert['reason']}")
                report_lines.append(f"- **Containment Actions:** {alert['action_taken']}")
                report_lines.append("")

        report_lines.append("## 3. MONITORED PROCESS ACTIVITY TIMELINE")
        if not calibrated:
            report_lines.append("No process activity recorded.")
        else:
            report_lines.append("| PID | Process Name | File Event Count | Max Threat Score | Imposed Action |")
            report_lines.append("|---|---|---|---|---|")
            for proc in calibrated:
                report_lines.append(f"| {proc['pid']} | {os.path.basename(proc['exe_path'])} | {proc['event_count']} | {proc['max_threat']:.2f} | {proc['actions']} |")

        report_lines.append("\n## 4. DETAILED FILE EVENT LOG (LAST 100 EVENTS)")
        if not events:
            report_lines.append("No file events recorded.")
        else:
            report_lines.append("| Timestamp | PID | Process | Event Type | File Path | Before Entropy | After Entropy | Sp | Status |")
            report_lines.append("|---|---|---|---|---|---|---|---|---|")
            for e in events:
                ts_str = time.strftime('%H:%M:%S', time.localtime(e['timestamp']))
                name = os.path.basename(e['exe_path'])
                ent_before = f"{e['entropy_before']:.2f}" if e['entropy_before'] is not None else "0.00"
                ent_after = f"{e['entropy_after']:.2f}" if e['entropy_after'] is not None else "0.00"
                sp_str = f"{e['threat_score']:.2f}" if e['threat_score'] is not None else "0.00"
                report_lines.append(f"| {ts_str} | {e['pid']} | {name} | {e['event_type']} | {e['file_path']} | {ent_before} | {ent_after} | {sp_str} | {e['action_taken']} |")

        report_content = "\n".join(report_lines)
        
        response = make_response(report_content)
        response.headers['Content-Disposition'] = 'attachment; filename=ranshield_dfir_report.md'
        response.headers['Content-Type'] = 'text/markdown'
        return response
    except Exception as e:
        return f"Error generating DFIR report: {str(e)}", 500

def start_web_server(host="127.0.0.1", port=5000, debug=False):
    """Start the Flask development server."""
    app.run(host=host, port=port, debug=debug, use_reloader=False)
