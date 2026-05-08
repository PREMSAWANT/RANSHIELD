import os
import sys
import time
import zipfile
import shutil
from flask import Flask, render_template, jsonify, send_file, request, make_response, current_app

import ranshield.config as config
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

@app.route('/policies', methods=['GET', 'POST'])
def policies_page():
    """Renders the Policies and Custom Threshold Rules view, and handles setting saves."""
    if request.method == 'POST':
        try:
            # Load current JSON values to merge
            config.load_policies()
            
            # Fetch values from forms
            mode = request.form.get('containment_mode', config.CONTAINMENT_MODE)
            entropy_thresh = float(request.form.get('entropy_threshold_default', config.DEFAULT_ENTROPY_THRESHOLD))
            io_thresh = float(request.form.get('io_rate_threshold_mb', config.IO_RATE_THRESHOLD / (1024 * 1024)))
            web_url = request.form.get('webhook_url', config.WEBHOOK_URL)
            email_addr = request.form.get('smtp_email', config.SMTP_EMAIL)
            
            # Watch directories list (comma separated text area)
            watch_dirs_text = request.form.get('watch_directories', '')
            watch_dirs = [path.strip() for path in watch_dirs_text.split(',') if path.strip()]
            if not watch_dirs:
                watch_dirs = config.WATCH_DIRECTORIES
                
            # Rule weights (Layer 3)
            rule_weights = {}
            for key in config.WEIGHTS.keys():
                form_val = request.form.get(f'weight_{key}')
                if form_val is not None:
                    rule_weights[key] = float(form_val)
                else:
                    rule_weights[key] = config.WEIGHTS[key]
                    
            # Write to policies.json and update global state
            config.save_policies(
                mode=mode, 
                watch_dirs=watch_dirs, 
                rule_weights=rule_weights, 
                entropy_thresh=entropy_thresh, 
                io_thresh=io_thresh, 
                web_url=web_url, 
                email=email_addr
            )
            
            # Force dynamic reload of directories on the watchdog monitor
            if "AGENT" in current_app.config and current_app.config["AGENT"]:
                current_app.config["AGENT"].reload_watch_directories()
                
            return render_template('policies.html', success=True, config=config)
        except Exception as e:
            return render_template('policies.html', error=str(e), config=config)
            
    return render_template('policies.html', config=config)

@app.route('/vault')
def vault_page():
    """Renders the Quarantine Vault and malware signature scanner views."""
    return render_template('vault.html')

@app.route('/calibrator')
def calibrator_page():
    """Renders the Workload Profiler and Adaptive Calibrator views."""
    return render_template('calibrator.html')


# --- TELEMETRY API ENDPOINTS ---

@app.route('/api/stats')
def api_stats():
    """Returns high-level statistics for dashboard widgets."""
    try:
        stats = db.get_stats()
        stats["watch_dir"] = config.WATCH_DIRECTORIES[0] if config.WATCH_DIRECTORIES else "None"
        stats["containment_mode"] = config.CONTAINMENT_MODE
        
        # Add calibration status
        if "CALIBRATION_MGR" in current_app.config and current_app.config["CALIBRATION_MGR"]:
            stats["is_calibrating"] = current_app.config["CALIBRATION_MGR"].is_calibrating
        else:
            stats["is_calibrating"] = False
            
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
    """Returns aggregated process metrics for timeline visualizers."""
    try:
        timeline = db.get_process_timeline()
        return jsonify(timeline)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Returns historical threat alerts."""
    try:
        alerts = db.get_alerts()
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reset', methods=['POST'])
def api_reset():
    """Clears all event log history to reset the system console."""
    try:
        db.clear_db()
        return jsonify({"status": "success", "message": "Database cleared successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- QUARANTINE VAULT API ENDPOINTS ---

@app.route('/api/vault')
def api_vault_list():
    """Returns a list of quarantined binaries in the database."""
    try:
        items = db.get_quarantine_items()
        return jsonify(items)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault/release', methods=['POST'])
def api_vault_release():
    """Moves a quarantined binary back to its original path (simulated restoration/exclusion)."""
    try:
        data = request.json or {}
        qid = data.get('quarantine_id')
        if not qid:
            return jsonify({"error": "Missing quarantine_id parameter."}), 400
            
        item = db.get_quarantine_item_by_id(qid)
        if not item:
            return jsonify({"error": "Quarantined item not found."}), 404
            
        q_path = item['quarantine_path']
        o_path = item['original_path']
        
        if not os.path.exists(q_path):
            return jsonify({"error": "Quarantined file missing from vault directory."}), 410
            
        # Ensure original directory exists
        os.makedirs(os.path.dirname(o_path), exist_ok=True)
        
        # Move back
        shutil.move(q_path, o_path)
        db.update_quarantine_status(qid, 'RELEASED')
        
        # Log event of release
        db.log_event(item['pid'], o_path, o_path, "RELEASE", 0.0, 0.0, 0.0, "RELEASED_FROM_QUARANTINE")
        
        return jsonify({"status": "success", "message": f"Successfully restored {os.path.basename(o_path)} to its original path."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault/virustotal', methods=['POST'])
def api_vault_virustotal():
    """Simulates submitting the quarantined file hash to VirusTotal threat intelligence database."""
    try:
        data = request.json or {}
        qid = data.get('quarantine_id')
        if not qid:
            return jsonify({"error": "Missing quarantine_id parameter."}), 400
            
        item = db.get_quarantine_item_by_id(qid)
        if not item:
            return jsonify({"error": "Quarantined item not found."}), 404
            
        db.update_quarantine_status(qid, 'SUBMITTED')
        
        # Create a realistic threat signature result
        filename = item['original_name']
        file_hash = item['file_hash']
        
        import random
        scores = [
            {"engines": "58/72", "tag": "Trojan.Win32.Ransomware.Lockbit", "family": "Lockbit 3.0"},
            {"engines": "61/72", "tag": "Trojan-Ransom.Win32.WannaCry.m", "family": "WannaCry"},
            {"engines": "52/70", "tag": "Win32/Filecoder.Sodinokibi.A", "family": "REvil / Sodinokibi"},
            {"engines": "48/72", "tag": "Trojan.Win64.Ransom.Maze", "family": "Maze Ransomware"}
        ]
        
        # Pick signature based on hash seed to stay deterministic for the same file
        seed = sum(ord(c) for c in file_hash)
        vt_data = scores[seed % len(scores)]
        
        response_payload = {
            "status": "success",
            "filename": filename,
            "hash": file_hash,
            "detections": vt_data["engines"],
            "classification": vt_data["tag"],
            "malware_family": vt_data["family"],
            "scan_date": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        }
        return jsonify(response_payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- ADAPTIVE CALIBRATOR API ENDPOINTS ---

@app.route('/api/calibrator')
def api_calibrator_status():
    """Returns current calibration stats, thresholds, and profiled processes list."""
    try:
        mgr = current_app.config.get("CALIBRATION_MGR")
        if not mgr:
            return jsonify({"error": "Calibration manager is offline."}), 503
            
        conn = db.sqlite3.connect(config.DB_PATH)
        conn.row_factory = db.sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM process_calibration")
        calibrated_items = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            "is_calibrating": mgr.is_calibrating,
            "calibration_progress": mgr.get_progress_percent(),
            "profiled_processes_count": len(calibrated_items),
            "profiled_processes": calibrated_items
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/calibrator/recalibrate', methods=['POST'])
def api_calibrator_recalibrate():
    """Forces the security agent to reset calibration parameters and start profiling again."""
    try:
        mgr = current_app.config.get("CALIBRATION_MGR")
        if not mgr:
            return jsonify({"error": "Calibration manager is offline."}), 503
            
        # Restart calibration
        mgr.start_calibration()
        
        # Clear calibration table
        conn = db.sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM process_calibration")
        conn.commit()
        conn.close()
        
        # Launch countdown timer thread
        import threading
        from main import run_calibration_timer
        cal_thread = threading.Thread(target=run_calibration_timer, args=(mgr,), daemon=True)
        cal_thread.start()
        
        return jsonify({"status": "success", "message": "Recalibration initiated. Profiling active for next 60 seconds."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- FORENSICS RESTORE API ENDPOINT ---

@app.route('/api/restore', methods=['POST'])
def api_restore_watch_dir():
    """
    Self-Healing Recovery Control:
    Looks for the latest fallback snapshot zip, unzips it back into the watch folder,
    and returns a summary of restored files.
    """
    try:
        backup_dir = os.path.join(os.path.dirname(config.DEFAULT_WATCH_DIR), "RanShield_Backups")
        if not os.path.exists(backup_dir):
            return jsonify({"error": "No backup recovery archives exist. You must trigger an alert to generate backup checkpoints."}), 404
            
        zips = [os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if f.endswith('.zip')]
        if not zips:
            return jsonify({"error": "No snapshot recovery files (.zip) located in backup vaults."}), 404
            
        # Get the latest backup zip
        latest_zip = max(zips, key=os.path.getctime)
        
        restored_files = []
        with zipfile.ZipFile(latest_zip, 'r') as zip_ref:
            # We restore back to config.DEFAULT_WATCH_DIR
            target_dir = config.DEFAULT_WATCH_DIR
            os.makedirs(target_dir, exist_ok=True)
            
            # Extract
            zip_ref.extractall(target_dir)
            restored_files = zip_ref.namelist()
            
        # Log self-healing restore event
        db.log_event(os.getpid(), sys.executable, target_dir, "RESTORE", 0.0, 0.0, 0.0, "SELF_HEALING_RESTORE_COMPLETE")
        
        return jsonify({
            "status": "success",
            "archive": os.path.basename(latest_zip),
            "restored_count": len(restored_files),
            "files": restored_files,
            "message": f"Self-healing complete. Restored {len(restored_files)} files back to their healthy pre-encryption states!"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/dfir/export')
def dfir_export():
    """Generates and downloads a structured Markdown forensic incident report."""
    try:
        alerts = db.get_alerts()
        events = db.get_recent_events(100)
        calibrated = db.get_process_timeline()
        q_vault = db.get_quarantine_items()
        
        report_lines = [
            "# RANSHIELD DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) REPORT",
            f"Generated At: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}",
            "========================================================================\n",
            "## 1. INCIDENT SUMMARY",
            f"Total Alerts Triggered: {len(alerts)}",
            f"Total File Events Captured: {len(events)}",
            f"Quarantined Threat Binaries: {len(q_vault)}",
            f"Unique Processes Monitored: {len(calibrated)}\n",
            "## 2. QUARANTINED THREAT VAULT"
        ]
        
        if not q_vault:
            report_lines.append("No executables quarantined on this endpoint.")
        else:
            report_lines.append("| Name | Original Path | SHA-256 Hash | File Size | Status |")
            report_lines.append("|---|---|---|---|---|")
            for q in q_vault:
                report_lines.append(f"| {q['original_name']} | {q['original_path']} | `{q['file_hash']}` | {q['file_size']} bytes | {q['status']} |")
                
        report_lines.append("\n## 3. CONVENTIONAL ALERT TIMELINE")
        if not alerts:
            report_lines.append("No security threats or active ransomware processes contained on this system.")
        else:
            for alert in alerts:
                ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert['timestamp']))
                report_lines.append(f"### [ALERT] Process PID {alert['pid']} - {os.path.basename(alert['exe_path'])}")
                report_lines.append(f"- **Timestamp:** {ts_str}")
                report_lines.append(f"- **Executable Path:** {alert['exe_path']}")
                report_lines.append(f"- **Threat Score (Sp):** {alert['threat_score']:.2f}")
                report_lines.append(f"- **Trigger Signatures:** {alert['reason']}")
                report_lines.append(f"- **Applied Containments:** {alert['action_taken']}")
                report_lines.append("")

        report_lines.append("## 4. PROCESS ACTIVITY SUMMARY")
        if not calibrated:
            report_lines.append("No active process activity recorded.")
        else:
            report_lines.append("| PID | Process Name | File Event Count | Max Threat Score | Applied Action |")
            report_lines.append("|---|---|---|---|---|")
            for proc in calibrated:
                report_lines.append(f"| {proc['pid']} | {os.path.basename(proc['exe_path'])} | {proc['event_count']} | {proc['max_threat']:.2f} | {proc['actions']} |")

        report_lines.append("\n## 5. RECENT FILE ACTIVITY LOG (LAST 100 EVENTS)")
        if not events:
            report_lines.append("No file events recorded.")
        else:
            report_lines.append("| Timestamp | PID | Process | Event Type | Target File | Entropy Before | Entropy After | Sp | Status |")
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
        return f"Error exporting DFIR report: {str(e)}", 500

def start_web_server(host="127.0.0.1", port=5000, debug=False):
    """Start the Flask development server."""
    app.run(host=host, port=port, debug=debug, use_reloader=False)
