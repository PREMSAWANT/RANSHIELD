import sqlite3
import time
import os
from ranshield.config import DB_PATH

def init_db():
    """Initialize the SQLite database and create necessary tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Event Log Table (Table III from Paper)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS event_log (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            pid INTEGER NOT NULL,
            exe_path TEXT NOT NULL,
            file_path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            entropy_before REAL,
            entropy_after REAL,
            threat_score REAL,
            action_taken TEXT NOT NULL
        )
    """)
    
    # Process Threshold Table (For calibration & adaptive score history)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_calibration (
            pid INTEGER,
            exe_path TEXT PRIMARY KEY,
            process_class TEXT NOT NULL,
            mean_entropy REAL,
            std_entropy REAL,
            calibrated_threshold REAL,
            calibrated_at REAL
        )
    """)
    
    # Alerts table for direct threat scoring tracking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            pid INTEGER NOT NULL,
            exe_path TEXT NOT NULL,
            threat_score REAL NOT NULL,
            reason TEXT NOT NULL,
            action_taken TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def log_event(pid, exe_path, file_path, event_type, entropy_before, entropy_after, threat_score, action_taken):
    """Log a file system event to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO event_log (
                timestamp, pid, exe_path, file_path, event_type, 
                entropy_before, entropy_after, threat_score, action_taken
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (time.time(), pid, exe_path, file_path, event_type, entropy_before, entropy_after, threat_score, action_taken))
        conn.commit()
    except Exception as e:
        print(f"[-] Database log_event error: {e}")
    finally:
        conn.close()

def log_alert(pid, exe_path, threat_score, reason, action_taken):
    """Log a containment alert when threat score crosses threshold."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO alerts (timestamp, pid, exe_path, threat_score, reason, action_taken)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (time.time(), pid, exe_path, threat_score, reason, action_taken))
        conn.commit()
    except Exception as e:
        print(f"[-] Database log_alert error: {e}")
    finally:
        conn.close()

def save_calibration(exe_path, process_class, mean_entropy, std_entropy, threshold):
    """Save calibrated entropy parameters for a process executable."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO process_calibration (exe_path, process_class, mean_entropy, std_entropy, calibrated_threshold, calibrated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(exe_path) DO UPDATE SET
                process_class = excluded.process_class,
                mean_entropy = excluded.mean_entropy,
                std_entropy = excluded.std_entropy,
                calibrated_threshold = excluded.calibrated_threshold,
                calibrated_at = excluded.calibrated_at
        """, (exe_path, process_class, mean_entropy, std_entropy, threshold, time.time()))
        conn.commit()
    except Exception as e:
        print(f"[-] Database save_calibration error: {e}")
    finally:
        conn.close()

def get_calibration(exe_path):
    """Retrieve calibration threshold for an executable path."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT calibrated_threshold FROM process_calibration WHERE exe_path = ?", (exe_path,))
        row = cursor.fetchone()
        return row[0] if row else None
    except Exception as e:
        print(f"[-] Database get_calibration error: {e}")
        return None
    finally:
        conn.close()

def get_recent_events(limit=100):
    """Retrieve recent event log entries."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM event_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print(f"[-] Database get_recent_events error: {e}")
        return []
    finally:
        conn.close()

def get_process_timeline():
    """Retrieve summarized statistics grouped by process."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                pid, 
                exe_path, 
                COUNT(*) as event_count, 
                MAX(threat_score) as max_threat,
                GROUP_CONCAT(DISTINCT event_type) as event_types,
                GROUP_CONCAT(DISTINCT action_taken) as actions
            FROM event_log 
            GROUP BY pid, exe_path
            ORDER BY max_threat DESC, event_count DESC
        """)
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print(f"[-] Database get_process_timeline error: {e}")
        return []
    finally:
        conn.close()

def get_alerts():
    """Retrieve active alerts/containments."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print(f"[-] Database get_alerts error: {e}")
        return []
    finally:
        conn.close()

def get_stats():
    """Get high level statistics for dashboard cards."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    stats = {
        "total_events": 0,
        "active_alerts": 0,
        "processes_monitored": 0,
        "calibrated_count": 0
    }
    try:
        cursor.execute("SELECT COUNT(*) FROM event_log")
        stats["total_events"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts")
        stats["active_alerts"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT pid) FROM event_log")
        stats["processes_monitored"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM process_calibration")
        stats["calibrated_count"] = cursor.fetchone()[0]
    except Exception as e:
        print(f"[-] Database get_stats error: {e}")
    finally:
        conn.close()
    return stats

def clear_db():
    """Wipe database tables (primarily for testing/demo reset)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM event_log")
        cursor.execute("DELETE FROM process_calibration")
        cursor.execute("DELETE FROM alerts")
        conn.commit()
    except Exception as e:
        print(f"[-] Database clear_db error: {e}")
    finally:
        conn.close()
