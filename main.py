import os
import sys
import time
import threading
from ranshield.config import DEFAULT_WATCH_DIR, CALIBRATION_DURATION, HOST, PORT, DEBUG
import ranshield.database as db
from ranshield.calibration import CalibrationManager
from ranshield.engine import DetectionEngine
from ranshield.monitor import MonitoringAgent
from ranshield.web.app import app

def run_calibration_timer(calibration_mgr: CalibrationManager):
    """
    Runs as a background timer to count down the 60-second calibration phase
    and automatically finalize adaptive process profiling.
    """
    time.sleep(CALIBRATION_DURATION)
    if calibration_mgr.is_calibrating:
        count = calibration_mgr.finalize_calibration()
        print(f"[INFO] Calibration phase concluded. {count} processes profiled successfully.")
        print("[INFO] RANSHIELD: Now operating in full Threat Detection & Containment mode.")

def main():
    print("========================================================================")
    print("               RANSHIELD ENDPOINT SECURITY DAEMON                       ")
    print("      Real-Time Ransomware Detection and Multi-Signal Containment       ")
    print("========================================================================")
    
    # 1. Initialize DB schema
    print("[INFO] Initializing SQLite database schema...")
    db.init_db()
    
    # 2. Setup Calibration Subsystem
    calibration_mgr = CalibrationManager()
    calibration_mgr.start_calibration()
    
    # 3. Instantiate Detection Engine
    engine = DetectionEngine(calibration_mgr)
    
    # 4. Start Monitoring Agent
    print(f"[INFO] Pre-populating directory cache for: {DEFAULT_WATCH_DIR}")
    # Let's populate file path caches for initial state
    from ranshield.entropy import pre_populate_entropy_cache
    pre_populate_entropy_cache(DEFAULT_WATCH_DIR)
    
    print("[INFO] Launching filesystem file watchers...")
    agent = MonitoringAgent(engine)
    agent.start()
    
    # 5. Start Calibration countdown thread
    cal_thread = threading.Thread(target=run_calibration_timer, args=(calibration_mgr,), daemon=True)
    cal_thread.start()
    
    # 6. Start blocking Flask web application on the main thread
    print(f"[INFO] Launching Flask dashboard on http://{HOST}:{PORT}")
    try:
        app.run(host=HOST, port=PORT, debug=DEBUG, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[INFO] Keyboard interrupt detected. Initiating clean system shutdown...")
    finally:
        # 7. Clean up threads & watchers on exit
        print("[INFO] Halting file system watchers...")
        agent.stop()
        print("[INFO] RANSHIELD daemon shut down cleanly.")

if __name__ == "__main__":
    main()
