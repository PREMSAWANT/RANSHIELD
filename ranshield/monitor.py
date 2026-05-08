import os
import sys
import time
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import ranshield.config as config
from ranshield.engine import DetectionEngine

class FileMonitorHandler(FileSystemEventHandler):
    """
    Handles file system events detected by watchdog and forwards them
    to the Detection Engine with resolved process information.
    """
    def __init__(self, engine: DetectionEngine):
        super().__init__()
        self.engine = engine
        self._cache_lock = threading.Lock()
        self._active_pids_cache = []
        self._update_process_cache()
        
        # Background thread to keep the process list cache warm and fresh
        self._stop_cache_thread = threading.Event()
        self._cache_thread = threading.Thread(target=self._keep_cache_warm, daemon=True)
        self._cache_thread.start()

    def _update_process_cache(self):
        """Helper to fetch processes that have non-trivial I/O or system activity."""
        active = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['pid'] <= 4 or not proc.info['exe']:
                    continue
                active.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        with self._cache_lock:
            self._active_pids_cache = active

    def _keep_cache_warm(self):
        """Runs in background to refresh active process cache every few seconds."""
        while not self._stop_cache_thread.is_set():
            time.sleep(2.0)
            try:
                self._update_process_cache()
            except Exception:
                pass

    def _resolve_pid_for_file(self, file_path: str) -> tuple[int, str]:
        """
        Heuristic to resolve which process modified/created/deleted a file.
        Queries active file handles and correlates I/O activity.
        """
        abs_path = os.path.abspath(file_path)
        
        # Strategy 1: Check active file locks or open handles using psutil
        with self._cache_lock:
            candidates = list(self._active_pids_cache)
            
        for proc_info in candidates:
            try:
                pid = proc_info['pid']
                p = psutil.Process(pid)
                for f in p.open_files():
                    if os.path.abspath(f.path) == abs_path:
                        return pid, proc_info['exe']
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
                
        # Strategy 2: Correlate with the process doing the most I/O write operations right now
        best_pid = None
        best_exe = None
        max_writes = -1
        
        for proc_info in candidates:
            try:
                pid = proc_info['pid']
                p = psutil.Process(pid)
                io = p.io_counters()
                if io.write_bytes > max_writes:
                    max_writes = io.write_bytes
                    best_pid = pid
                    best_exe = proc_info['exe']
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
                
        if best_pid is not None:
            return best_pid, best_exe
            
        # Fallback to current python process
        return os.getpid(), sys.executable

    def on_modified(self, event):
        if event.is_directory:
            return
        
        pid, exe_path = self._resolve_pid_for_file(event.src_path)
        self.engine.evaluate_event(pid, exe_path, event.src_path, "MODIFY")

    def on_created(self, event):
        if event.is_directory:
            return
            
        pid, exe_path = self._resolve_pid_for_file(event.src_path)
        self.engine.evaluate_event(pid, exe_path, event.src_path, "CREATE")

    def on_deleted(self, event):
        if event.is_directory:
            return
            
        pid, exe_path = self._resolve_pid_for_file(event.src_path)
        self.engine.evaluate_event(pid, exe_path, event.src_path, "DELETE")

    def on_moved(self, event):
        if event.is_directory:
            return
            
        pid, exe_path = self._resolve_pid_for_file(event.dest_path)
        self.engine.evaluate_event(pid, exe_path, event.dest_path, "RENAME")

    def stop(self):
        self._stop_cache_thread.set()


class MonitoringAgent:
    """
    Main monitoring subsystem managing file-system observers
    on configured watch directories. Supports dynamic watch folder reloads.
    """
    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.observer = None
        self.handler = FileMonitorHandler(engine)
        self.is_running = False

    def start(self):
        """Start the watchdog filesystem observer on configured paths."""
        if self.is_running:
            return
            
        self.observer = Observer()
        for path in config.WATCH_DIRECTORIES:
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)
            self.observer.schedule(self.handler, path, recursive=True)
            print(f"[INFO] Monitoring Agent scheduled directory: {path}")
            
        self.observer.start()
        self.is_running = True
        print("[INFO] Monitoring Agent started and listening for file events.")

    def stop(self):
        """Stop the watchdog observer."""
        if not self.is_running or not self.observer:
            return
            
        self.observer.stop()
        self.observer.join()
        self.observer = None
        self.is_running = False
        print("[INFO] Monitoring Agent stopped.")

    def reload_watch_directories(self):
        """Reload directory watching schedules dynamically based on active config list."""
        print("[INFO] Reloading directory watches dynamically...")
        was_running = self.is_running
        if was_running:
            self.stop()
        # Paths will be read dynamically from config in start()
        if was_running:
            self.start()
        print("[INFO] Dynamic directory reload complete.")
