import os
import sys
import time
import re
import psutil
from typing import Dict, List, Set, Tuple
from collections import deque

import ranshield.config as config
from ranshield.entropy import get_entropy_before_and_after
from ranshield.calibration import CalibrationManager
from ranshield.response import ResponseModule
from ranshield.database import log_event

class ProcessContext:
    """Holds temporal monitoring state and sliding window data for a single process."""
    def __init__(self, pid: int, exe_path: str):
        self.pid = pid
        self.exe_path = exe_path
        self.exe_name = os.path.basename(exe_path).lower()
        
        # Sliding window for file events: (timestamp, event_type, file_path)
        self.events = deque()
        
        # Entropy history: list of float values
        self.entropy_history: List[float] = []
        
        # Write volumes: deque of (timestamp, byte_count)
        self.write_volumes = deque()
        
        # Directories accessed in sliding window
        self.directories_accessed: Set[str] = set()
        
        # Child process execution logs
        self.spawned_children: Set[str] = set()
        
        # Outbound network connection ports
        self.network_ports: Set[int] = set()
        
        # Triggered rules cache (rule_name -> bool)
        self.triggered_rules: Dict[str, bool] = {rule: False for rule in config.WEIGHTS.keys()}
        
        # Threat score history
        self.current_score = 0.0
        
        # Last time this process was checked
        self.last_active_time = time.time()

    def prune_old_events(self, now: float):
        """Keep only events inside the sliding window buffer (e.g., 10s)."""
        limit = now - config.SLIDING_WINDOW_BUFFER
        
        # Prune events
        while self.events and self.events[0][0] < limit:
            self.events.popleft()
            
        # Prune write volumes
        while self.write_volumes and self.write_volumes[0][0] < limit:
            self.write_volumes.popleft()
            
        # Recompute directories accessed from remaining events
        self.directories_accessed = {os.path.dirname(e[2]) for e in self.events}

    def record_write(self, byte_count: int, file_path: str, now: float):
        """Record a write event and update volume metrics."""
        self.write_volumes.append((now, byte_count))
        self.events.append((now, "MODIFY", file_path))
        self.directories_accessed.add(os.path.dirname(file_path))
        self.last_active_time = now

    def record_deletion(self, file_path: str, now: float):
        """Record a deletion event."""
        self.events.append((now, "DELETE", file_path))
        self.last_active_time = now

    def record_rename(self, old_path: str, new_path: str, now: float):
        """Record a rename event."""
        self.events.append((now, "RENAME", new_path))
        self.directories_accessed.add(os.path.dirname(new_path))
        self.last_active_time = now

    def get_write_rate(self, now: float, interval: float = 1.0) -> float:
        """Calculate bytes written per second in the last 'interval' seconds."""
        limit = now - interval
        total_bytes = sum(vol for ts, vol in self.write_volumes if ts >= limit)
        return total_bytes / interval

    def get_fan_out(self) -> int:
        """Count unique directories accessed in the sliding window."""
        return len(self.directories_accessed)


class DetectionEngine:
    def __init__(self, calibration_mgr: CalibrationManager):
        self.calibration_mgr = calibration_mgr
        # Maps PID -> ProcessContext
        self.processes: Dict[int, ProcessContext] = {}
        
        # Layer weights
        self.w_entropy = 0.35  # Layer 1 weight
        self.w_io = 0.30       # Layer 2 weight
        
        # Set of active containments to prevent double-containment
        self.contained_pids: Set[int] = set()

    def get_context(self, pid: int, exe_path: str) -> ProcessContext:
        """Retrieve or create a ProcessContext for a given PID."""
        if pid not in self.processes:
            self.processes[pid] = ProcessContext(pid, exe_path)
        return self.processes[pid]

    def check_behavioral_rules(self, ctx: ProcessContext, now: float):
        """Layer 3: Evaluates behavioral heuristics and updates active rules."""
        # Ensure rules keys exist if configuration was reloaded with different keys
        for rule in config.WEIGHTS.keys():
            if rule not in ctx.triggered_rules:
                ctx.triggered_rules[rule] = False

        # 1. Shadow-copy deletion (weight 0.40)
        # Check active child processes or command lines
        if not ctx.triggered_rules.get("shadow_copy_deletion", False):
            try:
                p = psutil.Process(ctx.pid)
                children = p.children(recursive=True)
                for child in children:
                    cmd_line = " ".join(child.cmdline()).lower()
                    if any(term in cmd_line for term in ["vssadmin", "shadowcopy", "shadowstorage", "bcedit", "wbadmin"]):
                        if "delete" in cmd_line or "resize" in cmd_line:
                            ctx.triggered_rules["shadow_copy_deletion"] = True
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 2. Ransomnote file created (weight 0.30) - Evaluated dynamically in evaluate_event

        # 3. Mass deletion: > k files deleted within sliding window after high-entropy modifications (weight 0.25)
        if not ctx.triggered_rules.get("mass_deletion", False):
            deletions = [e for e in ctx.events if e[1] == "DELETE" and e[0] >= now - 5.0]
            modifications = [e for e in ctx.events if e[1] == "MODIFY" and e[0] >= now - 10.0]
            if len(deletions) >= config.MASS_DELETION_LIMIT and len(modifications) >= 3:
                if any(h > 6.0 for h in ctx.entropy_history[-10:]):
                    ctx.triggered_rules["mass_deletion"] = True

        # 4. Outbound connection to .onion domain or Tor port (weight 0.20)
        if not ctx.triggered_rules.get("onion_connection", False):
            try:
                p = psutil.Process(ctx.pid)
                connections = p.connections(kind='inet')
                for conn in connections:
                    if conn.raddr and conn.raddr.port in [9050, 9150]:
                        ctx.triggered_rules["onion_connection"] = True
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 5. Rapid traversal of >3 user directories (weight 0.15)
        if not ctx.triggered_rules.get("rapid_traversal", False):
            if ctx.get_fan_out() >= 3:
                ctx.triggered_rules["rapid_traversal"] = True

        # 6. Process spawns cmd/powershell child (weight 0.15)
        if not ctx.triggered_rules.get("child_process_spawned", False):
            try:
                p = psutil.Process(ctx.pid)
                for child in p.children():
                    child_name = child.name().lower()
                    if child_name in ["cmd.exe", "powershell.exe", "bash", "sh"]:
                        ctx.triggered_rules["child_process_spawned"] = True
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 7. File extensions changed to unknown type (weight 0.20) - Evaluated in evaluate_event

        # 8. Registry run-key persistence established (weight 0.10)
        if not ctx.triggered_rules.get("registry_persistence", False):
            try:
                p = psutil.Process(ctx.pid)
                for child in p.children():
                    cmd_line = " ".join(child.cmdline()).lower()
                    if "reg" in cmd_line and ("add" in cmd_line or "run" in cmd_line) and "currentversion" in cmd_line:
                        ctx.triggered_rules["registry_persistence"] = True
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def evaluate_event(self, pid: int, exe_path: str, file_path: str, event_type: str) -> float:
        """
        Executes the three-layer detection pipeline for a file system event.
        Returns the aggregate threat score Sp.
        """
        if pid in self.contained_pids:
            return 1.0
            
        now = time.time()
        ctx = self.get_context(pid, exe_path)
        ctx.prune_old_events(now)
        
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1].lower()
        
        # Track event details
        if event_type == "MODIFY":
            try:
                size = os.path.getsize(file_path)
            except:
                size = 1024
            ctx.record_write(size, file_path, now)
        elif event_type == "DELETE":
            ctx.record_deletion(file_path, now)
        elif event_type == "RENAME":
            ctx.record_rename("", file_path, now)
        else:
            ctx.events.append((now, event_type, file_path))

        # --- Layer 1: Shannon Entropy Scoring ---
        entropy_before = 0.0
        entropy_after = 0.0
        s1 = 0.0
        
        if event_type in ["MODIFY", "CREATE", "RENAME"]:
            entropy_before, entropy_after = get_entropy_before_and_after(file_path)
            
            # If in calibration, record observation and skip evaluation
            if self.calibration_mgr.is_calibrating:
                if entropy_after > 0.1:
                    self.calibration_mgr.record_observation(exe_path, entropy_after)
                log_event(pid, exe_path, file_path, event_type, entropy_before, entropy_after, 0.0, "CALIBRATION")
                return 0.0
                
            # If calibrated, evaluate threshold
            if entropy_after > 0.0:
                ctx.entropy_history.append(entropy_after)
                
                # Fetch adaptive per-process class threshold
                tau_enc = self.calibration_mgr.get_threshold(exe_path)
                
                # Check Layer 1 breach: H > tau_enc and Median(History) > tau_enc and historyLen >= nmin
                if len(ctx.entropy_history) >= config.MIN_ENTROPY_WRITES:
                    median_entropy = float(np.median(ctx.entropy_history[-10:])) if len(ctx.entropy_history) > 1 else entropy_after
                    import numpy as np # ensure numpy imported inside block if missing, or at module level
                    if entropy_after > tau_enc and median_entropy > tau_enc:
                        s1 = self.w_entropy
                        print(f"[ALERT] [Layer 1] PID {pid} high entropy write. H={entropy_after:.2f}, Threshold={tau_enc:.2f}")

        # --- Layer 2: I/O Rate Heuristics ---
        s2 = 0.0
        write_rate = ctx.get_write_rate(now)
        
        # Detect extension mutations
        is_mutated = False
        if event_type == "RENAME" or (event_type == "MODIFY" and file_ext in config.KNOWN_RANSOM_EXTENSIONS):
            if file_ext in config.KNOWN_RANSOM_EXTENSIONS:
                is_mutated = True
            elif file_ext and len(file_ext) >= 3 and len(file_ext) <= 10:
                common_exts = [".txt", ".docx", ".xlsx", ".pptx", ".pdf", ".png", ".jpg", ".jpeg", ".mp3", ".mp4", ".py", ".html", ".css", ".js", ".zip", ".rar", ".exe", ".dll", ".ini", ".log"]
                if file_ext not in common_exts:
                    is_mutated = True
                    
        if is_mutated:
            ctx.triggered_rules["extension_mutated"] = True

        # Formula (3): Write Rate > IO Threshold AND extension mutation detected
        if write_rate > config.IO_RATE_THRESHOLD and ctx.triggered_rules.get("extension_mutated", False):
            s2 = self.w_io
            print(f"[ALERT] [Layer 2] PID {pid} high throughput & mutation. Rate={write_rate/(1024*1024):.2f}MB/s")

        # --- Layer 3: Behavioural Rule Engine ---
        if event_type in ["CREATE", "MODIFY"]:
            for regex in config.KNOWN_RANSOM_NOTE_REGEX:
                if re.match(regex, file_name):
                    ctx.triggered_rules["ransomnote_created"] = True
                    print(f"[ALERT] [Layer 3] Ransom note creation match: {file_name}")
                    break

        self.check_behavioral_rules(ctx, now)
        
        # Calculate Layer 3 score sum
        s3 = 0.0
        active_rules = []
        for rule, triggered in ctx.triggered_rules.items():
            if triggered:
                weight = config.WEIGHTS.get(rule, 0.0)
                s3 += weight
                active_rules.append(rule)
                
        # --- Score Fusion ---
        Sp = s1 + s2 + s3
        ctx.current_score = Sp
        
        active_rules_str = ", ".join(active_rules) if active_rules else "None"
        action = "MONITOR"
        
        if Sp >= config.THREAT_THRESHOLD:
            # Respect containment mode: even if audited, mark as terminated or audited in DB
            action = "TERMINATED" if config.CONTAINMENT_MODE != "safe" else "AUDITED"
            self.contained_pids.add(pid)
            
            reason_str = f"Score Sp={Sp:.2f} >= {config.THREAT_THRESHOLD:.2f}. Active rules: [{active_rules_str}]"
            
            # Execute containment (non-blocking thread)
            import threading
            threading.Thread(
                target=ResponseModule.contain,
                args=(pid, exe_path, Sp, reason_str),
                daemon=True
            ).start()
            
        # Log event details to DB
        log_event(pid, exe_path, file_path, event_type, entropy_before, entropy_after, Sp, action)
        
        return Sp

    def prune_stale_processes(self):
        """Periodically clean up memory for processes that have been inactive."""
        now = time.time()
        stale_pids = []
        for pid, ctx in self.processes.items():
            if now - ctx.last_active_time > 300.0:
                stale_pids.append(pid)
        for pid in stale_pids:
            del self.processes[pid]
            if pid in self.contained_pids:
                self.contained_pids.remove(pid)
