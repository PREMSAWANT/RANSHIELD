import os
import sys
import numpy as np
import time
from typing import Dict, List

import ranshield.config as config
from ranshield.database import save_calibration, get_calibration

class CalibrationManager:
    def __init__(self):
        # Maps executable path -> list of entropy values observed
        self.entropy_observations: Dict[str, List[float]] = {}
        self.calibration_start_time = None
        self.is_calibrating = False

    def start_calibration(self):
        """Start the calibration timer."""
        self.calibration_start_time = time.time()
        self.is_calibrating = True
        print(f"[+] RANSHIELD: Calibration phase started (Duration: {config.CALIBRATION_DURATION}s).")

    def record_observation(self, exe_path: str, entropy: float):
        """Record an entropy observation for an executable during calibration."""
        if not self.is_calibrating:
            return
            
        exe_name = os.path.basename(exe_path).lower()
        if exe_path not in self.entropy_observations:
            self.entropy_observations[exe_path] = []
        self.entropy_observations[exe_path].append(entropy)

    def classify_process(self, exe_path: str) -> str:
        """Categorize an executable into one of the four paper-defined classes."""
        name = os.path.basename(exe_path).lower()
        
        # Legitimate high-entropy workloads (media, encryption, compression)
        media_keywords = ["ffmpeg", "vlc", "obs", "handbrake", "premiere", "photoshop", "7z", "winrar", "zip", "tar", "gzip"]
        office_keywords = ["winword", "excel", "powerpnt", "acrord", "pdf", "libreoffice", "word", "document"]
        dev_keywords = ["python", "node", "java", "gcc", "clang", "git", "code", "studio", "py", "sh", "powershell"]
        
        if any(kw in name for kw in media_keywords):
            return "media"
        elif any(kw in name for kw in office_keywords):
            return "office"
        elif any(kw in name for kw in dev_keywords):
            return "development"
        else:
            return "system"

    def finalize_calibration(self) -> int:
        """
        Finalize calibration, compute adaptive thresholds using formula (5):
        Thresh = Mean + 2.5 * StdDev, and save to DB.
        """
        self.is_calibrating = False
        calibrated_count = 0
        
        print("[+] RANSHIELD: Finalizing calibration...")
        
        for exe_path, values in self.entropy_observations.items():
            if len(values) < 3:
                # Not enough samples to calculate robust mean and standard deviation
                continue
                
            p_class = self.classify_process(exe_path)
            mean_val = float(np.mean(values))
            std_val = float(np.std(values)) if len(values) > 1 else 0.0
            
            # Formula 5: threshold = mean + 2.5 * stddev
            threshold = mean_val + 2.5 * std_val
            
            # Sanity clamps to keep thresholds reasonable
            # Office documents are low entropy, compressed media can approach 8.0
            if p_class == "media":
                threshold = max(7.4, min(threshold, 7.95))
            elif p_class == "office":
                threshold = max(6.5, min(threshold, 7.2))
            else:
                threshold = max(7.0, min(threshold, 7.8))
                
            save_calibration(exe_path, p_class, mean_val, std_val, threshold)
            print(f"    [Calibrated] {os.path.basename(exe_path)} -> Class: {p_class}, Thresh: {threshold:.3f} (Mean: {mean_val:.2f}, Std: {std_val:.2f})")
            calibrated_count += 1
            
        return calibrated_count

    def get_threshold(self, exe_path: str) -> float:
        """Get the calibrated threshold for an executable, or fallback to default."""
        # Try database first
        threshold = get_calibration(exe_path)
        if threshold is not None:
            return threshold
            
        # Hardcoded fallback classification if process wasn't active during calibration
        p_class = self.classify_process(exe_path)
        if p_class == "media":
            return 7.8  # high-entropy default
        elif p_class == "office":
            return 6.9  # low-entropy default
        elif p_class == "development":
            return 7.2  # medium-entropy default
        else:
            return config.DEFAULT_ENTROPY_THRESHOLD  # general default

    def get_progress_percent(self) -> float:
        """Calculate active calibration percentage elapsed."""
        if not self.is_calibrating or self.calibration_start_time is None:
            return 100.0
            
        elapsed = time.time() - self.calibration_start_time
        percent = (elapsed / config.CALIBRATION_DURATION) * 100.0
        return min(percent, 100.0)
