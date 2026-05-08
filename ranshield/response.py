import os
import sys
import subprocess
import shutil
import hashlib
import psutil
import time
from typing import Dict
import ranshield.config as config
from ranshield.database import log_alert, log_quarantine

def is_admin() -> bool:
    """Check if the current script is running with Administrative privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.getuid() == 0

def calculate_sha256(filepath: str) -> str:
    """Calculate the cryptographic SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "unknown_hash"

class ResponseModule:
    @staticmethod
    def contain(pid: int, exe_path: str, threat_score: float, reason: str) -> Dict[str, bool]:
        """
        Executes automated containment workflows based on configuration:
        
        CONTAINMENT_MODE = "safe" (Monitor & Alert only, zero disruption)
        CONTAINMENT_MODE = "strict" (Instant Kill first, followed by audit & backup)
        CONTAINMENT_MODE = "standard" (Suspension -> Isolation -> Snapshot -> Kill & Quarantine)
        """
        results = {
            "suspended": False,
            "network_isolated": False,
            "snapshot_created": False,
            "terminated": False,
            "quarantined": False
        }
        
        mode = config.CONTAINMENT_MODE.lower()
        print(f"\n[INFO] [RANSHIELD TRIGGERED] Threat score breached Sp={threat_score:.2f} >= 0.75. Active Mode: {mode.upper()}")
        print(f"[INFO] Threat Signature Match: {reason}")
        
        if mode == "safe":
            # Safe Mode: Audit only, do not disrupt the process or system
            print(f"[INFO] Safe Mode active. No containment measures will be enforced for PID {pid}.")
            log_alert(pid, exe_path, threat_score, f"[SAFE MODE AUDIT Only] {reason}", "AUDITED_ONLY")
            ResponseModule._trigger_notification(pid, exe_path, f"[SAFE MODE] {reason}", audit_only=True)
            return results

        # --- STRICT MODE: INSTANT TERMINATION ---
        # Kill the process first to minimize file encryption latency
        if mode == "strict":
            print(f"[WARNING] Strict Mode active! Terminating process PID {pid} immediately to prevent encryption...")
            try:
                p = psutil.Process(pid)
                p.kill()
                results["terminated"] = True
                print("[SUCCESS] Process killed instantly.")
            except Exception as e:
                if not psutil.pid_exists(pid):
                    results["terminated"] = True
                else:
                    print(f"[-] Instant kill failed: {e}")

        # --- STAGE 1: Process Suspension (Standard mode only, since strict has already terminated) ---
        if mode == "standard" and not results["terminated"]:
            try:
                p = psutil.Process(pid)
                p.suspend()
                results["suspended"] = True
                print(f"[SUCCESS] Process PID {pid} suspended. I/O writes paused.")
            except Exception as e:
                print(f"[-] Suspension failed: {e}")

        # --- STAGE 2: Network Isolation ---
        if sys.platform == "win32":
            rule_name = f"RanShield-Block-PID-{pid}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{exe_path}" enable=yes'
            try:
                res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode == 0:
                    results["network_isolated"] = True
                    print("[SUCCESS] Outbound network traffic isolated via Windows Defender Firewall.")
                else:
                    if "Administrator" in res.stderr or "privileges" in res.stderr:
                        print("[-] Isolation Warning: Firewall configurations require Administrative privileges.")
                    else:
                        print(f"[-] Isolation Failed: {res.stderr.strip()}")
            except Exception as e:
                print(f"[-] Isolation Error: {e}")
        else:
            cmd = f"iptables -A OUTPUT -m owner --pid-owner {pid} -j REJECT"
            try:
                res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if res.returncode == 0:
                    results["network_isolated"] = True
                    print("[SUCCESS] Outbound network traffic isolated via iptables.")
                else:
                    print("[-] Isolation Warning: iptables configurations require root privileges.")
            except Exception as e:
                print(f"[-] Isolation Error: {e}")

        # --- STAGE 3: Volume Snapshot / Backups ---
        if sys.platform == "win32":
            cmd = 'powershell -Command "vssadmin create shadow /for=C:"'
            try:
                res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode == 0 or "Successfully created shadow copy" in res.stdout:
                    results["snapshot_created"] = True
                    print("[SUCCESS] Volume Shadow Copy (VSS) restore checkpoint created.")
                else:
                    print("[-] Snapshot Warning: VSS requires Administrator rights. Executing local ZIP backup fallback...")
                    results["snapshot_created"] = ResponseModule._mock_backup_fallback()
            except Exception as e:
                print(f"[-] Snapshot Error: {e}")
        else:
            print("[-] Snapshot Warning: Linux LVM configuration required. Executing local ZIP backup fallback...")
            results["snapshot_created"] = ResponseModule._mock_backup_fallback()

        # --- STAGE 4: Process Termination (Standard mode, or if instant kill failed) ---
        if not results["terminated"]:
            try:
                p = psutil.Process(pid)
                p.kill()
                results["terminated"] = True
                print("[SUCCESS] Process terminated.")
            except Exception as e:
                if not psutil.pid_exists(pid):
                    results["terminated"] = True
                    print("[SUCCESS] Process was already dead.")
                else:
                    print(f"[-] Process termination failed: {e}")

        # --- QUARANTINE PHASE ---
        # Safely extract and move the binary to our locked quarantine vault
        if results["terminated"] and os.path.exists(exe_path) and os.path.isfile(exe_path):
            try:
                filename = os.path.basename(exe_path)
                file_hash = calculate_sha256(exe_path)
                file_size = os.path.getsize(exe_path)
                
                # Locked target path
                timestamp = int(time.time())
                quarantine_filename = f"{filename}.{timestamp}.quarantined"
                quarantine_target = os.path.join(config.QUARANTINE_DIR, quarantine_filename)
                
                # Copy/Move the file to quarantine vault (using copy to keep original binary location for forensic audits)
                shutil.copy2(exe_path, quarantine_target)
                results["quarantined"] = True
                
                # Log quarantine database record
                log_quarantine(exe_path, quarantine_target, file_hash, file_size, pid)
                print(f"[SUCCESS] Threat binary quarantined to: {quarantine_target} (SHA256: {file_hash[:16]}...)")
            except Exception as e:
                print(f"[-] Quarantine Failed: Unable to move executable to secure vault. Error: {e}")

        # Log active alert
        action_summary = f"SUSPEND:{results['suspended']}|ISOLATE:{results['network_isolated']}|VSS:{results['snapshot_created']}|KILL:{results['terminated']}|QUARANTINE:{results['quarantined']}"
        log_alert(pid, exe_path, threat_score, reason, action_summary)
        
        # Show desktop popups
        ResponseModule._trigger_notification(pid, exe_path, reason)
        
        return results

    @staticmethod
    def _mock_backup_fallback() -> bool:
        """Create a mock ZIP backup of the watched directory as a safe fallback when not running as administrator."""
        import zipfile
        backup_dir = os.path.join(os.path.dirname(config.DEFAULT_WATCH_DIR), "RanShield_Backups")
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = int(time.time())
        zip_path = os.path.join(backup_dir, f"ranshield_snapshot_{timestamp}.zip")
        
        try:
            # Only backup watched directories configured
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for watch_folder in config.WATCH_DIRECTORIES:
                    if os.path.exists(watch_folder):
                        for root, _, files in os.walk(watch_folder):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, watch_folder)
                                zipf.write(file_path, arcname)
            print(f"[SUCCESS] Backup fallbacks created: {zip_path}")
            return True
        except Exception as e:
            print(f"[-] Backup fallback failed: {e}")
            return False

    @staticmethod
    def _trigger_notification(pid: int, exe_path: str, reason: str, audit_only=False):
        """Displays a desktop notification warning box regarding the threat."""
        title = "RANSHIELD WARNING: Policy Audit!" if audit_only else "RANSHIELD ALERT: Threat Blocked!"
        message = f"Process {os.path.basename(exe_path)} (PID: {pid}) triggered security policy.\nReason: {reason}"
        
        if sys.platform == "win32":
            try:
                import ctypes
                import threading
                threading.Thread(
                    target=lambda: ctypes.windll.user32.MessageBoxW(0, message, title, 0x00000030),
                    daemon=True
                ).start()
            except Exception:
                pass
        else:
            try:
                subprocess.run(["notify-send", title, message], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
