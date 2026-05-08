import os
import sys
import subprocess
import psutil
import time
from typing import Dict
from ranshield.database import log_alert

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

class ResponseModule:
    @staticmethod
    def contain(pid: int, exe_path: str, threat_score: float, reason: str) -> Dict[str, bool]:
        """
        Executes the automated four-stage containment workflow:
        1. Process Suspension
        2. Network Isolation
        3. Snapshot Creation
        4. Process Termination
        
        Returns a dict of status for each stage.
        """
        results = {
            "suspended": False,
            "network_isolated": False,
            "snapshot_created": False,
            "terminated": False
        }
        
        print(f"\n[!] [RANSHIELD THREAT TRIGGERED] Sp={threat_score:.2f} >= Threshold! Threat: {reason}")
        print(f"[!] Executing 4-Stage Containment on PID {pid} ({os.path.basename(exe_path)})...")
        
        # --- STAGE 1: Process Suspension ---
        try:
            p = psutil.Process(pid)
            p.suspend()  # Sends SuspendThread-equivalent on Windows, SIGSTOP on Linux
            results["suspended"] = True
            print("[+] Stage 1: Process SUSPENDED successfully. I/O halted.")
        except Exception as e:
            print(f"[-] Stage 1 Failed: Unable to suspend process {pid}. Error: {e}")
            
        # --- STAGE 2: Network Isolation ---
        # Block outbound connections for the offending executable via Windows Firewall
        if sys.platform == "win32":
            rule_name = f"RanShield-Block-PID-{pid}"
            # Standard command to block outbound connections for this program
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{exe_path}" enable=yes'
            try:
                # Run firewall command (requires admin privileges)
                res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode == 0:
                    results["network_isolated"] = True
                    print("[+] Stage 2: Windows Firewall rule added. Outbound network isolated.")
                else:
                    if "Administrator" in res.stderr or "privileges" in res.stderr:
                        print("[-] Stage 2 Warning: Network isolation requires Administrative privileges.")
                    else:
                        print(f"[-] Stage 2 Failed: netsh returned error. {res.stderr.strip()}")
            except Exception as e:
                print(f"[-] Stage 2 Failed: Network isolation command error: {e}")
        else:
            # Linux iptables network isolation
            cmd = f"iptables -A OUTPUT -m owner --pid-owner {pid} -j REJECT"
            try:
                res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if res.returncode == 0:
                    results["network_isolated"] = True
                    print("[+] Stage 2: iptables rule added. Process network isolated.")
                else:
                    print("[-] Stage 2 Warning: iptables command requires root privileges.")
            except Exception as e:
                print(f"[-] Stage 2 Failed: iptables command error: {e}")

        # --- STAGE 3: Snapshot Creation ---
        # Windows Volume Shadow Copy (VSS) or Linux LVM
        if sys.platform == "win32":
            # Command to create a VSS shadow copy of drive C:
            # Note: wmic shadowcopy is deprecated but highly functional, or we can use powershell vss
            cmd = 'powershell -Command "vssadmin create shadow /for=C:"'
            try:
                res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode == 0 or "Successfully created shadow copy" in res.stdout:
                    results["snapshot_created"] = True
                    print("[+] Stage 3: Windows VSS shadow copy snapshot created.")
                else:
                    # Alternative backup fallback for test sandbox (create a zip/rar copy of watched directory)
                    print("[-] Stage 3 Warning: VSS snapshot creation requires Administrative privileges. Creating mock folder backup...")
                    results["snapshot_created"] = ResponseModule._mock_backup_fallback()
            except Exception as e:
                print(f"[-] Stage 3 Failed: VSS snapshot command error: {e}")
        else:
            # Linux LVM snapshot or sync/backup fallback
            print("[-] Stage 3: Linux LVM snapshot creation (Stubbed - LVM config-dependent). Creating mock folder backup...")
            results["snapshot_created"] = ResponseModule._mock_backup_fallback()

        # --- STAGE 4: Process Termination ---
        try:
            p = psutil.Process(pid)
            p.kill()  # Force kill the process
            results["terminated"] = True
            print("[+] Stage 4: Process TERMINATED cleanly.")
        except Exception as e:
            # Check if already dead
            if not psutil.pid_exists(pid):
                results["terminated"] = True
                print("[+] Stage 4: Process was already terminated.")
            else:
                print(f"[-] Stage 4 Failed: Unable to terminate process {pid}. Error: {e}")

        # Log alert to SQLite
        action_summary = f"SUSPEND:{results['suspended']}|ISOLATE:{results['network_isolated']}|VSS:{results['snapshot_created']}|KILL:{results['terminated']}"
        log_alert(pid, exe_path, threat_score, reason, action_summary)
        
        # Show Windows desktop notification (if on Windows)
        ResponseModule._trigger_notification(pid, exe_path, reason)
        
        return results

    @staticmethod
    def _mock_backup_fallback() -> bool:
        """Create a mock ZIP backup of the watched directory as a safe fallback when not running as administrator."""
        import zipfile
        from ranshield.config import DEFAULT_WATCH_DIR
        
        backup_dir = os.path.join(os.path.dirname(DEFAULT_WATCH_DIR), "RanShield_Backups")
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = int(time.time())
        zip_path = os.path.join(backup_dir, f"ranshield_snapshot_{timestamp}.zip")
        
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(DEFAULT_WATCH_DIR):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, DEFAULT_WATCH_DIR)
                        zipf.write(file_path, arcname)
            print(f"[+] Fallback Snapshot: Watched files backed up to {zip_path}")
            return True
        except Exception as e:
            print(f"[-] Fallback Snapshot Failed: {e}")
            return False

    @staticmethod
    def _trigger_notification(pid: int, exe_path: str, reason: str):
        """Displays a desktop notification regarding the containment action."""
        title = "RANSHIELD ALERT: Threat Blocked!"
        message = f"Process {os.path.basename(exe_path)} (PID: {pid}) was terminated.\nReason: {reason}"
        
        if sys.platform == "win32":
            try:
                # Use win32api to show a standard message box in the background or use a system toast
                # Let's try displaying a non-blocking Windows Toast or a simple popup
                import ctypes
                # MB_OK | MB_ICONWARNING = 0x00000000 | 0x00000030
                # Run in a separate thread so it doesn't block containment execution
                import threading
                threading.Thread(
                    target=lambda: ctypes.windll.user32.MessageBoxW(0, message, title, 0x00000030),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"[-] Toast Notification failed: {e}")
        else:
            try:
                # Linux notify-send
                subprocess.run(["notify-send", title, message], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
