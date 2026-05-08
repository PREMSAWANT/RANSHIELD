import os
import sys
import time
import random
import subprocess
from ranshield.config import DEFAULT_WATCH_DIR, IO_RATE_THRESHOLD, KNOWN_RANSOM_EXTENSIONS

def generate_mock_files(count=20):
    """Populates the watch directory with plain-text files to encrypt."""
    print(f"[INFO] Populating watch folder {DEFAULT_WATCH_DIR} with {count} plain text files...")
    if not os.path.exists(DEFAULT_WATCH_DIR):
        os.makedirs(DEFAULT_WATCH_DIR, exist_ok=True)
        
    for i in range(count):
        file_path = os.path.join(DEFAULT_WATCH_DIR, f"important_document_{i}.txt")
        # Generate clean, low-entropy text content
        content = "This is a confidential corporate document. It contains normal low-entropy plain English text designed to simulate production data.\n" * 50
        with open(file_path, "w") as f:
            f.write(content)
    print("[INFO] Mock files created successfully.")

def simulate_shadow_copy_deletion():
    """Simulates a ransomware process spawning command-line shadow copy deletion."""
    print("[INFO] Simulating Shadow Copy deletion command...")
    # On Windows, we can invoke a mock safe cmd command that triggers the rule
    # but doesn't actually delete critical files. We can call:
    # "cmd.exe /c echo vssadmin delete shadows"
    try:
        if sys.platform == "win32":
            subprocess.run("cmd.exe /c echo vssadmin delete shadows /all /quiet", shell=True)
        else:
            subprocess.run("echo vssadmin delete shadows", shell=True)
    except Exception as e:
        print(f"[-] Command simulation error: {e}")

def simulate_ransom_note():
    """Simulates creation of a classic ransomware readme file."""
    print("[INFO] Simulating Ransom Note creation...")
    note_path = os.path.join(DEFAULT_WATCH_DIR, "README_RECOVER_FILES.txt")
    note_content = (
        "ATTENTION! ALL YOUR PERSONAL FILES HAVE BEEN ENCRYPTED!\n"
        "To decrypt your documents and restore access, you must pay 0.5 BTC.\n"
        "Contact support at: support@ranshieldtemp.onion\n"
    )
    with open(note_path, "w") as f:
        f.write(note_content)
    print(f"[INFO] Created: {note_path}")

def simulate_encryption_attack():
    """
    Simulates high-entropy file overwriting and name renaming (extension mutation).
    This mimics the core signature of active ransomware.
    """
    print("[INFO] Launching high-entropy encryption simulation...")
    
    # 1. First trigger a shadow copy deletion to boost threat score (Sp + 0.40)
    simulate_shadow_copy_deletion()
    time.sleep(1.0)
    
    # 2. Get files to "encrypt"
    files = [f for f in os.listdir(DEFAULT_WATCH_DIR) if f.endswith(".txt") and not f.startswith("README")]
    if not files:
        print("[WARNING] No plain text files found to encrypt. Generating files first...")
        generate_mock_files()
        files = [f for f in os.listdir(DEFAULT_WATCH_DIR) if f.endswith(".txt") and not f.startswith("README")]
        
    print(f"[INFO] Preparing to encrypt {len(files)} files...")
    
    # We will simulate high entropy writes. 
    # High entropy is generated using random raw bytes.
    # To trigger the I/O rate heuristic (Sp + 0.30), we write a larger chunk of random bytes.
    # To trigger extension mutation, we rename files to .lockbit (Sp + 0.20)
    for index, file_name in enumerate(files):
        old_path = os.path.join(DEFAULT_WATCH_DIR, file_name)
        new_path = old_path.replace(".txt", ".lockbit")
        
        try:
            print(f"    [Encryption Action] Processing: {file_name} -> {os.path.basename(new_path)}")
            # Generate high-entropy data (random bytes)
            # 1 MB of high entropy random bytes
            random_data = bytearray(random.getrandbits(8) for _ in range(50 * 1024))
            
            # Overwrite original file (this triggers MODIFY)
            with open(old_path, "wb") as f:
                f.write(random_data)
                
            # Rename the file (this triggers RENAME and extension mutation)
            os.rename(old_path, new_path)
            
            # Brief sleep to let watchdog process events, but fast enough to trigger I/O heuristics
            time.sleep(0.3)
            
        except Exception as e:
            # If the process is suspended or killed by RANSHIELD, this file operation will fail!
            print(f"\n[SUCCESS] Encryption script blocked! Exception raised: {e}")
            print("[INFO] This indicates RANSHIELD has suspended or terminated this process successfully!")
            break
            
    print("\n[INFO] Simulation finished.")

def main():
    print("========================================================================")
    print("               RANSHIELD RANSOMWARE SIMULATOR                           ")
    print("      Safe, Local Simulation of Heuristic & Encryption Attacks          ")
    print("========================================================================")
    
    if not os.path.exists(DEFAULT_WATCH_DIR):
        os.makedirs(DEFAULT_WATCH_DIR, exist_ok=True)
        
    print(f"[INFO] Watch folder is set to: {DEFAULT_WATCH_DIR}")
    print("\nChoose simulation option:")
    print("1) Pre-populate watch directory with healthy plain text files")
    print("2) Create a Ransomware Note file (Triggers Sp +0.30)")
    print("3) Simulate Outbound shadow copy deletion (Triggers Sp +0.40)")
    print("4) Run full active encryption attack (Overwrites files with high entropy and renames them)")
    print("5) Run everything combined (Guaranteed to trigger containment)")
    
    try:
        choice = input("\nEnter choice (1-5): ").strip()
    except KeyboardInterrupt:
        print("\n[INFO] Exiting simulator.")
        return
        
    if choice == "1":
        generate_mock_files()
    elif choice == "2":
        simulate_ransom_note()
    elif choice == "3":
        simulate_shadow_copy_deletion()
    elif choice == "4":
        simulate_encryption_attack()
    elif choice == "5":
        generate_mock_files()
        print("\n[INFO] Starting combined attack sequence in 3 seconds. Watch your RANSHIELD console...")
        time.sleep(3.0)
        simulate_ransom_note()
        time.sleep(1.0)
        simulate_encryption_attack()
    else:
        print("[ERROR] Invalid choice selected.")

if __name__ == "__main__":
    main()
