import os
import sys
import json

# Base directories
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
DB_PATH = os.path.join(BASE_DIR, "ranshield.db")
POLICIES_JSON_PATH = os.path.join(os.path.dirname(__file__), "policies.json")

# Quarantined binaries directory
USER_HOME = os.path.expanduser("~")
QUARANTINE_DIR = os.path.join(USER_HOME, "RanShield_Quarantine")
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Watch directories config
WATCH_DIR_NAME = "RanShield_Watch"
DEFAULT_WATCH_DIR = os.path.join(USER_HOME, WATCH_DIR_NAME)
if not os.path.exists(DEFAULT_WATCH_DIR):
    os.makedirs(DEFAULT_WATCH_DIR, exist_ok=True)

# Set defaults
WATCH_DIRECTORIES = [DEFAULT_WATCH_DIR]
CALIBRATION_DURATION = 60.0  # seconds
DEFAULT_ENTROPY_THRESHOLD = 7.20
MIN_ENTROPY_WRITES = 5  # nmin
SAMPLE_SIZE_KB = 4      # 4KB block size
IO_RATE_THRESHOLD = 5.0 * 1024 * 1024  # 5 MB/s
IO_WINDOW_SECONDS = 1.0
SLIDING_WINDOW_BUFFER = 10.0            # 10s window for temporal correlation
MASS_DELETION_LIMIT = 5                 # > k files deleted within 1s after encryption
THREAT_THRESHOLD = 0.75
CONTAINMENT_MODE = "standard"           # standard, safe (monitor-only), strict (instant-kill)
WEBHOOK_URL = ""
SMTP_EMAIL = ""

WEIGHTS = {
    "shadow_copy_deletion": 0.40,
    "ransomnote_created": 0.30,
    "mass_deletion": 0.25,
    "onion_connection": 0.20,
    "rapid_traversal": 0.15,
    "child_process_spawned": 0.15,
    "extension_mutated": 0.20,
    "registry_persistence": 0.10
}

# Known ransomware extensions
KNOWN_RANSOM_EXTENSIONS = {
    ".wnry", ".wcry", ".locky", ".crypt", ".encrypted", ".paycrypt", ".dharma",
    ".lockbit", ".maze", ".ryuk", ".clop", ".revil", ".sodinokibi", ".ransom"
}

# Known ransom note signatures
KNOWN_RANSOM_NOTE_REGEX = [
    r"(?i)readme.*\.txt",
    r"(?i)ransom.*\.txt",
    r"(?i)restore.*\.txt",
    r"(?i)decrypt.*\.txt",
    r"(?i)instruction.*\.txt",
    r"(?i)how_to_decrypt.*",
    r"(?i)readme.*\.html",
    r"(?i)how_to_recover.*"
]

# Web GUI configuration
PORT = 5000
HOST = "127.0.0.1"
DEBUG = False

def load_policies():
    """Load policies from the JSON file and dynamically update configuration variables."""
    global CONTAINMENT_MODE, WATCH_DIRECTORIES, WEIGHTS, DEFAULT_ENTROPY_THRESHOLD, IO_RATE_THRESHOLD, WEBHOOK_URL, SMTP_EMAIL
    
    if not os.path.exists(POLICIES_JSON_PATH):
        # Save current defaults if file does not exist
        save_policies()
        return
        
    try:
        with open(POLICIES_JSON_PATH, "r") as f:
            data = json.load(f)
            
        CONTAINMENT_MODE = data.get("containment_mode", "standard")
        WATCH_DIRECTORIES = data.get("watch_directories", [DEFAULT_WATCH_DIR])
        WEIGHTS = data.get("weights", WEIGHTS)
        DEFAULT_ENTROPY_THRESHOLD = data.get("entropy_threshold_default", 7.20)
        IO_RATE_THRESHOLD = data.get("io_rate_threshold_mb", 5.0) * 1024 * 1024
        WEBHOOK_URL = data.get("webhook_url", "")
        SMTP_EMAIL = data.get("smtp_email", "")
        
        # Ensure watch folders exist
        for directory in WATCH_DIRECTORIES:
            os.makedirs(directory, exist_ok=True)
            
    except Exception as e:
        print(f"[-] Config loading warning: {e}. Reverting to default values.")

def save_policies(mode=None, watch_dirs=None, rule_weights=None, entropy_thresh=None, io_thresh=None, web_url=None, email=None):
    """Save policies to the JSON file and update configuration variables."""
    global CONTAINMENT_MODE, WATCH_DIRECTORIES, WEIGHTS, DEFAULT_ENTROPY_THRESHOLD, IO_RATE_THRESHOLD, WEBHOOK_URL, SMTP_EMAIL
    
    if mode is not None: CONTAINMENT_MODE = mode
    if watch_dirs is not None: WATCH_DIRECTORIES = watch_dirs
    if rule_weights is not None: WEIGHTS = rule_weights
    if entropy_thresh is not None: DEFAULT_ENTROPY_THRESHOLD = entropy_thresh
    if io_thresh is not None: IO_RATE_THRESHOLD = io_thresh * 1024 * 1024
    if web_url is not None: WEBHOOK_URL = web_url
    if email is not None: SMTP_EMAIL = email
    
    data = {
        "containment_mode": CONTAINMENT_MODE,
        "watch_directories": WATCH_DIRECTORIES,
        "webhook_url": WEBHOOK_URL,
        "smtp_email": SMTP_EMAIL,
        "weights": WEIGHTS,
        "entropy_threshold_default": DEFAULT_ENTROPY_THRESHOLD,
        "io_rate_threshold_mb": IO_RATE_THRESHOLD / (1024 * 1024)
    }
    
    try:
        with open(POLICIES_JSON_PATH, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"[-] Config saving warning: {e}")

# Initial load on import
load_policies()
