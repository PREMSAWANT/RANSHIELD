import os
import sys

# Base directories
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
DB_PATH = os.path.join(BASE_DIR, "ranshield.db")

# Watch directories
# We will watch a dedicated sandbox folder inside the user's home folder for safety,
# but it can be configured to watch other locations.
USER_HOME = os.path.expanduser("~")
WATCH_DIR_NAME = "RanShield_Watch"
DEFAULT_WATCH_DIR = os.path.join(USER_HOME, WATCH_DIR_NAME)

WATCH_DIRECTORIES = [
    DEFAULT_WATCH_DIR
]

# Ensure the default watch directory exists
if not os.path.exists(DEFAULT_WATCH_DIR):
    os.makedirs(DEFAULT_WATCH_DIR, exist_ok=True)

# Calibration configurations
CALIBRATION_DURATION = 60.0  # seconds

# Layer 1: Entropy Heuristics
DEFAULT_ENTROPY_THRESHOLD = 7.2
MIN_ENTROPY_WRITES = 5  # nmin
SAMPLE_SIZE_KB = 4      # 4KB block size

# Layer 2: I/O Heuristics
IO_RATE_THRESHOLD = 5.0 * 1024 * 1024  # 5 MB/s
IO_WINDOW_SECONDS = 1.0
SLIDING_WINDOW_BUFFER = 10.0            # 10s window for temporal correlation
MASS_DELETION_LIMIT = 5                 # > k files deleted within 1s after encryption

# Layer 3: Behavioral Rules
THREAT_THRESHOLD = 0.75

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

# Ransomware extensions to monitor / signatures
KNOWN_RANSOM_EXTENSIONS = {
    ".wnry", ".wcry", ".locky", ".crypt", ".encrypted", ".paycrypt", ".dharma",
    ".lockbit", ".maze", ".ryuk", ".clop", ".revil", ".sodinokibi", ".ransom"
}

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
