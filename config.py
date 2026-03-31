import os
import secrets

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
CAPTURES_DIR  = os.path.join(BASE_DIR, "captures")
FORENSICS_DIR = os.path.join(BASE_DIR, "forensics")
LOGS_DIR      = os.path.join(BASE_DIR, "logs")
RULES_DIR     = os.path.join(BASE_DIR, "rules")
DB_PATH       = os.path.join(BASE_DIR, "suricata_ids.db")
GEOIP_DB      = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")

# ── Binaries ──────────────────────────────────────────────────────────────
# Adjust these paths if Wireshark / Suricata are installed elsewhere
SURICATA_BIN = r"C:\Program Files\Suricata\suricata.exe"
DUMPCAP_BIN  = r"C:\Program Files\Wireshark\dumpcap.exe"
TSHARK_BIN   = r"C:\Program Files\Wireshark\tshark.exe"

# Directory containing Suricata's bundled DLLs (derived from binary path)
SURICATA_DIR = os.path.dirname(SURICATA_BIN)
# Npcap DLL directory – required on Windows for Suricata to find wpcap.dll
NPCAP_DIR    = r"C:\Windows\System32\Npcap"

# ── Defaults (can be overridden via Settings UI → stored in SQLite) ────────
DEFAULT_CAPTURE_FILESIZE_KB   = 204800  # 200 MB
DEFAULT_MAX_CAPTURE_FILES     = 10      # keep at most N completed capture files
DEFAULT_DEDUP_WINDOW_SECS     = 60      # alert de-dup window
DEFAULT_CAPTURE_DURATION_SECS = 0       # 0 = size-only rotation

# ── Flask ──────────────────────────────────────────────────────────────────
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
SECRET_KEY = secrets.token_hex(32)
