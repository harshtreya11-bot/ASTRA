"""
config.py - Central configuration for Web Application Attack Detector
"""

import os

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "detector.db")
SAMPLE_LOG_PATH = os.path.join(DATA_DIR, "sample_access.log")
SAMPLE_ATTACKS_PATH = os.path.join(DATA_DIR, "sample_attacks.json")

# ---------------------------------------------------------------------------
# Detection thresholds (can be overridden via UI settings)
# ---------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 5          # failed logins from same IP within window
BRUTE_FORCE_WINDOW_MINUTES = 5     # time window for brute force detection
CORRELATION_WINDOW_MINUTES = 10    # time window for campaign correlation
CAMPAIGN_MIN_ALERTS = 3            # minimum alerts to form a campaign
LONG_PARAM_THRESHOLD = 512         # chars to flag a parameter as suspiciously long
DUPLICATE_PARAM_THRESHOLD = 3      # same param repeated this many times → flag

# ---------------------------------------------------------------------------
# Risk score ranges
# ---------------------------------------------------------------------------
RISK_LEVELS = {
    "CRITICAL": (80, 100),
    "HIGH":     (60, 79),
    "MEDIUM":   (30, 59),
    "LOW":      (0,  29),
}

# ---------------------------------------------------------------------------
# Detection sensitivity  (1 = strict, 3 = permissive)
# ---------------------------------------------------------------------------
DETECTION_SENSITIVITY = 2

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = "INFO"

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
APP_TITLE = "WEB APPLICATION ATTACK DETECTOR"
APP_SUBTITLE = "HTTP Threat Detection & Investigation Platform"
PAGE_SIZE = 25                      # rows per table page

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
REPORT_DIR = os.path.join(BASE_DIR, "reports", "generated")
os.makedirs(REPORT_DIR, exist_ok=True)
