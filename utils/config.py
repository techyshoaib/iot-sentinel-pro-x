"""
Configuration module for IoT Sentinel Pro — Campus Edition.
Manages application constants, paths, default ports, severity tiers,
device classification signatures, risk scoring weights, and Nmap discovery.
"""

import os
import shutil
import platform
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
DB_PATH = DATA_DIR / "iot_scanner.db"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Application Metadata
APP_NAME = "IoT Sentinel Pro — Campus Edition"
APP_SHORT_NAME = "IoT Sentinel Pro"
APP_VERSION = "2.0.0"
APP_SUBTITLE = "Advanced Defensive IoT Security Auditor, Asset Classifier & Vulnerability Assessment Engine"

# Common IoT TCP Ports targeted for assessment
# Categorized with service signatures and security significance
IOT_COMMON_PORTS = {
    21: {
        "service": "FTP",
        "description": "File Transfer Protocol (Unencrypted cleartext file & credential transfer)",
        "protocol": "tcp",
        "risk_category": "Cleartext Authentication",
        "typical_device": "NAS / Server / Printer"
    },
    22: {
        "service": "SSH",
        "description": "Secure Shell (Encrypted remote command management interface)",
        "protocol": "tcp",
        "risk_category": "Remote Access Surface",
        "typical_device": "Gateway / Server / Camera"
    },
    23: {
        "service": "Telnet",
        "description": "Telnet (Legacy cleartext terminal - High Botnet/Mirai risk)",
        "protocol": "tcp",
        "risk_category": "Legacy Protocol Vulnerability",
        "typical_device": "Legacy Router / Switch / DVR"
    },
    53: {
        "service": "DNS",
        "description": "Domain Name System (Open resolver or IoT DNS proxy)",
        "protocol": "tcp",
        "risk_category": "Name Resolution Surface",
        "typical_device": "Router / Gateway"
    },
    80: {
        "service": "HTTP",
        "description": "Hypertext Transfer Protocol (Cleartext Web Management Console)",
        "protocol": "tcp",
        "risk_category": "Insecure Web Portal",
        "typical_device": "All IoT Devices"
    },
    443: {
        "service": "HTTPS",
        "description": "Hypertext Transfer Protocol Secure (TLS Encrypted Web Console)",
        "protocol": "tcp",
        "risk_category": "Encrypted Web Portal",
        "typical_device": "Modern IoT / Server"
    },
    554: {
        "service": "RTSP",
        "description": "Real Time Streaming Protocol (Surveillance Camera & NVR Video Stream)",
        "protocol": "tcp",
        "risk_category": "Surveillance Stream Exposure",
        "typical_device": "CCTV / IP Camera / NVR"
    },
    1883: {
        "service": "MQTT",
        "description": "Message Queuing Telemetry Transport (Unencrypted IoT Messaging Broker)",
        "protocol": "tcp",
        "risk_category": "Telemetry & Sensor Bus",
        "typical_device": "MQTT Broker / Sensor Hub"
    },
    8883: {
        "service": "MQTTS",
        "description": "MQTT Secure (TLS Encrypted IoT Messaging Broker)",
        "protocol": "tcp",
        "risk_category": "Secure Messaging Bus",
        "typical_device": "Secure MQTT Broker"
    },
    8080: {
        "service": "HTTP-Alt",
        "description": "Alternate HTTP Web Management / REST API Interface",
        "protocol": "tcp",
        "risk_category": "Secondary Management Surface",
        "typical_device": "Camera / Development Node"
    },
    8443: {
        "service": "HTTPS-Alt",
        "description": "Alternate HTTPS Web Management / Secure REST API Interface",
        "protocol": "tcp",
        "risk_category": "Secondary Secure Surface",
        "typical_device": "Modern Gateway / Camera"
    }
}

DEFAULT_PORT_LIST = sorted(list(IOT_COMMON_PORTS.keys()))

# Extended CCTV / Surveillance Ports for dedicated inspection
CCTV_SPECIFIC_PORTS = [80, 443, 554, 8000, 8080, 8443, 37777]

# Device Classification Categories
DEVICE_TYPES = [
    "CCTV / IP Camera",
    "Router / Gateway",
    "Network Switch",
    "Network Printer",
    "MQTT Broker / IoT Hub",
    "Server / Storage (NAS)",
    "Generic IoT Device"
]

# Asset Criticality Tiers & Weights for Risk Scoring
ASSET_CRITICALITY = {
    "Critical": 1.30,   # Core Infrastructure, Campus Gateways, Central NVR
    "High": 1.15,       # Surveillance Cameras, Physical Access Controls
    "Medium": 1.00,     # Environmental Sensor Nodes, Smart Lighting Bridges
    "Low": 0.85         # Isolated Lab Test Benches
}

# Network Zones
NETWORK_ZONES = [
    "Surveillance Zone (CCTV)",
    "Management Network",
    "Core Campus LAN",
    "Lab / Testing Sandbox",
    "Guest / Untrusted IoT"
]

# Verification Status Taxonomy
VERIFICATION_STATUSES = {
    "CONFIRMED": "Confirmed Technical Finding",
    "POTENTIAL_RISK": "Potential Security Risk",
    "NEEDS_VERIFICATION": "Needs Administrative Verification",
    "INFORMATIONAL": "Informational Observation"
}

# Severity Levels, Score Weights, and UI Badges
SEVERITY_LEVELS = {
    "CRITICAL": {
        "weight": 25,
        "color": "#DC2626",      # Vivid Crimson
        "bg_color": "rgba(220, 38, 38, 0.15)",
        "badge": "CRITICAL",
        "order": 1
    },
    "HIGH": {
        "weight": 15,
        "color": "#F97316",      # Neon Orange
        "bg_color": "rgba(249, 115, 22, 0.15)",
        "badge": "HIGH",
        "order": 2
    },
    "MEDIUM": {
        "weight": 8,
        "color": "#FBBF24",      # Amber Gold
        "bg_color": "rgba(251, 191, 36, 0.15)",
        "badge": "MEDIUM",
        "order": 3
    },
    "LOW": {
        "weight": 3,
        "color": "#3B82F6",      # Bright Cyan / Blue
        "bg_color": "rgba(59, 130, 246, 0.15)",
        "badge": "LOW",
        "order": 4
    },
    "INFORMATIONAL": {
        "weight": 1,
        "color": "#94A3B8",      # Slate Grey
        "bg_color": "rgba(148, 163, 184, 0.15)",
        "badge": "INFO",
        "order": 5
    }
}

# Free NVD CVE API (REST API v2.0)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
DEFAULT_DEMO_MODE = os.getenv("DEFAULT_DEMO_MODE", "True").lower() in ("true", "1", "yes")
DEFAULT_TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SEC", "60"))

# Detection helper for Nmap executable
def get_nmap_path() -> str:
    """
    Locates the Nmap executable across Windows and Linux environments.
    Checks user environment override, system PATH, and standard install locations.
    """
    env_override = os.getenv("NMAP_PATH", "").strip()
    if env_override and shutil.which(env_override):
        return env_override

    path_nmap = shutil.which("nmap")
    if path_nmap:
        return path_nmap

    if platform.system() == "Windows":
        common_win_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe")
        ]
        for p in common_win_paths:
            if os.path.exists(p):
                return p

    elif platform.system() == "Linux":
        common_linux_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/bin/nmap"
        ]
        for p in common_linux_paths:
            if os.path.exists(p):
                return p

    return "nmap"

def is_nmap_available() -> bool:
    """Checks if Nmap is installed and executable on the current system."""
    binary = get_nmap_path()
    return shutil.which(binary) is not None or os.path.exists(binary)
