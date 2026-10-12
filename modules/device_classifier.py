"""
Device Classification & Stable Asset Identification Module.
Heuristically classifies discovered devices into standardized IoT roles:
- CCTV / IP Camera
- Router / Gateway
- Network Switch
- Network Printer
- MQTT Broker / IoT Hub
- Server / Storage (NAS)
- Generic IoT Device

Calculates classification confidence and supporting evidence without intrusive scanning.
Generates deterministic, stable asset identifiers across sequential scans.
"""

import hashlib
import uuid
from typing import List, Dict, Any, Tuple

# Known Hardware Vendor Fingerprints (MAC vendor / string matching)
CCTV_VENDORS = [
    "dahua", "hikvision", "axis communications", "amcrest", "reolink",
    "hanwha", "samsung techwin", "vivotek", "uniview", "flir", "foscam"
]

ROUTER_VENDORS = [
    "tp-link", "cisco", "netgear", "mikrotik", "ubiquiti", "asus",
    "d-link", "linksys", "huawei", "zyxel", "openwrt"
]

PRINTER_VENDORS = [
    "hewlett-packard", "hp inc", "canon", "epson", "brother", "xerox",
    "lexmark", "ricoh", "kyocera"
]

STORAGE_VENDORS = [
    "synology", "qnap", "asustor", "western digital", "netgear ready-nas", "truenas"
]

IOT_SOC_VENDORS = [
    "espressif", "raspberry pi", "arduino", "signify", "philips", "tuya", "sonoff"
]

class DeviceClassifier:
    """Classifies network devices and assigns deterministic asset identifiers."""

    @staticmethod
    def generate_asset_id(mac_address: str, ip_address: str) -> str:
        """
        Generates a stable, deterministic asset UUID.
        Prefers MAC address (hardware bound). Falls back to normalized IP if MAC is missing.
        """
        mac_clean = mac_address.strip().lower().replace("-", ":") if mac_address else ""
        if mac_clean and mac_clean not in ("n/a", "unknown", "00:00:00:00:00:00"):
            seed = f"mac:{mac_clean}"
        else:
            seed = f"ip:{ip_address.strip()}"

        hasher = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        return f"AST-{hasher[:10].upper()}"

    @classmethod
    def classify_device(
        cls,
        ip_address: str,
        services: List[Dict[str, Any]],
        vendor: str = "",
        hostname: str = ""
    ) -> Dict[str, Any]:
        """
        Analyzes discovered ports, services, banners, vendor, and hostname
        to determine the most probable device classification.
        """
        open_ports = {s.get("port") for s in services if s.get("state", "open") == "open"}
        banners_text = " ".join([
            f"{s.get('service_name', '')} {s.get('product', '')} {s.get('version', '')} {s.get('banner', '')}"
            for s in services
        ]).lower()

        vendor_lower = vendor.lower() if vendor else ""
        host_lower = hostname.lower() if hostname else ""

        evidence = []
        score_cctv = 0
        score_router = 0
        score_printer = 0
        score_mqtt = 0
        score_nas = 0
        score_switch = 0

        # --- Indicator 1: CCTV / Surveillance Camera ---
        if 554 in open_ports:
            score_cctv += 60
            evidence.append("RTSP (554/tcp) video stream port active")
        if any(p in open_ports for p in (8000, 37777)):
            score_cctv += 40
            evidence.append("Surveillance media management port (8000/37777) open")
        if any(cv in vendor_lower for cv in CCTV_VENDORS):
            score_cctv += 45
            evidence.append(f"MAC vendor '{vendor}' matches known camera manufacturer")
        if any(k in host_lower for k in ("cam", "cctv", "dvr", "nvr", "ipcam")):
            score_cctv += 30
            evidence.append(f"Hostname '{hostname}' suggests surveillance device")
        if any(b in banners_text for b in ("live555", "boa", "onvif", "rtsp", "hikvision", "dahua")):
            score_cctv += 35
            evidence.append("Banner indicates embedded surveillance web/stream server")

        # --- Indicator 2: MQTT Broker / IoT Hub ---
        if 1883 in open_ports:
            score_mqtt += 60
            evidence.append("Standard MQTT (1883/tcp) broker port open")
        if 8883 in open_ports:
            score_mqtt += 60
            evidence.append("Secure MQTT (8883/tcp) broker port open")
        if any(b in banners_text for b in ("mosquitto", "emqx", "hivemq", "mqtt")):
            score_mqtt += 40
            evidence.append("Service banner confirms MQTT messaging engine")

        # --- Indicator 3: Router / Gateway ---
        last_octet = ip_address.split(".")[-1] if "." in ip_address else ""
        if last_octet in ("1", "254"):
            score_router += 30
            evidence.append(f"IP address ({ip_address}) is standard gateway position (.1 / .254)")
        if 53 in open_ports and (80 in open_ports or 443 in open_ports):
            score_router += 35
            evidence.append("DNS resolver combined with HTTP/HTTPS web management interface")
        if any(rv in vendor_lower for rv in ROUTER_VENDORS):
            score_router += 40
            evidence.append(f"MAC vendor '{vendor}' matches known router/gateway maker")
        if any(k in host_lower for k in ("router", "gateway", "openwrt", "gateway")):
            score_router += 30
            evidence.append(f"Hostname '{hostname}' matches router naming convention")

        # --- Indicator 4: Network Printer ---
        if any(p in open_ports for p in (9100, 631, 515)):
            score_printer += 70
            evidence.append("Direct printing port (9100/631/515) active")
        if any(pv in vendor_lower for pv in PRINTER_VENDORS):
            score_printer += 40
            evidence.append(f"MAC vendor '{vendor}' matches printer manufacturer")

        # --- Indicator 5: Server / NAS Storage ---
        if 21 in open_ports and 22 in open_ports:
            score_nas += 35
            evidence.append("FTP and SSH simultaneously open for file management")
        if any(sv in vendor_lower for sv in STORAGE_VENDORS):
            score_nas += 50
            evidence.append(f"MAC vendor '{vendor}' matches NAS hardware vendor")

        # Decision Matrix
        max_score = max(score_cctv, score_router, score_printer, score_mqtt, score_nas, score_switch, 0)

        if max_score < 25:
            # Fallback to Generic IoT
            device_type = "Generic IoT Device"
            confidence = "Low"
            evidence_summary = ["No definitive hardware signatures observed; classified as generic IoT endpoint."]
        elif score_cctv == max_score and score_cctv >= 35:
            device_type = "CCTV / IP Camera"
            confidence = "High" if score_cctv >= 60 else "Medium"
            evidence_summary = [e for e in evidence if any(k in e.lower() for k in ("rtsp", "camera", "cctv", "media", "live555", "8000"))] or evidence
        elif score_mqtt == max_score and score_mqtt >= 40:
            device_type = "MQTT Broker / IoT Hub"
            confidence = "High" if score_mqtt >= 60 else "Medium"
            evidence_summary = [e for e in evidence if "mqtt" in e.lower()] or evidence
        elif score_printer == max_score and score_printer >= 40:
            device_type = "Network Printer"
            confidence = "High" if score_printer >= 70 else "Medium"
            evidence_summary = [e for e in evidence if any(k in e.lower() for k in ("printer", "printing", "9100", "631"))] or evidence
        elif score_nas == max_score and score_nas >= 40:
            device_type = "Server / Storage (NAS)"
            confidence = "High" if score_nas >= 60 else "Medium"
            evidence_summary = [e for e in evidence if any(k in e.lower() for k in ("nas", "ftp", "storage"))] or evidence
        elif score_router == max_score and score_router >= 35:
            device_type = "Router / Gateway"
            confidence = "High" if score_router >= 60 else "Medium"
            evidence_summary = [e for e in evidence if any(k in e.lower() for k in ("gateway", "router", "dns", "openwrt"))] or evidence
        else:
            device_type = "Generic IoT Device"
            confidence = "Medium"
            evidence_summary = evidence or ["Basic TCP service profile matched."]

        return {
            "device_type": device_type,
            "confidence": confidence,
            "evidence": evidence_summary,
            "classification_score": max_score
        }
