"""
Network Device Discovery Module for IoT Sentinel Pro — Campus Edition.
Discovers reachable hosts within authorized private IPv4 subnets.
Performs device classification, stable asset identification, and duplicate resolution.
Supports both live safe Nmap sweeps and 100% Offline Demo Mode simulation.
"""

import subprocess
import xml.etree.ElementTree as ET
import time
from typing import List, Dict, Any, Tuple
from utils.config import get_nmap_path, is_nmap_available
from utils.validators import validate_subnet
from modules.device_classifier import DeviceClassifier

# Realistic Simulated Subnet Assets for Offline Demo Mode
DEMO_SUBNET_DEVICES = [
    {
        "ip_address": "192.168.1.1",
        "mac_address": "50:D4:F7:2C:99:01",
        "hostname": "gateway.campus.local",
        "vendor": "TP-Link Technologies Co.",
        "device_type": "Router / Gateway",
        "classification_confidence": "High",
        "classification_evidence": ["IP is default gateway (.1)", "Vendor indicates TP-Link network equipment"],
        "asset_criticality": "Critical",
        "expected_zone": "Management Network",
        "user_label": "Campus Subnet Gateway",
        "status": "up"
    },
    {
        "ip_address": "192.168.1.105",
        "mac_address": "3C:E3:6B:4A:11:89",
        "hostname": "ipcam-north-gate.lan",
        "vendor": "Zhejiang Dahua Technology Co.",
        "device_type": "CCTV / IP Camera",
        "classification_confidence": "High",
        "classification_evidence": ["MAC vendor indicates Dahua Technology", "Hostname contains 'ipcam'"],
        "asset_criticality": "High",
        "expected_zone": "Surveillance Zone (CCTV)",
        "user_label": "North Perimeter IP Camera",
        "status": "up"
    },
    {
        "ip_address": "192.168.1.142",
        "mac_address": "24:6F:28:B1:77:43",
        "hostname": "sensor-node-env01.iot",
        "vendor": "Espressif Inc (ESP32)",
        "device_type": "MQTT Broker / IoT Hub",
        "classification_confidence": "High",
        "classification_evidence": ["MAC vendor indicates Espressif Systems (ESP32)", "Hostname matches IoT sensor bus"],
        "asset_criticality": "Medium",
        "expected_zone": "Lab / Testing Sandbox",
        "user_label": "Environmental Sensor Node",
        "status": "up"
    },
    {
        "ip_address": "192.168.1.200",
        "mac_address": "00:11:32:8A:F4:55",
        "hostname": "nas-backup.campus.local",
        "vendor": "Synology Inc.",
        "device_type": "Server / Storage (NAS)",
        "classification_confidence": "High",
        "classification_evidence": ["MAC vendor indicates Synology Storage hardware"],
        "asset_criticality": "High",
        "expected_zone": "Core Campus LAN",
        "user_label": "Central Storage Server",
        "status": "up"
    },
    {
        "ip_address": "192.168.1.75",
        "mac_address": "00:17:88:65:E2:10",
        "hostname": "hue-bridge.local",
        "vendor": "Signify Netherlands (Philips Hue)",
        "device_type": "Generic IoT Device",
        "classification_confidence": "High",
        "classification_evidence": ["MAC vendor indicates Signify / Philips Hue smart lighting bridge"],
        "asset_criticality": "Low",
        "expected_zone": "Guest / Untrusted IoT",
        "user_label": "Lab Lighting Bridge",
        "status": "up"
    }
]

def discover_network(
    subnet_cidr: str,
    demo_mode: bool = True,
    timeout: int = 30
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Sweeps an authorized private subnet for reachable hosts with classification.
    
    Returns:
        (success: bool, status_message: str, devices_list: List[Dict])
    """
    # 1. Scope Validation
    is_valid, msg, net_obj = validate_subnet(subnet_cidr)
    if not is_valid:
        return False, msg, []

    # 2. Offline Demo Mode Simulation
    if demo_mode:
        time.sleep(1.0)  # Simulated latency for realistic UX
        base_net = str(net_obj.network_address).rsplit(".", 1)[0]
        adapted_devices = []
        for dev in DEMO_SUBNET_DEVICES:
            dev_copy = dict(dev)
            host_suffix = dev["ip_address"].split(".")[-1]
            dev_copy["ip_address"] = f"{base_net}.{host_suffix}"
            dev_copy["asset_id"] = DeviceClassifier.generate_asset_id(dev_copy["mac_address"], dev_copy["ip_address"])
            adapted_devices.append(dev_copy)

        return True, f"[DEMO MODE] Successfully discovered {len(adapted_devices)} simulated IoT endpoints in {subnet_cidr}.", adapted_devices

    # 3. Live Safe Scanning with Nmap
    if not is_nmap_available():
        return False, (
            "Nmap binary was not found on your system. "
            "Please install Nmap or activate 'Demo Mode' in the sidebar to simulate realistic IoT endpoints."
        ), []

    nmap_bin = get_nmap_path()
    cmd = [
        nmap_bin,
        "-sn",              # Ping / ARP host discovery only
        "-oX", "-",         # XML output to stdout
        "--host-timeout", "10s",
        "--max-retries", "1",
        subnet_cidr
    ]

    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False  # Secure argument array execution prevents injection
        )

        if process.returncode != 0 and not process.stdout:
            err_msg = process.stderr.strip() or f"Nmap exited with code {process.returncode}"
            return False, f"Discovery error: {err_msg}", []

        # Parse XML with size protection (max 10MB)
        if len(process.stdout) > 10_000_000:
            return False, "Nmap XML output exceeded safe buffer size limit (10MB).", []

        devices = parse_nmap_discovery_xml(process.stdout)

        # De-duplicate devices by IP address
        seen_ips = set()
        deduped = []
        for d in devices:
            if d["ip_address"] not in seen_ips:
                seen_ips.add(d["ip_address"])
                deduped.append(d)

        return True, f"Live discovery completed. Found {len(deduped)} active hosts on {subnet_cidr}.", deduped

    except subprocess.TimeoutExpired:
        return False, f"Discovery sweep timed out after {timeout} seconds.", []
    except Exception as ex:
        return False, f"Discovery failed with error: {str(ex)}", []

def parse_nmap_discovery_xml(xml_content: str) -> List[Dict[str, Any]]:
    """Parses Nmap XML output from a host discovery sweep."""
    devices = []
    if not xml_content:
        return devices

    try:
        root = ET.fromstring(xml_content)
        for host in root.findall("host"):
            status_elem = host.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue

            ip_address = ""
            mac_address = "N/A"
            vendor = "Unknown Vendor"

            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4":
                    ip_address = addr.get("addr", "")
                elif addr_type == "mac":
                    mac_address = addr.get("addr", "N/A")
                    vendor = addr.get("vendor", "Unknown Vendor")

            # Hostname parsing
            hostname = "Unknown"
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                h_elem = hostnames_elem.find("hostname")
                if h_elem is not None:
                    hostname = h_elem.get("name", "Unknown")

            if ip_address:
                # Initial classification from discovery metadata
                classification = DeviceClassifier.classify_device(
                    ip_address=ip_address,
                    services=[],
                    vendor=vendor,
                    hostname=hostname
                )
                asset_id = DeviceClassifier.generate_asset_id(mac_address, ip_address)

                devices.append({
                    "asset_id": asset_id,
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": classification["device_type"],
                    "classification_confidence": classification["confidence"],
                    "classification_evidence": classification["evidence"],
                    "asset_criticality": "Medium",
                    "expected_zone": "Core Campus LAN",
                    "user_label": "",
                    "status": "up"
                })

    except ET.ParseError:
        pass

    return devices
