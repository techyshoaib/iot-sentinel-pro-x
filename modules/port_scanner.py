"""
Controlled Port Scanner Module for IoT Sentinel Pro — Campus Edition.
Performs safe, non-destructive TCP port enumeration and service version detection.
Enforces buffer size limits, timeouts, cancellation safety, and realistic IoT profiles.
"""

import subprocess
import xml.etree.ElementTree as ET
import time
from typing import List, Dict, Any, Tuple, Optional
from utils.config import (
    DEFAULT_PORT_LIST,
    IOT_COMMON_PORTS,
    get_nmap_path,
    is_nmap_available,
    DEFAULT_TIMEOUT
)
from utils.validators import validate_ip_address

# Realistic Offline Demo Profiles
DEMO_PORT_PROFILES = {
    "camera": [
        {"port": 80, "protocol": "tcp", "service_name": "http", "product": "Boa", "version": "0.94.14", "state": "open", "banner": "server: Boa/0.94.14"},
        {"port": 554, "protocol": "tcp", "service_name": "rtsp", "product": "Live555", "version": "2016.11.28", "state": "open", "banner": "RTSP/1.0 200 OK | Live555 Media"},
        {"port": 8080, "protocol": "tcp", "service_name": "http-alt", "product": "lighttpd", "version": "1.4.35", "state": "open", "banner": "server: lighttpd/1.4.35"}
    ],
    "gateway": [
        {"port": 22, "protocol": "tcp", "service_name": "ssh", "product": "Dropbear", "version": "2016.74", "state": "open", "banner": "SSH-2.0-dropbear_2016.74"},
        {"port": 23, "protocol": "tcp", "service_name": "telnet", "product": "BusyBox telnetd", "version": "1.24.1", "state": "open", "banner": "BusyBox v1.24.1 login:"},
        {"port": 80, "protocol": "tcp", "service_name": "http", "product": "uHTTPd", "version": "1.0", "state": "open", "banner": "server: uHTTPd"},
        {"port": 1883, "protocol": "tcp", "service_name": "mqtt", "product": "Mosquitto", "version": "1.4.15", "state": "open", "banner": "MQTT v3.1.1 Broker"}
    ],
    "sensor": [
        {"port": 80, "protocol": "tcp", "service_name": "http", "product": "Espressif HTTP Server", "version": "1.0", "state": "open", "banner": "server: ESP-HTTPD"},
        {"port": 1883, "protocol": "tcp", "service_name": "mqtt", "product": "Mosquitto", "version": "2.0.11", "state": "open", "banner": "MQTT telemetry bridge"}
    ],
    "nas": [
        {"port": 21, "protocol": "tcp", "service_name": "ftp", "product": "ProFTPD", "version": "1.3.5", "state": "open", "banner": "220 ProFTPD 1.3.5 Server ready"},
        {"port": 22, "protocol": "tcp", "service_name": "ssh", "product": "OpenSSH", "version": "7.4p1", "state": "open", "banner": "SSH-2.0-OpenSSH_7.4p1"},
        {"port": 80, "protocol": "tcp", "service_name": "http", "product": "Apache", "version": "2.4.25", "state": "open", "banner": "Apache/2.4.25"},
        {"port": 443, "protocol": "tcp", "service_name": "https", "product": "Apache", "version": "2.4.25", "state": "open", "banner": "Apache/2.4.25 SSL"}
    ],
    "printer": [
        {"port": 80, "protocol": "tcp", "service_name": "http", "product": "HP Web Admin", "version": "4.0", "state": "open", "banner": "HP-ChaiSOE/4.0"},
        {"port": 631, "protocol": "tcp", "service_name": "ipp", "product": "CUPS/IPP", "version": "2.2", "state": "open", "banner": "IPP Server 2.2"}
    ]
}

def scan_target_device(
    target_ip: str,
    ports: Optional[List[int]] = None,
    demo_mode: bool = True,
    timeout: int = DEFAULT_TIMEOUT
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Performs port scanning and service detection against a target IPv4 address.
    
    Returns:
        (success: bool, status_message: str, open_services: List[Dict])
    """
    # 1. Target Validation
    is_valid, msg, ip_obj = validate_ip_address(target_ip)
    if not is_valid:
        return False, msg, []

    ports_to_scan = ports if ports else DEFAULT_PORT_LIST

    # 2. Offline Demo Mode
    if demo_mode:
        time.sleep(1.2)  # Realistic simulation delay
        last_octet = target_ip.split(".")[-1]

        if last_octet in ("105", "10", "11"):
            base_profile = DEMO_PORT_PROFILES["camera"]
        elif last_octet in ("1", "254"):
            base_profile = DEMO_PORT_PROFILES["gateway"]
        elif last_octet in ("142", "42", "50"):
            base_profile = DEMO_PORT_PROFILES["sensor"]
        elif last_octet in ("200", "201", "202"):
            base_profile = DEMO_PORT_PROFILES["nas"]
        elif last_octet in ("75", "76"):
            base_profile = DEMO_PORT_PROFILES["printer"]
        else:
            base_profile = DEMO_PORT_PROFILES["gateway"]

        matched_services = []
        for s in base_profile:
            if s["port"] in ports_to_scan:
                s_copy = dict(s)
                s_copy["device_ip"] = target_ip
                matched_services.append(s_copy)

        return True, f"[DEMO MODE] Simulated scan completed. Identified {len(matched_services)} open services on {target_ip}.", matched_services

    # 3. Live Safe Scanning with Nmap
    if not is_nmap_available():
        return False, (
            "Nmap executable not detected on this system. "
            "Please install Nmap or activate 'Demo Mode' in the sidebar to simulate realistic IoT scans."
        ), []

    nmap_bin = get_nmap_path()
    port_str = ",".join(str(p) for p in ports_to_scan)

    # Safe Non-Destructive Nmap Flags:
    # -sT: TCP Connect scan (safe unprivileged scanning, does not send malformed TCP packets)
    # -sV: Safe service version detection
    # --version-light: Quick and light probes to avoid crashing microcontrollers
    # -Pn: Assume host online (handles hosts blocking ICMP ping)
    cmd = [
        nmap_bin,
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "-p", port_str,
        "-oX", "-",
        "--max-retries", "1",
        "--host-timeout", f"{timeout}s",
        target_ip
    ]

    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 5,
            shell=False  # Secure: prevents shell command injection
        )

        if process.returncode != 0 and not process.stdout:
            err_msg = process.stderr.strip() or f"Nmap exited with code {process.returncode}"
            return False, f"Port scan failed: {err_msg}", []

        # XML size safety check (max 10MB)
        if len(process.stdout) > 10_000_000:
            return False, "Nmap scan output exceeded safe XML size limit (10MB).", []

        # Parse XML
        services = parse_nmap_port_xml(process.stdout, target_ip)
        return True, f"Live scan completed. Discovered {len(services)} open ports on {target_ip}.", services

    except subprocess.TimeoutExpired:
        return False, f"Scan timed out after {timeout} seconds. The target may be offline or dropping packets.", []
    except Exception as ex:
        return False, f"Scan execution error: {str(ex)}", []

def parse_nmap_port_xml(xml_content: str, target_ip: str) -> List[Dict[str, Any]]:
    """Parses Nmap XML output for open ports, service names, and version info."""
    services = []
    if not xml_content:
        return services

    try:
        root = ET.fromstring(xml_content)
        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_id = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = "unknown"
                product = ""
                version = ""
                banner = ""

                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extrainfo = service_elem.get("extrainfo", "")
                    
                    banner_parts = [p for p in (product, version, extrainfo) if p]
                    banner = " ".join(banner_parts)

                if service_name == "unknown" and port_id in IOT_COMMON_PORTS:
                    service_name = IOT_COMMON_PORTS[port_id]["service"].lower()

                services.append({
                    "device_ip": target_ip,
                    "port": port_id,
                    "protocol": protocol,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "state": "open",
                    "banner": banner
                })

    except ET.ParseError:
        pass

    return services
