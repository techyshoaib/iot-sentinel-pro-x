"""
Network Diagnostics Module for IoT Sentinel Pro X.
Provides multi-network connectivity diagnostics, interface enumeration,
target reachability checking, and network restriction analysis.

Supports assessment of devices on:
- Same Wi-Fi or Ethernet network
- Phone hotspot
- Routed remote subnets
- Networks accessible through virtual machines (Kali Linux)
"""

import socket
import subprocess
import platform
import ipaddress
import re
import struct
import time
from typing import List, Dict, Any, Optional, Tuple


class NetworkDiagnostics:
    """Multi-network connectivity and diagnostics engine."""

    @classmethod
    def get_system_interfaces(cls) -> List[Dict[str, Any]]:
        """
        Enumerates available network interfaces with IP addresses and subnets.
        Cross-platform: works on Windows, Linux, and macOS.
        """
        interfaces = []
        system = platform.system()

        try:
            if system == "Windows":
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True, text=True, timeout=10, shell=False
                )
                interfaces = cls._parse_ipconfig(result.stdout)
            else:
                # Linux / macOS
                result = subprocess.run(
                    ["ip", "addr", "show"],
                    capture_output=True, text=True, timeout=10, shell=False
                )
                if result.returncode == 0:
                    interfaces = cls._parse_ip_addr(result.stdout)
                else:
                    # Fallback to ifconfig
                    result = subprocess.run(
                        ["ifconfig"],
                        capture_output=True, text=True, timeout=10, shell=False
                    )
                    interfaces = cls._parse_ifconfig(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Fallback: at minimum include the local hostname's address
        if not interfaces:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                interfaces.append({
                    "name": "default",
                    "ip_address": local_ip,
                    "subnet_mask": "255.255.255.0",
                    "gateway": "Unknown",
                    "type": "Unknown",
                    "status": "up",
                    "note": "Detected via hostname resolution fallback"
                })
            except socket.gaierror:
                pass

        return interfaces

    @classmethod
    def _parse_ipconfig(cls, output: str) -> List[Dict[str, Any]]:
        """Parses Windows ipconfig /all output."""
        interfaces = []
        current_iface = None
        lines = output.split("\n")

        for line in lines:
            line = line.rstrip()
            # New adapter section
            if line and not line.startswith(" ") and "adapter" in line.lower():
                if current_iface and current_iface.get("ip_address"):
                    interfaces.append(current_iface)
                adapter_name = line.split("adapter")[-1].strip().rstrip(":")
                current_iface = {
                    "name": adapter_name,
                    "ip_address": "",
                    "subnet_mask": "",
                    "gateway": "",
                    "type": "Ethernet" if "ethernet" in line.lower() else "Wi-Fi" if "wi-fi" in line.lower() or "wireless" in line.lower() else "Other",
                    "status": "up",
                    "mac_address": "",
                    "note": ""
                }
            elif current_iface:
                stripped = line.strip()
                if "IPv4 Address" in stripped or "IP Address" in stripped:
                    match = re.search(r':\s*([\d.]+)', stripped)
                    if match:
                        current_iface["ip_address"] = match.group(1)
                elif "Subnet Mask" in stripped:
                    match = re.search(r':\s*([\d.]+)', stripped)
                    if match:
                        current_iface["subnet_mask"] = match.group(1)
                elif "Default Gateway" in stripped:
                    match = re.search(r':\s*([\d.]+)', stripped)
                    if match:
                        current_iface["gateway"] = match.group(1)
                elif "Physical Address" in stripped:
                    match = re.search(r':\s*([0-9A-Fa-f-]+)', stripped)
                    if match:
                        current_iface["mac_address"] = match.group(1)
                elif "Media disconnected" in stripped:
                    current_iface["status"] = "down"

        if current_iface and current_iface.get("ip_address"):
            interfaces.append(current_iface)

        return interfaces

    @classmethod
    def _parse_ip_addr(cls, output: str) -> List[Dict[str, Any]]:
        """Parses Linux 'ip addr show' output."""
        interfaces = []
        current_iface = None
        lines = output.split("\n")

        for line in lines:
            # Interface header line
            iface_match = re.match(r'^\d+:\s+(\S+):', line)
            if iface_match:
                if current_iface and current_iface.get("ip_address"):
                    interfaces.append(current_iface)
                name = iface_match.group(1)
                status = "up" if "UP" in line else "down"
                current_iface = {
                    "name": name,
                    "ip_address": "",
                    "subnet_mask": "",
                    "gateway": "",
                    "type": cls._guess_interface_type(name),
                    "status": status,
                    "mac_address": "",
                    "note": ""
                }
            elif current_iface:
                # MAC address
                mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', line)
                if mac_match:
                    current_iface["mac_address"] = mac_match.group(1)
                # IPv4 address
                ip_match = re.search(r'inet\s+([\d.]+)/(\d+)', line)
                if ip_match:
                    current_iface["ip_address"] = ip_match.group(1)
                    prefix = int(ip_match.group(2))
                    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                    current_iface["subnet_mask"] = socket.inet_ntoa(struct.pack('>I', mask_int))

        if current_iface and current_iface.get("ip_address"):
            interfaces.append(current_iface)

        return interfaces

    @classmethod
    def _parse_ifconfig(cls, output: str) -> List[Dict[str, Any]]:
        """Parses macOS/Linux ifconfig output."""
        interfaces = []
        current_iface = None
        lines = output.split("\n")

        for line in lines:
            iface_match = re.match(r'^(\S+?):\s+', line) or re.match(r'^(\S+)\s+', line)
            if iface_match and not line.startswith(" ") and not line.startswith("\t"):
                if current_iface and current_iface.get("ip_address"):
                    interfaces.append(current_iface)
                name = iface_match.group(1).rstrip(":")
                current_iface = {
                    "name": name,
                    "ip_address": "",
                    "subnet_mask": "",
                    "gateway": "",
                    "type": cls._guess_interface_type(name),
                    "status": "up" if "UP" in line else "down",
                    "mac_address": "",
                    "note": ""
                }
            elif current_iface:
                ip_match = re.search(r'inet\s+([\d.]+)', line)
                if ip_match:
                    current_iface["ip_address"] = ip_match.group(1)
                mask_match = re.search(r'netmask\s+([\d.]+|0x[0-9a-f]+)', line, re.IGNORECASE)
                if mask_match:
                    mask_val = mask_match.group(1)
                    if mask_val.startswith("0x"):
                        mask_int = int(mask_val, 16)
                        current_iface["subnet_mask"] = socket.inet_ntoa(struct.pack('>I', mask_int))
                    else:
                        current_iface["subnet_mask"] = mask_val

        if current_iface and current_iface.get("ip_address"):
            interfaces.append(current_iface)

        return interfaces

    @staticmethod
    def _guess_interface_type(name: str) -> str:
        """Heuristically guesses interface type from name."""
        name_lower = name.lower()
        if "wlan" in name_lower or "wl" in name_lower or "wi-fi" in name_lower:
            return "Wi-Fi"
        elif "eth" in name_lower or "en" in name_lower:
            return "Ethernet"
        elif "lo" == name_lower:
            return "Loopback"
        elif "vmnet" in name_lower or "vbox" in name_lower or "virbr" in name_lower:
            return "Virtual (VM)"
        elif "docker" in name_lower or "br-" in name_lower:
            return "Container Bridge"
        elif "tun" in name_lower or "tap" in name_lower:
            return "VPN Tunnel"
        return "Other"

    @classmethod
    def get_default_gateway(cls) -> Optional[str]:
        """Attempts to detect the default gateway IP address."""
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True, text=True, timeout=10, shell=False
                )
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0":
                        gw = parts[2]
                        try:
                            ipaddress.ip_address(gw)
                            return gw
                        except ValueError:
                            continue
            else:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=10, shell=False
                )
                match = re.search(r'default via ([\d.]+)', result.stdout)
                if match:
                    return match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return None

    @classmethod
    def check_target_reachability(
        cls,
        target_ip: str,
        timeout_sec: int = 3,
        method: str = "tcp_ping"
    ) -> Dict[str, Any]:
        """
        Checks if a target IP is reachable from the scanner host.
        Uses TCP connect probe (port 80) as a safe, unprivileged test.
        Never sends ICMP raw packets (may require root).
        """
        result = {
            "target": target_ip,
            "reachable": False,
            "method": method,
            "latency_ms": None,
            "error": None
        }

        if method == "tcp_ping":
            # Try common ports in order
            test_ports = [80, 443, 22, 554, 8080]
            for port in test_ports:
                try:
                    start = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout_sec)
                    conn_result = sock.connect_ex((target_ip, port))
                    elapsed = (time.time() - start) * 1000
                    sock.close()

                    if conn_result == 0:
                        result["reachable"] = True
                        result["latency_ms"] = round(elapsed, 1)
                        result["method"] = f"TCP connect port {port}"
                        return result
                except (socket.timeout, socket.error, OSError):
                    continue
            result["error"] = "No response on common TCP ports (80, 443, 22, 554, 8080)"

        elif method == "icmp_ping":
            # Use system ping (works without raw sockets)
            system = platform.system()
            try:
                count_flag = "-n" if system == "Windows" else "-c"
                timeout_flag = "-w" if system == "Windows" else "-W"
                timeout_val = str(timeout_sec * 1000) if system == "Windows" else str(timeout_sec)
                cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, target_ip]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout_sec + 2, shell=False
                )
                if proc.returncode == 0:
                    result["reachable"] = True
                    # Extract RTT
                    rtt_match = re.search(r'time[=<]\s*([\d.]+)', proc.stdout)
                    if rtt_match:
                        result["latency_ms"] = float(rtt_match.group(1))
                    result["method"] = "ICMP ping"
                else:
                    result["error"] = "ICMP ping failed (host may block ICMP or be unreachable)"
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                result["error"] = f"Ping failed: {str(e)}"

        return result

    @classmethod
    def get_routing_table(cls) -> List[Dict[str, str]]:
        """Retrieves the system routing table for diagnostic display."""
        routes = []
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(
                    ["route", "print"],
                    capture_output=True, text=True, timeout=10, shell=False
                )
                in_routes = False
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if "Network Destination" in line:
                        in_routes = True
                        continue
                    if in_routes and line:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                ipaddress.ip_address(parts[0].split("/")[0])
                                routes.append({
                                    "destination": parts[0],
                                    "netmask": parts[1] if len(parts) > 1 else "",
                                    "gateway": parts[2] if len(parts) > 2 else "",
                                    "interface": parts[3] if len(parts) > 3 else "",
                                    "metric": parts[4] if len(parts) > 4 else ""
                                })
                            except ValueError:
                                if "==" in line:
                                    in_routes = False
            else:
                result = subprocess.run(
                    ["ip", "route", "show"],
                    capture_output=True, text=True, timeout=10, shell=False
                )
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        route = {"destination": parts[0] if parts else ""}
                        for i, p in enumerate(parts):
                            if p == "via" and i + 1 < len(parts):
                                route["gateway"] = parts[i + 1]
                            elif p == "dev" and i + 1 < len(parts):
                                route["interface"] = parts[i + 1]
                            elif p == "metric" and i + 1 < len(parts):
                                route["metric"] = parts[i + 1]
                        routes.append(route)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return routes

    @classmethod
    def analyze_connectivity_restrictions(
        cls,
        target_ip: str,
        scanner_interfaces: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, str]]:
        """
        Analyzes potential restrictions that may affect target reachability.
        Returns a list of potential restriction warnings.
        """
        restrictions = []
        if scanner_interfaces is None:
            scanner_interfaces = cls.get_system_interfaces()

        try:
            target_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            restrictions.append({
                "type": "INVALID_TARGET",
                "severity": "CRITICAL",
                "description": f"'{target_ip}' is not a valid IP address."
            })
            return restrictions

        # Check if target is on same subnet as any interface
        on_same_subnet = False
        for iface in scanner_interfaces:
            iface_ip = iface.get("ip_address", "")
            mask = iface.get("subnet_mask", "255.255.255.0")
            if not iface_ip:
                continue
            try:
                network = ipaddress.ip_network(f"{iface_ip}/{mask}", strict=False)
                if target_obj in network:
                    on_same_subnet = True
                    break
            except ValueError:
                continue

        if not on_same_subnet:
            restrictions.append({
                "type": "DIFFERENT_SUBNET",
                "severity": "WARNING",
                "description": (
                    f"Target {target_ip} is not on the same subnet as any detected scanner interface. "
                    "Traffic must be routed through a gateway. NAT, firewall rules, and VLAN boundaries "
                    "may block connectivity. Verify routing is configured."
                )
            })

        # Check for hotspot isolation
        for iface in scanner_interfaces:
            if iface.get("type") == "Wi-Fi":
                restrictions.append({
                    "type": "WIFI_ISOLATION",
                    "severity": "INFO",
                    "description": (
                        f"Scanner is connected via Wi-Fi ({iface.get('name', 'unknown')}). "
                        "Some Wi-Fi networks enable client isolation (AP isolation) which prevents "
                        "devices from communicating directly. This is common on phone hotspots, "
                        "guest networks, and public Wi-Fi."
                    )
                })
                break

        # Check for VM interface
        for iface in scanner_interfaces:
            if iface.get("type") in ("Virtual (VM)", "Container Bridge"):
                restrictions.append({
                    "type": "VM_NETWORK",
                    "severity": "INFO",
                    "description": (
                        f"Virtual network interface detected ({iface.get('name', 'unknown')}). "
                        "If targeting devices through a Kali Linux VM, ensure the VM network adapter "
                        "is configured in Bridged mode (not NAT) to reach physical network devices."
                    )
                })
                break

        # Firewall restrictions note
        restrictions.append({
            "type": "FIREWALL_NOTE",
            "severity": "INFO",
            "description": (
                "Host-based firewalls (Windows Firewall, iptables, ufw) and network firewalls "
                "may block outbound connections from the scanner. Verify firewall rules allow "
                "TCP connections to the target on the intended ports."
            )
        })

        return restrictions

    @classmethod
    def run_full_diagnostics(cls) -> Dict[str, Any]:
        """Runs a comprehensive network diagnostics check and returns results."""
        interfaces = cls.get_system_interfaces()
        gateway = cls.get_default_gateway()
        routes = cls.get_routing_table()

        # Gateway reachability
        gateway_reachable = None
        if gateway:
            gateway_reachable = cls.check_target_reachability(gateway, timeout_sec=2, method="icmp_ping")

        return {
            "system": platform.system(),
            "hostname": socket.gethostname(),
            "interfaces": interfaces,
            "default_gateway": gateway,
            "gateway_reachable": gateway_reachable,
            "routing_table": routes[:20],  # Limit to 20 entries
            "diagnostics_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "notes": [
                "Interface enumeration may miss adapters with no IPv4 address assigned.",
                "Gateway reachability uses ICMP ping or TCP probe.",
                "Routing table is provided for diagnostic reference only.",
            ]
        }
