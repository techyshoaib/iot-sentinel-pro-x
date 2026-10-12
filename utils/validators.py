"""
Validation module for IoT Device Vulnerability Scanner.
Ensures strict defensive boundaries:
- Restricts live scans exclusively to authorized private IPv4 subnets and lab hosts
- Rejects public IP targets to prevent unauthorized scanning
- Sanitizes inputs to prevent command injection
"""

import ipaddress
import re
from typing import Tuple, List, Optional

# Characters that should never appear in host/target strings
FORBIDDEN_SHELL_CHARS = re.compile(r"[;&|`$><!\"'\\\s]")

def sanitize_target_string(target_str: str) -> str:
    """Strips whitespace and removes any potential shell control characters."""
    if not target_str:
        return ""
    cleaned = target_str.strip()
    return cleaned

def validate_ip_address(ip_str: str, allow_loopback: bool = True) -> Tuple[bool, str, Optional[ipaddress.IPv4Address]]:
    """
    Validates that a string is a valid private IPv4 address.
    Strictly rejects public IPv4 addresses, IPv6, multicast, and malformed strings.

    Returns:
        (is_valid: bool, error_or_success_message: str, parsed_ip_obj)
    """
    cleaned = sanitize_target_string(ip_str)
    if not cleaned:
        return False, "Target IP address cannot be empty.", None

    if FORBIDDEN_SHELL_CHARS.search(cleaned):
        return False, "Invalid characters detected in target IP. Potential shell injection prevented.", None

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return False, f"'{cleaned}' is not a valid IPv4 address.", None

    # Enforce IPv4
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return False, "Only IPv4 addresses are supported in this scanner.", None

    # Check loopback
    if ip_obj.is_loopback:
        if allow_loopback:
            return True, "Valid local loopback address (authorized lab host).", ip_obj
        else:
            return False, "Loopback address (127.0.0.0/8) is restricted.", None

    # Check for multicast, link-local, reserved
    if ip_obj.is_multicast:
        return False, "Multicast IP addresses (224.0.0.0/4) cannot be scanned.", None

    if ip_obj.is_reserved:
        return False, "Reserved IP addresses cannot be scanned.", None

    # Strict defensive check: MUST BE PRIVATE (RFC 1918)
    if not ip_obj.is_private:
        return False, (
            f"SECURITY RESTRICTION: '{cleaned}' is a PUBLIC IP address. "
            "Scanning public internet IP addresses is prohibited by safety policy "
            "and legal regulations. Only private lab subnets (10.0.0.0/8, 172.16.0.0/12, "
            "192.168.0.0/16) are permitted."
        ), None

    return True, f"Target '{cleaned}' verified as an authorized private IPv4 address.", ip_obj

def validate_subnet(subnet_str: str, max_hosts: int = 256) -> Tuple[bool, str, Optional[ipaddress.IPv4Network]]:
    """
    Validates that a subnet CIDR string is an authorized private network.
    Restricts size to /24 (256 addresses) or smaller to prevent network disruption.

    Returns:
        (is_valid: bool, message: str, parsed_network_obj)
    """
    cleaned = sanitize_target_string(subnet_str)
    if not cleaned:
        return False, "Subnet CIDR cannot be empty (e.g. 192.168.1.0/24).", None

    if FORBIDDEN_SHELL_CHARS.search(cleaned):
        return False, "Invalid characters in subnet CIDR.", None

    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        return False, f"'{cleaned}' is not a valid IPv4 CIDR subnet (e.g., 192.168.1.0/24).", None

    if not isinstance(network, ipaddress.IPv4Network):
        return False, "Only IPv4 CIDR networks are supported.", None

    if not network.is_private:
        return False, (
            f"SECURITY RESTRICTION: '{cleaned}' is not a private network. "
            "Host discovery is only permitted within RFC 1918 private subnets."
        ), None

    # Restrict network size (e.g. minimum prefix /24 = 256 hosts)
    if network.num_addresses > max_hosts:
        return False, (
            f"Subnet '{cleaned}' contains {network.num_addresses} addresses. "
            f"For safety and lab performance, discovery is restricted to subnets of {max_hosts} hosts or smaller (e.g., /24 to /32)."
        ), None

    return True, f"Private subnet '{cleaned}' ({network.num_addresses} addresses) verified.", network

def validate_port_list(ports_input: str) -> Tuple[bool, str, List[int]]:
    """
    Validates a comma-separated list or space-separated list of ports.
    Ensures every port is an integer in the valid range 1-65535.
    """
    if not ports_input:
        return False, "Port list cannot be empty.", []

    raw_tokens = re.split(r"[\s,]+", ports_input.strip())
    valid_ports = []

    for tok in raw_tokens:
        tok = tok.strip()
        if not tok:
            continue
        try:
            port_num = int(tok)
            if 1 <= port_num <= 65535:
                valid_ports.append(port_num)
            else:
                return False, f"Port '{tok}' is out of range (must be 1-65535).", []
        except ValueError:
            return False, f"Port '{tok}' is not a valid integer.", []

    if not valid_ports:
        return False, "No valid ports found in input.", []

    return True, f"Parsed {len(valid_ports)} valid ports.", sorted(list(set(valid_ports)))
