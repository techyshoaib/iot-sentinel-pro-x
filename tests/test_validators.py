"""
Unit tests for utils/validators.py.
Verifies private IPv4 validation, public IP rejection, loopback handling,
subnet constraints, and shell injection sanitization.
"""

import unittest
from utils.validators import (
    validate_ip_address,
    validate_subnet,
    validate_port_list,
    sanitize_target_string
)

class TestValidators(unittest.TestCase):

    def test_valid_private_ipv4_addresses(self):
        """Tests that standard RFC 1918 private IPv4 addresses pass validation."""
        valid_ips = [
            "192.168.1.1",
            "192.168.1.105",
            "10.0.0.1",
            "10.254.1.50",
            "172.16.0.1",
            "172.31.255.254",
            "127.0.0.1"  # Local loopback authorized for lab testing
        ]
        for ip in valid_ips:
            is_valid, msg, ip_obj = validate_ip_address(ip)
            self.assertTrue(is_valid, f"Expected {ip} to be valid, got error: {msg}")
            self.assertIsNotNone(ip_obj)

    def test_public_ip_rejection(self):
        """Verifies that public IPv4 targets are strictly rejected for safety."""
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "142.250.190.46"
        ]
        for ip in public_ips:
            is_valid, msg, ip_obj = validate_ip_address(ip)
            self.assertFalse(is_valid, f"Public IP {ip} should have been rejected!")
            self.assertIn("PUBLIC IP address", msg)
            self.assertIsNone(ip_obj)

    def test_invalid_ip_formats(self):
        """Verifies rejection of invalid formats, strings, and IPv6."""
        invalid_ips = [
            "",
            "not-an-ip",
            "999.999.999.999",
            "192.168.1",
            "192.168.1.1.1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"  # IPv6
        ]
        for ip in invalid_ips:
            is_valid, msg, ip_obj = validate_ip_address(ip)
            self.assertFalse(is_valid, f"Invalid IP '{ip}' should fail validation")
            self.assertIsNone(ip_obj)

    def test_shell_injection_characters_rejection(self):
        """Ensures strings containing shell metacharacters are rejected."""
        malicious_inputs = [
            "192.168.1.1; cat /etc/passwd",
            "192.168.1.1 | dir",
            "192.168.1.1 && whoami",
            "192.168.1.1`id`",
            "192.168.1.1$(calc)"
        ]
        for bad in malicious_inputs:
            is_valid, msg, _ = validate_ip_address(bad)
            self.assertFalse(is_valid, f"Shell injection payload '{bad}' should be rejected!")
            self.assertIn("Invalid characters", msg)

    def test_validate_subnet_private(self):
        """Tests subnet CIDR validation for RFC 1918 networks."""
        is_valid, msg, net = validate_subnet("192.168.1.0/24")
        self.assertTrue(is_valid)
        self.assertIsNotNone(net)

        # Public subnet should fail
        is_pub, msg_pub, _ = validate_subnet("8.8.8.0/24")
        self.assertFalse(is_pub)
        self.assertIn("not a private network", msg_pub)

        # Excessively large subnet should fail (over 256 hosts)
        is_large, msg_large, _ = validate_subnet("10.0.0.0/16")
        self.assertFalse(is_large)
        self.assertIn("restricted to subnets of 256 hosts", msg_large)

    def test_validate_port_list(self):
        """Tests port parsing and bounds checking."""
        is_valid, msg, ports = validate_port_list("21, 22, 80, 443, 8080")
        self.assertTrue(is_valid)
        self.assertEqual(ports, [21, 22, 80, 443, 8080])

        # Out of bounds port
        is_bad, msg_bad, _ = validate_port_list("80, 99999")
        self.assertFalse(is_bad)
        self.assertIn("out of range", msg_bad)

if __name__ == "__main__":
    unittest.main()
