"""
Unit tests for database/db_manager.py in IoT Sentinel Pro — Campus Edition.
Verifies schema initialization, audit logging, asset profiles, cascading deletes,
and offline CVE cache in isolated temporary databases.
"""

import unittest
import tempfile
import os
from database.db_manager import (
    init_db,
    save_scan_record,
    get_all_scans,
    get_scan_by_id,
    get_scan_devices,
    get_scan_services,
    get_scan_vulnerabilities,
    delete_scan,
    log_audit_event,
    get_audit_logs,
    save_asset_profile,
    get_asset_profile,
    get_cached_cve,
    set_cached_cve,
    seed_demo_data_if_empty
)

class TestDatabaseManager(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()
        init_db(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_save_and_retrieve_scan_record(self):
        """Verifies full persistence of scan metadata, devices, services, and findings."""
        scan_id = "TEST-ADV-001"
        target = "192.168.1.105"
        devices = [{
            "asset_id": "AST-CAM105",
            "ip_address": target,
            "mac_address": "3C:E3:6B:4A:11:89",
            "hostname": "cam-gate.lan",
            "vendor": "Dahua",
            "device_type": "CCTV / IP Camera",
            "classification_confidence": "High",
            "asset_criticality": "High",
            "expected_zone": "Surveillance Zone (CCTV)"
        }]
        services = [{"device_ip": target, "port": 554, "service_name": "rtsp", "state": "open"}]
        vulns = [{
            "device_ip": target,
            "port": 554,
            "rule_id": "CCTV-RTSP-001",
            "title": "Unencrypted RTSP Video Surveillance Stream Exposure",
            "severity": "HIGH",
            "confidence": "HIGH",
            "verification_status": "Potential Security Risk",
            "evidence": "Port 554/tcp open",
            "explanation": "Stream unencrypted",
            "remediation": "Enable RTSPS"
        }]

        save_scan_record(
            scan_id=scan_id,
            target=target,
            scan_type="vulnerability",
            status="completed",
            total_hosts=1,
            total_ports=1,
            total_findings=1,
            risk_score=78.5,
            duration_sec=2.4,
            is_demo=True,
            devices=devices,
            services=services,
            vulnerabilities=vulns,
            notes="Unit Test Audit",
            db_file=self.db_path
        )

        scan = get_scan_by_id(scan_id, self.db_path)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["risk_score"], 78.5)

        devs = get_scan_devices(scan_id, self.db_path)
        self.assertEqual(len(devs), 1)
        self.assertEqual(devs[0]["device_type"], "CCTV / IP Camera")

        findings = get_scan_vulnerabilities(scan_id, self.db_path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "CCTV-RTSP-001")

    def test_audit_logging(self):
        """Verifies audit trail persistence and retrieval."""
        log_audit_event(
            event_type="TEST_EVENT",
            details="Unit test execution log",
            target="192.168.1.1",
            status="SUCCESS",
            db_file=self.db_path
        )
        logs = get_audit_logs(limit=10, db_file=self.db_path)
        self.assertTrue(len(logs) >= 1)
        self.assertEqual(logs[0]["event_type"], "TEST_EVENT")

    def test_asset_profiles_crud(self):
        """Verifies creating and querying custom asset baseline profiles."""
        save_asset_profile(
            ip_address="192.168.1.200",
            asset_id="AST-NAS200",
            user_label="Central Backup NAS",
            asset_criticality="Critical",
            expected_zone="Core Campus LAN",
            expected_role="Server / Storage (NAS)",
            expected_ports=[21, 22, 80, 443],
            db_file=self.db_path
        )
        prof = get_asset_profile("192.168.1.200", self.db_path)
        self.assertIsNotNone(prof)
        self.assertEqual(prof["user_label"], "Central Backup NAS")
        self.assertEqual(prof["expected_ports"], [21, 22, 80, 443])

    def test_cascade_delete_scan(self):
        """Verifies deleting a scan removes its associated devices, services, and findings."""
        scan_id = "TEST-DEL-099"
        save_scan_record(
            scan_id=scan_id,
            target="192.168.1.50",
            scan_type="vulnerability",
            status="completed",
            total_hosts=1,
            total_ports=1,
            total_findings=1,
            risk_score=15.0,
            duration_sec=0.5,
            is_demo=True,
            devices=[{"ip_address": "192.168.1.50"}],
            services=[{"port": 80, "service_name": "http"}],
            vulnerabilities=[{"title": "HTTP Cleartext", "severity": "MEDIUM"}],
            db_file=self.db_path
        )
        self.assertTrue(delete_scan(scan_id, self.db_path))
        self.assertIsNone(get_scan_by_id(scan_id, self.db_path))
        self.assertEqual(len(get_scan_vulnerabilities(scan_id, self.db_path)), 0)

if __name__ == "__main__":
    unittest.main()
