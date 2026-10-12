"""
Database Manager for IoT Sentinel Pro — Campus Edition.
Serverless SQLite storage with automated schema creation, migration resilience,
audit logging, asset profiling, and scan-to-scan snapshot persistence.
"""

import sqlite3
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from utils.config import DB_PATH

def get_connection(db_file: Optional[str] = None) -> sqlite3.Connection:
    """Returns a SQLite connection with PRAGMA foreign_keys = ON and Row factory."""
    target_path = db_file if db_file else str(DB_PATH)
    conn = sqlite3.connect(target_path, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_file: Optional[str] = None) -> None:
    """Creates database schema if not already initialized, adding new columns safely."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()

        # 1. Scans Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                total_hosts INTEGER DEFAULT 0,
                total_ports INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0,
                duration_sec REAL DEFAULT 0.0,
                is_demo INTEGER DEFAULT 0,
                notes TEXT,
                cancellation_status TEXT DEFAULT 'NORMAL'
            );
        """)

        # 2. Devices / Assets Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                vendor TEXT,
                device_type TEXT DEFAULT 'Generic IoT Device',
                classification_confidence TEXT DEFAULT 'Medium',
                asset_criticality TEXT DEFAULT 'Medium',
                expected_zone TEXT DEFAULT 'Core Campus LAN',
                user_label TEXT,
                status TEXT DEFAULT 'up',
                discovered_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            );
        """)

        # 3. Services / Ports Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                service_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                service_name TEXT,
                product TEXT,
                version TEXT,
                state TEXT DEFAULT 'open',
                banner TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            );
        """)

        # 4. Vulnerabilities / Findings Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                rule_id TEXT DEFAULT 'RULE-GENERIC',
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT DEFAULT 'HIGH',
                verification_status TEXT DEFAULT 'Potential Security Risk',
                evidence TEXT,
                explanation TEXT,
                remediation TEXT,
                admin_verification_steps TEXT,
                cve_id TEXT,
                cvss_score REAL,
                cve_url TEXT,
                references_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            );
        """)

        # 5. Audit Logging Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT,
                target TEXT,
                status TEXT
            );
        """)

        # 6. CVE Offline Cache Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                query_key TEXT PRIMARY KEY,
                cve_json TEXT NOT NULL,
                cached_at TEXT NOT NULL,
                source TEXT DEFAULT 'NIST NVD API v2.0'
            );
        """)

        # 7. Asset Profiles & Baseline Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS asset_profiles (
                ip_address TEXT PRIMARY KEY,
                asset_id TEXT,
                user_label TEXT,
                asset_criticality TEXT DEFAULT 'Medium',
                expected_zone TEXT DEFAULT 'Core Campus LAN',
                expected_role TEXT DEFAULT 'IoT Device',
                expected_ports_json TEXT,
                updated_at TEXT
            );
        """)

        # Indices for optimal query speed
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_asset ON devices(asset_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_services_scan ON services(scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);")

        conn.commit()

def log_audit_event(
    event_type: str,
    details: str,
    target: str = "",
    status: str = "SUCCESS",
    db_file: Optional[str] = None
) -> None:
    """Records an administrative or scan execution event in the local audit log."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, event_type, details, target, status)
            VALUES (?, ?, ?, ?, ?)
        """, (ts, event_type, details, target, status))
        conn.commit()

def get_audit_logs(limit: int = 50, db_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves recent audit log events."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]

def save_scan_record(
    scan_id: str,
    target: str,
    scan_type: str,
    status: str,
    total_hosts: int,
    total_ports: int,
    total_findings: int,
    risk_score: float,
    duration_sec: float,
    is_demo: bool,
    devices: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    notes: str = "",
    cancellation_status: str = "NORMAL",
    db_file: Optional[str] = None
) -> str:
    """Persists a complete scan run with devices, services, findings, and audit log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_connection(db_file) as conn:
        cursor = conn.cursor()

        # 1. Insert Scan Record
        cursor.execute("""
            INSERT OR REPLACE INTO scans 
            (scan_id, timestamp, target, scan_type, status, total_hosts, total_ports, 
             total_findings, risk_score, duration_sec, is_demo, notes, cancellation_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, timestamp, target, scan_type, status, total_hosts, total_ports,
            total_findings, risk_score, duration_sec, 1 if is_demo else 0, notes, cancellation_status
        ))

        # 2. Insert Discovered Devices
        for dev in devices:
            cursor.execute("""
                INSERT INTO devices 
                (scan_id, asset_id, ip_address, mac_address, hostname, vendor, device_type,
                 classification_confidence, asset_criticality, expected_zone, user_label, status, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                dev.get("asset_id", f"AST-{dev.get('ip_address', 'UNK').replace('.', '')[-6:]}"),
                dev.get("ip_address", "Unknown"),
                dev.get("mac_address", "N/A"),
                dev.get("hostname", "Unknown"),
                dev.get("vendor", "Generic IoT"),
                dev.get("device_type", "Generic IoT Device"),
                dev.get("classification_confidence", "Medium"),
                dev.get("asset_criticality", "Medium"),
                dev.get("expected_zone", "Core Campus LAN"),
                dev.get("user_label", ""),
                dev.get("status", "up"),
                timestamp
            ))

        # 3. Insert Services
        for srv in services:
            cursor.execute("""
                INSERT INTO services 
                (scan_id, device_ip, port, protocol, service_name, product, version, state, banner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                srv.get("device_ip", target),
                srv.get("port", 0),
                srv.get("protocol", "tcp"),
                srv.get("service_name", "unknown"),
                srv.get("product", ""),
                srv.get("version", ""),
                srv.get("state", "open"),
                srv.get("banner", "")
            ))

        # 4. Insert Vulnerabilities
        for vuln in vulnerabilities:
            refs_json = json.dumps(vuln.get("references", []))
            cursor.execute("""
                INSERT INTO vulnerabilities 
                (scan_id, device_ip, port, service, rule_id, title, severity, confidence, 
                 verification_status, evidence, explanation, remediation, admin_verification_steps,
                 cve_id, cvss_score, cve_url, references_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                vuln.get("device_ip", target),
                vuln.get("port", 0),
                vuln.get("service", ""),
                vuln.get("rule_id", "IOT-RULE"),
                vuln.get("title", "Security Finding"),
                vuln.get("severity", "MEDIUM"),
                vuln.get("confidence", "HIGH"),
                vuln.get("verification_status", "Potential Security Risk"),
                vuln.get("evidence", ""),
                vuln.get("explanation", ""),
                vuln.get("remediation", ""),
                vuln.get("admin_verification_steps", ""),
                vuln.get("cve_id", ""),
                vuln.get("cvss_score"),
                vuln.get("cve_url", ""),
                refs_json
            ))

        conn.commit()

    # Log completion in audit trail
    log_audit_event(
        event_type="SCAN_COMPLETED",
        details=f"Scan {scan_id} ({scan_type}) completed on {target}. Found {total_ports} ports, {total_findings} findings.",
        target=target,
        status=status,
        db_file=db_file
    )

    return scan_id

def get_all_scans(limit: int = 50, db_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves list of past scans ordered by timestamp descending."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]

def get_scan_by_id(scan_id: str, db_file: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves full scan metadata by scan_id."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_scan_devices(scan_id: str, db_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all devices associated with a scan."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE scan_id = ?", (scan_id,))
        return [dict(r) for r in cursor.fetchall()]

def get_scan_services(scan_id: str, db_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all open ports and services associated with a scan."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM services WHERE scan_id = ?", (scan_id,))
        return [dict(r) for r in cursor.fetchall()]

def get_scan_vulnerabilities(scan_id: str, db_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all vulnerabilities associated with a scan."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("references_json"):
                try:
                    d["references"] = json.loads(d["references_json"])
                except Exception:
                    d["references"] = []
            else:
                d["references"] = []
            result.append(d)
        return result

def delete_scan(scan_id: str, db_file: Optional[str] = None) -> bool:
    """Deletes a scan and cascades deletion of its devices, services, and findings."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM services WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM devices WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        
        log_audit_event(
            event_type="SCAN_DELETED",
            details=f"Administrative deletion of scan record {scan_id}",
            target=scan_id,
            status="SUCCESS",
            db_file=db_file
        )
        return cursor.rowcount > 0

def get_cached_cve(query_key: str, db_file: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    """Retrieves cached CVE JSON by lookup key."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT cve_json FROM cve_cache WHERE query_key = ?", (query_key,))
        row = cursor.fetchone()
        if row:
            try:
                return json.loads(row["cve_json"])
            except Exception:
                return None
    return None

def set_cached_cve(query_key: str, data: List[Dict[str, Any]], db_file: Optional[str] = None) -> None:
    """Caches CVE results with source metadata to avoid repeat external queries."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT OR REPLACE INTO cve_cache (query_key, cve_json, cached_at, source)
            VALUES (?, ?, ?, ?)
        """, (query_key, json.dumps(data), now_str, "NIST NVD API v2.0"))
        conn.commit()

# --- Asset Profile CRUD ---

def get_asset_profile(ip_address: str, db_file: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves administrator configuration profile for an asset."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM asset_profiles WHERE ip_address = ?", (ip_address,))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            if d.get("expected_ports_json"):
                try:
                    d["expected_ports"] = json.loads(d["expected_ports_json"])
                except Exception:
                    d["expected_ports"] = []
            return d
    return None

def save_asset_profile(
    ip_address: str,
    asset_id: str,
    user_label: str,
    asset_criticality: str = "Medium",
    expected_zone: str = "Core Campus LAN",
    expected_role: str = "IoT Device",
    expected_ports: Optional[List[int]] = None,
    db_file: Optional[str] = None
) -> None:
    """Saves or updates custom asset metadata, criticality, and expected service baseline."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ports_json = json.dumps(expected_ports or [])
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO asset_profiles 
            (ip_address, asset_id, user_label, asset_criticality, expected_zone, 
             expected_role, expected_ports_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip_address, asset_id, user_label, asset_criticality, expected_zone, expected_role, ports_json, now_str))
        conn.commit()

def get_all_asset_profiles(db_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all custom asset configuration profiles."""
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM asset_profiles ORDER BY ip_address ASC")
        rows = cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("expected_ports_json"):
                try:
                    d["expected_ports"] = json.loads(d["expected_ports_json"])
                except Exception:
                    d["expected_ports"] = []
            result.append(d)
        return result

def seed_demo_data_if_empty(db_file: Optional[str] = None) -> None:
    """
    Populates realistic sample IoT scans if database has no records.
    Ensures first-time users immediately see a populated dashboard with metrics & charts.
    """
    with get_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM scans")
        count = cursor.fetchone()["cnt"]
        if count > 0:
            return  # Already has records

    # 1. Realistic CCTV Camera Demo Scan
    cam_scan_id = "DEMO-CAM-001"
    cam_devices = [{
        "asset_id": "AST-CAM105DHA",
        "ip_address": "192.168.1.105",
        "mac_address": "3C:E3:6B:4A:11:89",
        "hostname": "ipcam-north-gate.lan",
        "vendor": "Zhejiang Dahua Technology Co.",
        "device_type": "CCTV / IP Camera",
        "classification_confidence": "High",
        "asset_criticality": "High",
        "expected_zone": "Surveillance Zone (CCTV)",
        "user_label": "North Perimeter IP Camera",
        "status": "up"
    }]
    cam_services = [
        {"device_ip": "192.168.1.105", "port": 80, "protocol": "tcp", "service_name": "http", "product": "Boa", "version": "0.94.14", "state": "open", "banner": "server: Boa/0.94.14"},
        {"device_ip": "192.168.1.105", "port": 554, "protocol": "tcp", "service_name": "rtsp", "product": "Live555", "version": "2016.11.28", "state": "open", "banner": "RTSP/1.0 200 OK"},
        {"device_ip": "192.168.1.105", "port": 8080, "protocol": "tcp", "service_name": "http-alt", "product": "lighttpd", "version": "1.4.35", "state": "open", "banner": "server: lighttpd/1.4.35"}
    ]
    cam_vulns = [
        {
            "device_ip": "192.168.1.105",
            "port": 554,
            "service": "rtsp",
            "rule_id": "CCTV-RTSP-001",
            "title": "Unencrypted RTSP Video Surveillance Stream Exposure",
            "severity": "HIGH",
            "confidence": "HIGH",
            "verification_status": "Potential Security Risk",
            "evidence": "Port 554/tcp open | RTSP/1.0 Live555 Media Server",
            "explanation": "RTSP video surveillance stream is transmitted without transport encryption. Susceptible to passive packet sniffing on local LAN.",
            "remediation": "Enable RTSPS (TLS encryption) or isolate camera streams on a dedicated VLAN with strict ACLs.",
            "admin_verification_steps": "Check camera web console: ensure RTSP Authentication is set to Digest rather than None.",
            "cve_id": "",
            "cvss_score": None,
            "cve_url": "",
            "references": ["OWASP IoT Top 10 - I1", "CWE-319"]
        },
        {
            "device_ip": "192.168.1.105",
            "port": 80,
            "service": "http",
            "rule_id": "IOT-SEC-003",
            "title": "Unencrypted HTTP Device Management Web Console",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "verification_status": "Confirmed Technical Finding",
            "evidence": "Port 80/tcp open | Server: Boa/0.94.14 | HTTPS port 443 inactive",
            "explanation": "The web management console operates over unencrypted HTTP. Administrator credentials and session tokens are exposed in cleartext.",
            "remediation": "Enable HTTPS on port 443 with TLS 1.2+ and enforce automatic HTTP redirect.",
            "admin_verification_steps": "Log into camera web UI at http://192.168.1.105 and check if HTTPS is configurable.",
            "cve_id": "",
            "cvss_score": None,
            "cve_url": "",
            "references": ["CWE-319"]
        },
        {
            "device_ip": "192.168.1.105",
            "port": 80,
            "service": "http",
            "rule_id": "IOT-SEC-008",
            "title": "Discontinued Boa Embedded Web Server Detected",
            "severity": "HIGH",
            "confidence": "HIGH",
            "verification_status": "Confirmed Technical Finding",
            "evidence": "Banner: Boa/0.94.14 (Discontinued embedded server)",
            "explanation": "Boa web server was discontinued in 2005 and contains documented vulnerabilities regarding authorization bypass and buffer overflows.",
            "remediation": "Update camera firmware to a current supported vendor release or isolate behind an authenticated reverse proxy.",
            "admin_verification_steps": "Check vendor support site for newer firmware release.",
            "cve_id": "CVE-2017-9833",
            "cvss_score": 7.5,
            "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-9833",
            "references": ["CVE-2017-9833", "CWE-119"]
        }
    ]

    save_scan_record(
        scan_id=cam_scan_id,
        target="192.168.1.105",
        scan_type="vulnerability",
        status="completed",
        total_hosts=1,
        total_ports=3,
        total_findings=3,
        risk_score=78.5,
        duration_sec=3.2,
        is_demo=True,
        devices=cam_devices,
        services=cam_services,
        vulnerabilities=cam_vulns,
        notes="Offline Demo Scan: Smart IP Surveillance Camera (Dahua Profile)",
        db_file=db_file
    )

    # 2. Realistic Campus Gateway / Router Demo Scan
    gw_scan_id = "DEMO-GW-002"
    gw_devices = [{
        "asset_id": "AST-GW001TPL",
        "ip_address": "192.168.1.1",
        "mac_address": "50:D4:F7:2C:99:01",
        "hostname": "gateway.campus.local",
        "vendor": "TP-Link Technologies Co.",
        "device_type": "Router / Gateway",
        "classification_confidence": "High",
        "asset_criticality": "Critical",
        "expected_zone": "Management Network",
        "user_label": "Campus Subnet Gateway",
        "status": "up"
    }]
    gw_services = [
        {"device_ip": "192.168.1.1", "port": 22, "protocol": "tcp", "service_name": "ssh", "product": "Dropbear", "version": "2016.74", "state": "open", "banner": "SSH-2.0-dropbear_2016.74"},
        {"device_ip": "192.168.1.1", "port": 23, "protocol": "tcp", "service_name": "telnet", "product": "BusyBox telnetd", "version": "1.24.1", "state": "open", "banner": "BusyBox v1.24.1 login:"},
        {"device_ip": "192.168.1.1", "port": 80, "protocol": "tcp", "service_name": "http", "product": "uHTTPd", "version": "1.0", "state": "open", "banner": "server: uHTTPd"},
        {"device_ip": "192.168.1.1", "port": 1883, "protocol": "tcp", "service_name": "mqtt", "product": "Mosquitto", "version": "1.4.15", "state": "open", "banner": "MQTT Broker"}
    ]
    gw_vulns = [
        {
            "device_ip": "192.168.1.1",
            "port": 23,
            "service": "telnet",
            "rule_id": "IOT-SEC-001",
            "title": "Cleartext Telnet Remote Management Protocol Exposed",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "verification_status": "Confirmed Technical Finding",
            "evidence": "Port 23/tcp open | BusyBox v1.24.1 telnetd",
            "explanation": "Telnet communicates in plaintext. Primary intrusion vector for Mirai-family IoT botnets and credential sniffing.",
            "remediation": "Disable the Telnet daemon immediately in device configuration and rely exclusively on SSH with key authentication.",
            "admin_verification_steps": "Connect to router administration terminal and verify telnetd is disabled.",
            "cve_id": "",
            "cvss_score": None,
            "cve_url": "",
            "references": ["CWE-319"]
        },
        {
            "device_ip": "192.168.1.1",
            "port": 1883,
            "service": "mqtt",
            "rule_id": "IOT-SEC-004",
            "title": "Unencrypted MQTT Telemetry Broker Exposed",
            "severity": "HIGH",
            "confidence": "HIGH",
            "verification_status": "Confirmed Technical Finding",
            "evidence": "Port 1883/tcp open | Mosquitto 1.4.15",
            "explanation": "MQTT message broker listening without TLS encryption. Telemetry data and actuator controls can be sniffed or injected on the LAN.",
            "remediation": "Enforce MQTTS (Port 8883) with TLS encryption and require client certificate / token authentication.",
            "admin_verification_steps": "Check broker configuration file mosquitto.conf for listener 8883 and cafile settings.",
            "cve_id": "",
            "cvss_score": None,
            "cve_url": "",
            "references": ["CWE-319"]
        },
        {
            "device_ip": "192.168.1.1",
            "port": 22,
            "service": "ssh",
            "rule_id": "IOT-SEC-006",
            "title": "Remote SSH Management Surface Detected",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "verification_status": "Informational Observation",
            "evidence": "Port 22/tcp open | SSH-2.0-dropbear_2016.74",
            "explanation": "Dropbear SSH daemon release detected. Potential target for brute-force attacks.",
            "remediation": "Update Dropbear to latest stable release and disable password login in favor of Ed25519 public keys.",
            "admin_verification_steps": "Inspect /etc/dropbear/authorized_keys and disable root password authentication.",
            "cve_id": "CVE-2016-7406",
            "cvss_score": 7.5,
            "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2016-7406",
            "references": ["CVE-2016-7406"]
        }
    ]

    save_scan_record(
        scan_id=gw_scan_id,
        target="192.168.1.1",
        scan_type="vulnerability",
        status="completed",
        total_hosts=1,
        total_ports=4,
        total_findings=3,
        risk_score=92.0,
        duration_sec=2.8,
        is_demo=True,
        devices=gw_devices,
        services=gw_services,
        vulnerabilities=gw_vulns,
        notes="Offline Demo Scan: TP-Link Campus Gateway Profile",
        db_file=db_file
    )
