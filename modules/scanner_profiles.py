"""
Scanner Profile Registry for IoT Sentinel Pro X.
Provides modular, dedicated scanner profiles for each supported IoT device category.

Each profile defines:
- Applicable discovery techniques
- Supported protocols and service checks
- Safe security configuration checks
- Version identification and CVE correlation rules
- Timeouts and conservative request limits
- Evidence, confidence, and severity rules
- Remediation recommendations
- Known limitations and unsupported checks
"""

from typing import List, Dict, Any, Optional


class ScannerProfile:
    """Represents a dedicated scanner profile for a specific device category."""

    def __init__(
        self,
        profile_id: str,
        name: str,
        category: str,
        description: str,
        applicable_ports: List[int],
        discovery_techniques: List[str],
        supported_protocols: List[str],
        security_checks: List[str],
        version_id_patterns: List[Dict[str, str]],
        cve_correlation_products: List[str],
        timeout_sec: int = 30,
        max_concurrent_checks: int = 5,
        rate_limit_per_sec: float = 10.0,
        confidence_rules: Dict[str, str] = None,
        severity_rules: Dict[str, str] = None,
        remediation_recommendations: List[str] = None,
        known_limitations: List[str] = None,
    ):
        self.profile_id = profile_id
        self.name = name
        self.category = category
        self.description = description
        self.applicable_ports = applicable_ports
        self.discovery_techniques = discovery_techniques
        self.supported_protocols = supported_protocols
        self.security_checks = security_checks
        self.version_id_patterns = version_id_patterns
        self.cve_correlation_products = cve_correlation_products
        self.timeout_sec = timeout_sec
        self.max_concurrent_checks = max_concurrent_checks
        self.rate_limit_per_sec = rate_limit_per_sec
        self.confidence_rules = confidence_rules or {}
        self.severity_rules = severity_rules or {}
        self.remediation_recommendations = remediation_recommendations or []
        self.known_limitations = known_limitations or []

    def to_dict(self) -> Dict[str, Any]:
        """Serializes profile to dictionary for display and reporting."""
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "applicable_ports": self.applicable_ports,
            "discovery_techniques": self.discovery_techniques,
            "supported_protocols": self.supported_protocols,
            "security_checks": self.security_checks,
            "version_id_patterns": self.version_id_patterns,
            "cve_correlation_products": self.cve_correlation_products,
            "timeout_sec": self.timeout_sec,
            "max_concurrent_checks": self.max_concurrent_checks,
            "rate_limit_per_sec": self.rate_limit_per_sec,
            "confidence_rules": self.confidence_rules,
            "severity_rules": self.severity_rules,
            "remediation_recommendations": self.remediation_recommendations,
            "known_limitations": self.known_limitations,
        }

    def matches_device(self, device_type: str, services: List[Dict[str, Any]]) -> float:
        """
        Returns a confidence score (0.0 to 1.0) indicating how well this
        profile matches a discovered device based on type and open services.
        """
        score = 0.0
        dt_lower = device_type.lower() if device_type else ""

        # Category keyword match
        category_keywords = {
            "cctv_camera": ["cctv", "ip camera", "camera", "nvr", "dvr", "surveillance"],
            "router_gateway": ["router", "gateway", "switch", "access point", "wireless"],
            "smart_home": ["smart", "hub", "home", "bridge", "lighting", "thermostat"],
            "iot_sensor": ["sensor", "mqtt", "iot hub", "mqtt broker", "coap", "smart plug"],
            "printer": ["printer", "multifunction", "mfp"],
            "nas_storage": ["nas", "storage", "server", "workstation"],
            "industrial_iot": ["industrial", "scada", "plc", "ics", "hmi"],
            "server_workstation": ["server", "workstation", "linux", "windows"],
        }

        cat_keys = category_keywords.get(self.profile_id, [])
        for kw in cat_keys:
            if kw in dt_lower:
                score += 0.4
                break

        # Port overlap scoring
        open_ports = {s.get("port") for s in services if s.get("state", "open") == "open"}
        if self.applicable_ports and open_ports:
            overlap = open_ports.intersection(set(self.applicable_ports))
            port_ratio = len(overlap) / len(self.applicable_ports)
            score += port_ratio * 0.6

        return min(1.0, score)


class ScannerProfileRegistry:
    """Central registry of all scanner profiles. Supports auto-detect and manual selection."""

    _profiles: List[ScannerProfile] = []
    _initialized: bool = False

    @classmethod
    def _ensure_init(cls) -> None:
        if not cls._initialized:
            cls._profiles = cls._build_profiles()
            cls._initialized = True

    @classmethod
    def get_all_profiles(cls) -> List[ScannerProfile]:
        """Returns all registered scanner profiles."""
        cls._ensure_init()
        return cls._profiles

    @classmethod
    def get_profile_by_id(cls, profile_id: str) -> Optional[ScannerProfile]:
        """Returns a specific profile by its ID."""
        cls._ensure_init()
        for p in cls._profiles:
            if p.profile_id == profile_id:
                return p
        return None

    @classmethod
    def get_profile_names(cls) -> List[Dict[str, str]]:
        """Returns list of profile names and IDs for UI selection."""
        cls._ensure_init()
        return [{"id": p.profile_id, "name": p.name, "category": p.category} for p in cls._profiles]

    @classmethod
    def auto_detect_profile(
        cls,
        device_type: str,
        services: List[Dict[str, Any]]
    ) -> Optional[ScannerProfile]:
        """
        Automatically selects the best-matching profile based on observed device
        type and services. Returns None if no profile meets the confidence threshold.
        """
        cls._ensure_init()
        best_score = 0.0
        best_profile = None

        for p in cls._profiles:
            score = p.matches_device(device_type, services)
            if score > best_score:
                best_score = score
                best_profile = p

        if best_score >= 0.3:
            return best_profile
        return None

    @classmethod
    def _build_profiles(cls) -> List[ScannerProfile]:
        """Constructs the complete set of built-in scanner profiles."""
        return [
            # 1. CCTV / IP Camera / NVR / DVR
            ScannerProfile(
                profile_id="cctv_camera",
                name="CCTV / IP Camera / NVR / DVR",
                category="Surveillance",
                description=(
                    "Dedicated security profile for IP cameras, NVRs, DVRs, and surveillance equipment. "
                    "Checks RTSP stream exposure, ONVIF discovery, web management consoles, "
                    "proprietary media ports, and embedded server banners."
                ),
                applicable_ports=[80, 443, 554, 8000, 8080, 8443, 8554, 37777, 34567, 5000],
                discovery_techniques=[
                    "TCP port probe on surveillance-specific ports",
                    "HTTP/HTTPS banner analysis for embedded server fingerprints",
                    "RTSP service banner detection (port 554)",
                    "ONVIF service probe indicators (port 80/8080)",
                    "Vendor-specific proprietary port detection (8000, 37777, 34567)",
                ],
                supported_protocols=["HTTP", "HTTPS", "RTSP", "ONVIF", "TCP"],
                security_checks=[
                    "RTSP port 554 exposure without TLS (RTSPS)",
                    "Cleartext HTTP management console without HTTPS",
                    "Discontinued embedded web server banners (Boa, GoAhead, thttpd)",
                    "Proprietary surveillance ports (8000/37777) accessible",
                    "Telnet service active on camera (Mirai/botnet risk)",
                    "FTP service on surveillance device (unexpected)",
                    "Outdated firmware version evidence in banners",
                ],
                version_id_patterns=[
                    {"pattern": "boa/", "product": "Boa Web Server", "vendor": "Boa Project"},
                    {"pattern": "live555", "product": "Live555 Media Server", "vendor": "Live555"},
                    {"pattern": "hikvision", "product": "Hikvision", "vendor": "Hikvision"},
                    {"pattern": "dahua", "product": "Dahua", "vendor": "Dahua Technology"},
                    {"pattern": "onvif", "product": "ONVIF Service", "vendor": "ONVIF Forum"},
                    {"pattern": "goahead", "product": "GoAhead WebServer", "vendor": "Embedthis"},
                ],
                cve_correlation_products=["boa", "live555", "hikvision", "dahua", "goahead"],
                timeout_sec=20,
                max_concurrent_checks=3,
                rate_limit_per_sec=5.0,
                confidence_rules={
                    "RTSP+vendor_banner": "HIGH — RTSP port with known camera vendor banner",
                    "RTSP_only": "MEDIUM — RTSP port open but no confirming vendor evidence",
                    "web_only": "LOW — Only web ports open, insufficient camera evidence",
                },
                severity_rules={
                    "telnet_on_camera": "CRITICAL — Telnet on surveillance device",
                    "rtsp_unencrypted": "HIGH — RTSP without TLS encryption",
                    "http_no_https": "HIGH — Cleartext-only web management",
                    "boa_discontinued": "HIGH — Discontinued embedded web server",
                },
                remediation_recommendations=[
                    "Enable RTSPS (TLS-wrapped RTSP) if supported by firmware",
                    "Disable Telnet and FTP services on camera devices",
                    "Enable HTTPS and disable plain HTTP access",
                    "Update camera firmware to latest vendor release",
                    "Isolate surveillance devices on dedicated VLAN",
                    "Restrict proprietary port access to authorized NVR IPs",
                ],
                known_limitations=[
                    "Cannot verify RTSP stream authentication mode without connecting to stream",
                    "ONVIF service probe not implemented (requires WS-Discovery)",
                    "Does not test default credentials or attempt login",
                    "Cannot determine firmware version without authenticated access",
                ],
            ),

            # 2. Router / Switch / Wireless Access Point
            ScannerProfile(
                profile_id="router_gateway",
                name="Router / Switch / Wireless Access Point",
                category="Network Infrastructure",
                description=(
                    "Security profile for routers, switches, wireless APs, and network gateways. "
                    "Checks management interfaces, DNS exposure, Telnet/SSH services, "
                    "and SNMP community string indicators."
                ),
                applicable_ports=[22, 23, 53, 80, 161, 443, 8080, 8443, 8291, 8728],
                discovery_techniques=[
                    "TCP probe on management and infrastructure ports",
                    "SSH/Telnet banner analysis for router OS fingerprints",
                    "HTTP banner analysis for router web admin panels",
                    "DNS resolver detection on port 53",
                    "Gateway IP heuristic (.1 or .254 octets)",
                ],
                supported_protocols=["SSH", "Telnet", "HTTP", "HTTPS", "DNS", "SNMP", "TCP"],
                security_checks=[
                    "Telnet management interface exposed (CRITICAL)",
                    "DNS open resolver / recursive DNS exposure",
                    "Cleartext HTTP management without HTTPS",
                    "SNMP v1/v2c community string indicators",
                    "Outdated SSH server versions (Dropbear, OpenSSH)",
                    "Secondary management ports (8080, 8291, 8728)",
                    "UPnP service exposure indicators",
                ],
                version_id_patterns=[
                    {"pattern": "dropbear", "product": "Dropbear SSH", "vendor": "Dropbear Project"},
                    {"pattern": "openssh", "product": "OpenSSH", "vendor": "OpenBSD"},
                    {"pattern": "uhttpd", "product": "uHTTPd", "vendor": "OpenWrt"},
                    {"pattern": "mikrotik", "product": "RouterOS", "vendor": "MikroTik"},
                    {"pattern": "openwrt", "product": "OpenWrt", "vendor": "OpenWrt"},
                ],
                cve_correlation_products=["dropbear", "openssh", "uhttpd", "mikrotik", "routeros"],
                timeout_sec=20,
                max_concurrent_checks=4,
                rate_limit_per_sec=8.0,
                confidence_rules={
                    "gateway_ip+dns+web": "HIGH — Standard gateway IP with DNS and web management",
                    "vendor_match": "HIGH — Known router vendor MAC/banner",
                    "generic_web_only": "LOW — Only web port, no confirming evidence",
                },
                severity_rules={
                    "telnet_exposed": "CRITICAL — Cleartext management protocol",
                    "snmp_v1v2": "HIGH — Unencrypted SNMP community strings",
                    "dns_open_resolver": "MEDIUM — Potential DNS amplification",
                },
                remediation_recommendations=[
                    "Disable Telnet and use SSH with key-based authentication",
                    "Migrate SNMP to SNMPv3 with encryption and authentication",
                    "Restrict DNS recursion to authorized clients only",
                    "Enable HTTPS on management interfaces",
                    "Apply latest router firmware updates",
                ],
                known_limitations=[
                    "SNMP community string testing not implemented (requires probe)",
                    "Cannot verify UPnP exposure without UPnP discovery protocol",
                    "Wireless security mode (WPA2/WPA3) not detectable via port scan",
                ],
            ),

            # 3. Smart Home / Hub / Gateway
            ScannerProfile(
                profile_id="smart_home",
                name="Smart Home Device / Hub / Gateway",
                category="Smart Home / Consumer IoT",
                description=(
                    "Security profile for smart home hubs, smart lighting bridges, "
                    "smart speakers, and consumer IoT gateways."
                ),
                applicable_ports=[80, 443, 1883, 5353, 8080, 8443, 8008, 8009, 8443, 49152],
                discovery_techniques=[
                    "TCP probe on common smart-home ports",
                    "HTTP banner fingerprinting for hub web interfaces",
                    "MQTT broker detection on port 1883/8883",
                    "mDNS / Bonjour indicator detection (port 5353)",
                ],
                supported_protocols=["HTTP", "HTTPS", "MQTT", "MQTTS", "mDNS", "TCP"],
                security_checks=[
                    "Unencrypted MQTT broker exposed (port 1883)",
                    "Cleartext HTTP management interface",
                    "mDNS service broadcasting device information",
                    "API endpoints accessible without authentication indicators",
                    "Outdated hub firmware evidence in banners",
                ],
                version_id_patterns=[
                    {"pattern": "philips", "product": "Philips Hue Bridge", "vendor": "Signify"},
                    {"pattern": "tuya", "product": "Tuya Smart", "vendor": "Tuya"},
                    {"pattern": "home assistant", "product": "Home Assistant", "vendor": "HA"},
                ],
                cve_correlation_products=["philips hue", "tuya", "home assistant"],
                timeout_sec=15,
                max_concurrent_checks=3,
                rate_limit_per_sec=5.0,
                confidence_rules={
                    "mqtt+web": "HIGH — MQTT and web interface indicate smart hub",
                    "vendor_known": "HIGH — Known smart home vendor identified",
                },
                severity_rules={
                    "mqtt_unencrypted": "HIGH — MQTT without TLS on smart home network",
                    "http_no_auth_indicators": "MEDIUM — Web interface without auth",
                },
                remediation_recommendations=[
                    "Enforce MQTTS (TLS) on all MQTT communications",
                    "Isolate smart home devices on a separate VLAN",
                    "Update hub firmware to latest manufacturer release",
                    "Disable unnecessary mDNS broadcasting",
                ],
                known_limitations=[
                    "Cannot test Zigbee/Z-Wave/Bluetooth protocols (requires RF hardware)",
                    "Cloud API security not assessable locally",
                ],
            ),

            # 4. IoT Sensor / Smart Plug / MQTT/CoAP Device
            ScannerProfile(
                profile_id="iot_sensor",
                name="IoT Sensor / Smart Plug / MQTT-CoAP Device",
                category="IoT Sensors & Actuators",
                description=(
                    "Security profile for IoT sensor nodes, smart plugs, MQTT clients/brokers, "
                    "and CoAP-enabled embedded devices."
                ),
                applicable_ports=[80, 1883, 5683, 5684, 8883, 8080],
                discovery_techniques=[
                    "TCP probe on MQTT/CoAP ports",
                    "HTTP banner for embedded web servers (ESP-HTTPD, etc.)",
                    "MQTT broker detection",
                    "CoAP service indicator on UDP 5683/5684",
                ],
                supported_protocols=["MQTT", "MQTTS", "CoAP", "CoAPS", "HTTP", "TCP"],
                security_checks=[
                    "MQTT broker exposed without TLS",
                    "CoAP service exposed without DTLS",
                    "Embedded HTTP server without authentication",
                    "ESP/Arduino firmware version indicators",
                ],
                version_id_patterns=[
                    {"pattern": "mosquitto", "product": "Eclipse Mosquitto", "vendor": "Eclipse"},
                    {"pattern": "esp-httpd", "product": "ESP-HTTPD", "vendor": "Espressif"},
                    {"pattern": "espressif", "product": "Espressif", "vendor": "Espressif"},
                    {"pattern": "emqx", "product": "EMQX", "vendor": "EMQ Technologies"},
                ],
                cve_correlation_products=["mosquitto", "espressif", "emqx"],
                timeout_sec=15,
                max_concurrent_checks=3,
                rate_limit_per_sec=3.0,
                confidence_rules={
                    "mqtt+esp_banner": "HIGH — MQTT with Espressif banner",
                    "mqtt_only": "MEDIUM — MQTT port but no confirming evidence",
                },
                severity_rules={
                    "mqtt_cleartext": "HIGH — Unencrypted MQTT telemetry",
                    "coap_no_dtls": "MEDIUM — CoAP without DTLS encryption",
                },
                remediation_recommendations=[
                    "Encrypt all MQTT traffic with TLS (port 8883)",
                    "Enable DTLS for CoAP communications",
                    "Update firmware on sensor nodes",
                    "Restrict sensor network access with firewall ACLs",
                ],
                known_limitations=[
                    "CoAP discovery requires UDP probe (not performed by default)",
                    "Cannot verify MQTT topic ACLs without authenticated connection",
                    "BLE/Zigbee/LoRa protocols not assessable",
                ],
            ),

            # 5. Printer / Multifunction Device
            ScannerProfile(
                profile_id="printer",
                name="Printer / Multifunction Device",
                category="Office Equipment",
                description=(
                    "Security profile for network printers, multifunction printers (MFPs), "
                    "and print servers. Checks management interfaces and printing protocols."
                ),
                applicable_ports=[80, 443, 515, 631, 9100, 161, 8080],
                discovery_techniques=[
                    "TCP probe on printing-specific ports (9100/JetDirect, 631/IPP, 515/LPR)",
                    "HTTP banner analysis for printer admin panels",
                    "SNMP device description indicators",
                ],
                supported_protocols=["HTTP", "HTTPS", "IPP", "JetDirect", "LPR", "SNMP", "TCP"],
                security_checks=[
                    "JetDirect port 9100 exposed (raw data channel)",
                    "IPP/CUPS service exposed without authentication indicators",
                    "Cleartext HTTP printer admin panel",
                    "SNMP community string indicators",
                    "Outdated printer firmware in web banner",
                ],
                version_id_patterns=[
                    {"pattern": "hp-chaisoe", "product": "HP ChaiSOE", "vendor": "HP"},
                    {"pattern": "cups", "product": "CUPS", "vendor": "Apple/OpenPrinting"},
                    {"pattern": "jetdirect", "product": "HP JetDirect", "vendor": "HP"},
                    {"pattern": "brother", "product": "Brother Printer", "vendor": "Brother"},
                    {"pattern": "xerox", "product": "Xerox", "vendor": "Xerox"},
                ],
                cve_correlation_products=["cups", "hp jetdirect", "xerox", "brother"],
                timeout_sec=15,
                max_concurrent_checks=3,
                rate_limit_per_sec=5.0,
                confidence_rules={
                    "jetdirect+web": "HIGH — JetDirect port with web admin",
                    "ipp_or_lpr": "HIGH — IPP/LPR protocol detected",
                    "vendor_match": "HIGH — Known printer vendor identified",
                },
                severity_rules={
                    "jetdirect_exposed": "MEDIUM — Raw print data channel open",
                    "http_admin_no_https": "MEDIUM — Cleartext printer admin",
                },
                remediation_recommendations=[
                    "Restrict JetDirect (9100) access to print servers only",
                    "Enable HTTPS on printer management interfaces",
                    "Disable unused printing protocols (LPR, raw)",
                    "Apply printer firmware security updates",
                ],
                known_limitations=[
                    "Cannot test print job interception or document security",
                    "PJL/PostScript injection testing not performed",
                ],
            ),

            # 6. NAS / Storage Device
            ScannerProfile(
                profile_id="nas_storage",
                name="NAS / Storage Device",
                category="Storage & File Servers",
                description=(
                    "Security profile for NAS devices, file servers, and storage appliances. "
                    "Checks file transfer services, management interfaces, and storage protocols."
                ),
                applicable_ports=[21, 22, 80, 139, 443, 445, 548, 2049, 3260, 5000, 5001, 8080],
                discovery_techniques=[
                    "TCP probe on storage and file service ports",
                    "FTP/SSH/SMB banner analysis",
                    "HTTP banner for NAS web management interfaces",
                    "NFS/iSCSI port detection",
                ],
                supported_protocols=["FTP", "SFTP", "SSH", "HTTP", "HTTPS", "SMB", "NFS", "iSCSI", "TCP"],
                security_checks=[
                    "FTP service without TLS (cleartext credentials)",
                    "SMBv1 protocol indicators (EternalBlue risk)",
                    "SSH with outdated version strings",
                    "Cleartext HTTP management without HTTPS",
                    "NFS service exposed to network",
                    "iSCSI target exposure",
                ],
                version_id_patterns=[
                    {"pattern": "synology", "product": "Synology DSM", "vendor": "Synology"},
                    {"pattern": "qnap", "product": "QNAP QTS", "vendor": "QNAP"},
                    {"pattern": "proftpd", "product": "ProFTPD", "vendor": "ProFTPD Project"},
                    {"pattern": "samba", "product": "Samba", "vendor": "Samba Team"},
                    {"pattern": "apache", "product": "Apache HTTP Server", "vendor": "Apache"},
                ],
                cve_correlation_products=["synology", "qnap", "proftpd", "samba", "apache"],
                timeout_sec=25,
                max_concurrent_checks=4,
                rate_limit_per_sec=8.0,
                confidence_rules={
                    "ftp+ssh+web": "HIGH — FTP, SSH, and web management together",
                    "smb+nfs": "HIGH — File sharing protocols detected",
                    "vendor_match": "HIGH — Known NAS vendor identified",
                },
                severity_rules={
                    "ftp_cleartext": "HIGH — FTP without TLS",
                    "smbv1_indicator": "HIGH — SMBv1 vulnerability surface",
                    "nfs_exposed": "MEDIUM — NFS accessible from scanned network",
                },
                remediation_recommendations=[
                    "Disable FTP and migrate to SFTP/SCP",
                    "Disable SMBv1 and enforce SMBv3 with signing",
                    "Restrict NFS exports to specific IP addresses",
                    "Enable HTTPS on NAS management interfaces",
                    "Apply NAS firmware security updates",
                ],
                known_limitations=[
                    "Cannot verify SMBv1 vs SMBv3 without protocol negotiation",
                    "NFS export list verification requires NFS client probe",
                    "Cannot determine share permissions without authentication",
                ],
            ),

            # 7. Server / Workstation
            ScannerProfile(
                profile_id="server_workstation",
                name="Server / Workstation",
                category="General Purpose Compute",
                description=(
                    "Security profile for general servers and workstations. "
                    "Checks common management services, web servers, and database ports."
                ),
                applicable_ports=[21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432, 5900, 8080, 8443],
                discovery_techniques=[
                    "TCP probe on common server service ports",
                    "SSH/RDP banner analysis",
                    "Web server banner fingerprinting",
                    "Database port detection",
                ],
                supported_protocols=["SSH", "HTTP", "HTTPS", "FTP", "RDP", "VNC", "TCP"],
                security_checks=[
                    "Telnet exposed on server (CRITICAL)",
                    "RDP exposed without NLA indicators",
                    "VNC service exposed (potential remote desktop exposure)",
                    "Database ports exposed to network (MySQL 3306, PostgreSQL 5432)",
                    "FTP without TLS encryption",
                    "Cleartext HTTP management without HTTPS",
                ],
                version_id_patterns=[
                    {"pattern": "openssh", "product": "OpenSSH", "vendor": "OpenBSD"},
                    {"pattern": "apache", "product": "Apache HTTP Server", "vendor": "Apache"},
                    {"pattern": "nginx", "product": "Nginx", "vendor": "F5/Nginx"},
                    {"pattern": "mysql", "product": "MySQL", "vendor": "Oracle"},
                    {"pattern": "postgresql", "product": "PostgreSQL", "vendor": "PostgreSQL"},
                ],
                cve_correlation_products=["openssh", "apache", "nginx", "mysql", "postgresql"],
                timeout_sec=30,
                max_concurrent_checks=5,
                rate_limit_per_sec=10.0,
                confidence_rules={
                    "multiple_services": "HIGH — Multiple standard server services detected",
                    "ssh+web": "MEDIUM — SSH and web server indicate server role",
                },
                severity_rules={
                    "telnet_server": "CRITICAL — Cleartext remote management",
                    "rdp_exposed": "HIGH — Remote Desktop Protocol exposed",
                    "database_exposed": "HIGH — Database service accessible from network",
                },
                remediation_recommendations=[
                    "Disable Telnet and use SSH with key-based authentication",
                    "Restrict RDP access with NLA and network ACLs",
                    "Restrict database ports to application servers only",
                    "Enable HTTPS and redirect HTTP traffic",
                ],
                known_limitations=[
                    "Cannot verify OS patch level without authenticated scan",
                    "Cannot test RDP NLA enforcement without connection attempt",
                ],
            ),

            # 8. Industrial IoT / SCADA
            ScannerProfile(
                profile_id="industrial_iot",
                name="Industrial IoT / SCADA / ICS",
                category="Industrial Control Systems",
                description=(
                    "Security profile for industrial IoT devices, SCADA systems, PLCs, and HMIs. "
                    "Identifies exposure of industrial protocols and management interfaces."
                ),
                applicable_ports=[80, 102, 443, 502, 1883, 2404, 4840, 8080, 20000, 44818, 47808],
                discovery_techniques=[
                    "TCP probe on industrial protocol ports",
                    "Modbus TCP detection (port 502)",
                    "OPC UA detection (port 4840)",
                    "BACnet detection (port 47808)",
                    "S7comm/Siemens detection (port 102)",
                    "DNP3 detection (port 20000)",
                ],
                supported_protocols=["Modbus", "OPC-UA", "BACnet", "S7comm", "DNP3", "MQTT", "HTTP", "TCP"],
                security_checks=[
                    "Industrial protocol ports exposed to IT network",
                    "Modbus TCP without authentication (port 502)",
                    "OPC UA service exposure",
                    "Web management interface on industrial controller",
                    "MQTT broker on ICS network",
                ],
                version_id_patterns=[
                    {"pattern": "siemens", "product": "Siemens S7", "vendor": "Siemens"},
                    {"pattern": "schneider", "product": "Schneider Electric", "vendor": "Schneider"},
                    {"pattern": "modbus", "product": "Modbus TCP", "vendor": "Modbus.org"},
                ],
                cve_correlation_products=["siemens s7", "schneider electric", "modbus"],
                timeout_sec=15,
                max_concurrent_checks=2,
                rate_limit_per_sec=2.0,
                confidence_rules={
                    "industrial_ports": "HIGH — Industrial protocol ports detected",
                    "web+modbus": "HIGH — Web management with Modbus/OPC",
                },
                severity_rules={
                    "modbus_no_auth": "CRITICAL — Modbus without authentication",
                    "ics_on_it_network": "CRITICAL — ICS protocols on IT network",
                },
                remediation_recommendations=[
                    "Isolate ICS/SCADA networks from IT networks",
                    "Implement industrial firewalls with protocol inspection",
                    "Disable unnecessary web management on controllers",
                    "Use VPN for remote ICS access",
                    "Apply vendor security patches for industrial controllers",
                ],
                known_limitations=[
                    "Industrial protocol deep inspection not implemented",
                    "Cannot verify PLC logic or HMI configuration",
                    "Modbus function code testing not performed (destructive risk)",
                    "CAUTION: Aggressive scanning can disrupt ICS processes",
                ],
            ),

            # 9. Unknown / Unidentified Device
            ScannerProfile(
                profile_id="unknown_device",
                name="Unknown / Unidentified Device",
                category="Generic",
                description=(
                    "Fallback profile for devices that cannot be reliably classified. "
                    "Performs broad safe checks on commonly exposed ports."
                ),
                applicable_ports=[21, 22, 23, 53, 80, 443, 554, 1883, 8080, 8443, 8883],
                discovery_techniques=[
                    "TCP probe on standard IoT port set",
                    "Banner analysis across all detected services",
                    "Vendor MAC address lookup (if available)",
                ],
                supported_protocols=["TCP", "HTTP", "HTTPS", "SSH", "Telnet", "FTP", "MQTT", "RTSP"],
                security_checks=[
                    "Telnet exposure",
                    "FTP without encryption",
                    "Cleartext HTTP management",
                    "Unencrypted MQTT broker",
                    "RTSP stream exposure",
                    "Known vulnerable banner detection",
                ],
                version_id_patterns=[],
                cve_correlation_products=[],
                timeout_sec=20,
                max_concurrent_checks=3,
                rate_limit_per_sec=5.0,
                confidence_rules={
                    "any_match": "LOW — Insufficient evidence for reliable classification",
                },
                severity_rules={
                    "telnet": "CRITICAL — Cleartext remote access",
                    "ftp": "HIGH — Cleartext file transfer",
                },
                remediation_recommendations=[
                    "Identify the device and assign an appropriate security profile",
                    "Disable unnecessary services",
                    "Apply available firmware/software updates",
                ],
                known_limitations=[
                    "Limited classification confidence without device identification",
                    "Checks are generic rather than device-specific",
                ],
            ),
        ]
