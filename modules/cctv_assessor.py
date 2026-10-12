"""
Dedicated CCTV & IP-Camera Security Assessment Module for IoT Sentinel Pro.
Conducts non-destructive, defensive evaluations of surveillance cameras and NVRs:
- RTSP Port 554 exposure and cleartext stream indicators
- HTTP/HTTPS management interfaces
- Legacy administration services (Telnet 23, FTP 21, SSH 22)
- Secondary surveillance ports (8000, 37777, 8080, 8443)
- Firmware & server banner verification
- Step-by-step administrator verification procedures

Strict Ethical Boundaries:
- NEVER retrieves live video feeds or opens streams.
- NEVER guesses or tests credentials.
- NEVER modifies camera configuration.
- Clearly distinguishes Confirmed Findings from Potential Risks and Needs Verification.
"""

from typing import List, Dict, Any, Optional

class CCTVSecurityAssessor:
    """Specialized defensive security assessor for CCTV and IP surveillance equipment."""

    @classmethod
    def assess_cctv_device(
        cls,
        target_ip: str,
        services: List[Dict[str, Any]],
        device_type: str = "CCTV / IP Camera"
    ) -> Dict[str, Any]:
        """
        Performs in-depth CCTV security posture evaluation based on observable service evidence.
        """
        open_ports = {s.get("port"): s for s in services if s.get("state", "open") == "open"}
        findings = []

        is_cctv = (
            device_type == "CCTV / IP Camera" or
            554 in open_ports or
            any(p in open_ports for p in (8000, 37777))
        )

        has_rtsp = 554 in open_ports
        has_http = 80 in open_ports or 8080 in open_ports
        has_https = 443 in open_ports or 8443 in open_ports
        has_telnet = 23 in open_ports
        has_ftp = 21 in open_ports
        has_ssh = 22 in open_ports
        has_vendor_port = any(p in open_ports for p in (8000, 37777))

        # 1. RTSP Stream Exposure
        if has_rtsp:
            rtsp_srv = open_ports[554]
            banner_info = rtsp_srv.get("banner") or rtsp_srv.get("product") or "Standard RTSP/1.0 Listener"
            findings.append({
                "rule_id": "CCTV-RTSP-001",
                "title": "Unencrypted RTSP Video Surveillance Stream Exposure",
                "severity": "HIGH",
                "confidence": "HIGH",
                "verification_status": "Potential Security Risk",
                "port": 554,
                "service": "rtsp",
                "observation_evidence": f"Port 554/tcp open | Service: rtsp | Banner: {banner_info}",
                "potential_impact": (
                    "The Real-Time Streaming Protocol (RTSP) is active over unencrypted TCP. "
                    "Camera video streams may be susceptible to passive LAN packet inspection, eavesdropping, "
                    "or unauthorized stream endpoint querying if unsegmented."
                ),
                "remediation": (
                    "1. Restrict RTSP traffic to a secured, isolated Surveillance VLAN via firewall ACLs.\n"
                    "2. Enable RTSPS (TLS-wrapped RTSP) if supported by camera firmware.\n"
                    "3. Ensure the camera requires strong Digest authentication for all RTSP streams."
                ),
                "admin_verification_steps": (
                    "1. Log into the camera web management interface.\n"
                    "2. Navigate to 'Network > RTSP / Video Stream Settings'.\n"
                    "3. Verify that RTSP Authentication is set to 'Digest' rather than 'None' or 'Basic'.\n"
                    "4. Verify that default stream URLs (e.g., /live/ch0, /onvif1) require authentication."
                )
            })

        # 2. Cleartext Web Management Console
        if has_http and not has_https:
            http_port = 80 if 80 in open_ports else 8080
            http_srv = open_ports[http_port]
            web_banner = http_srv.get("banner") or http_srv.get("product") or "HTTP Server"
            findings.append({
                "rule_id": "CCTV-WEB-001",
                "title": "Camera Administration Exclusively Over Cleartext HTTP",
                "severity": "HIGH" if is_cctv else "MEDIUM",
                "confidence": "HIGH",
                "verification_status": "Confirmed Technical Finding",
                "port": http_port,
                "service": "http",
                "observation_evidence": f"Port {http_port}/tcp open (HTTP) without HTTPS (443) available | Server: {web_banner}",
                "potential_impact": (
                    "Surveillance camera configuration and live PTZ controls are managed over unencrypted HTTP. "
                    "Administrator credentials and session authentication cookies are transmitted in cleartext on the LAN."
                ),
                "remediation": (
                    "1. Enable HTTPS on port 443 with TLS 1.2 or TLS 1.3 in camera network settings.\n"
                    "2. Install a trusted or internal CA certificate.\n"
                    "3. Disable plain HTTP access or enforce HTTP-to-HTTPS automatic redirection."
                ),
                "admin_verification_steps": (
                    "1. Access camera configuration at http://<target_ip>.\n"
                    "2. Check 'Security > HTTPS' to see if TLS certificate support is available.\n"
                    "3. If HTTPS cannot be enabled, place the camera behind an authenticated reverse proxy."
                )
            })
        elif has_http and has_https:
            findings.append({
                "rule_id": "CCTV-WEB-002",
                "title": "Cleartext HTTP Port 80 Open Alongside HTTPS",
                "severity": "LOW",
                "confidence": "HIGH",
                "verification_status": "Needs Administrative Verification",
                "port": 80,
                "service": "http",
                "observation_evidence": "Port 80 (HTTP) and Port 443 (HTTPS) both open simultaneously.",
                "potential_impact": (
                    "If administrators access the camera over HTTP without automatic redirection, "
                    "login credentials may still be leaked over the network."
                ),
                "remediation": "Configure automatic HTTP-to-HTTPS redirect or close HTTP port 80 entirely.",
                "admin_verification_steps": "Attempt visiting http://<target_ip> in browser and verify if it auto-redirects to https://."
            })

        # 3. Telnet on CCTV Device
        if has_telnet:
            findings.append({
                "rule_id": "CCTV-TEL-001",
                "title": "Legacy Telnet Remote Shell Active on Surveillance Camera",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "verification_status": "Confirmed Technical Finding",
                "port": 23,
                "service": "telnet",
                "observation_evidence": "Port 23/tcp open | Telnet terminal active on camera endpoint",
                "potential_impact": (
                    "Telnet on CCTV devices is a primary exploit vector for botnets (e.g. Mirai, Persirai, Reaper). "
                    "Provides unencrypted command shell access susceptible to credential spraying and unauthorized firmware access."
                ),
                "remediation": (
                    "1. Immediately disable Telnet in the camera firmware settings.\n"
                    "2. If Telnet cannot be deactivated via UI, upgrade to the latest vendor firmware release.\n"
                    "3. Isolate the camera from untrusted subnets using network ACLs."
                ),
                "admin_verification_steps": (
                    "1. Check camera web console under 'System > Security > Services' for a Telnet toggle.\n"
                    "2. Verify vendor security advisory for this camera model."
                )
            })

        # 4. Secondary Management / Surveillance Discovery Ports
        if has_vendor_port:
            v_port = 8000 if 8000 in open_ports else 37777
            v_srv = open_ports[v_port]
            findings.append({
                "rule_id": "CCTV-MAN-001",
                "title": f"Proprietary Surveillance Discovery / Media Port {v_port} Active",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "verification_status": "Needs Administrative Verification",
                "port": v_port,
                "service": v_srv.get("service_name", "surveillance-mgmt"),
                "observation_evidence": f"Port {v_port}/tcp open (commonly used by Dahua, Hikvision, or ONVIF client tools)",
                "potential_impact": (
                    "Proprietary binary surveillance protocols may bypass standard web application protections. "
                    "Historical disclosures in proprietary camera control protocols include unauthenticated command execution."
                ),
                "remediation": (
                    "1. If proprietary VMS software is not utilized, disable auxiliary media ports in camera settings.\n"
                    "2. Restrict access to authorized NVR server IP addresses only."
                ),
                "admin_verification_steps": (
                    "1. Check if video management software (e.g. SmartPSS, iVMS) requires this port.\n"
                    "2. Ensure port is not exposed across subnets or routed externally."
                )
            })

        # 5. Outdated Server Banners (Boa, etc.)
        for srv in services:
            banner_lower = f"{srv.get('product', '')} {srv.get('version', '')} {srv.get('banner', '')}".lower()
            if "boa/" in banner_lower:
                findings.append({
                    "rule_id": "CCTV-BANNER-001",
                    "title": "Discontinued Boa Embedded Web Server Detected on Camera",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "verification_status": "Confirmed Technical Finding",
                    "port": srv.get("port"),
                    "service": srv.get("service_name", "http"),
                    "observation_evidence": f"Server banner: {banner_lower[:80]}",
                    "potential_impact": (
                        "Boa web server was discontinued in 2005 and has documented memory corruption and header parsing vulnerabilities. "
                        "Common in legacy IP camera firmware."
                    ),
                    "remediation": "Apply the latest manufacturer firmware patch to replace the embedded web server daemon.",
                    "admin_verification_steps": "Check camera manufacturer support portal for updated firmware."
                })

        # Compute CCTV Specific Posture Rating
        cctv_risk_level = "LOW"
        if any(f["severity"] == "CRITICAL" for f in findings):
            cctv_risk_level = "CRITICAL"
        elif any(f["severity"] == "HIGH" for f in findings):
            cctv_risk_level = "HIGH"
        elif any(f["severity"] == "MEDIUM" for f in findings):
            cctv_risk_level = "MEDIUM"

        return {
            "target_ip": target_ip,
            "is_cctv_device": is_cctv,
            "cctv_risk_level": cctv_risk_level,
            "total_cctv_findings": len(findings),
            "findings": findings,
            "assessment_summary": (
                f"Assessed {len(services)} open ports on surveillance target {target_ip}. "
                f"Identified {len(findings)} CCTV-specific security indicators (Risk Tier: {cctv_risk_level})."
            )
        }
