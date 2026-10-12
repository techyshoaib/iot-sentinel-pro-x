"""
Scan Comparison & Asset History Differential Engine.
Compares historical scan snapshots to identify asset deltas:
- Newly discovered vs unobserved devices
- Newly opened vs closed ports
- New vs resolved vulnerability findings
- Changes in finding severity or evidence

Safeguard: Incomplete or timed-out scans are flagged so that unobserved
services are NOT falsely classified as resolved vulnerabilities.
"""

from typing import Dict, Any, List, Optional
from database.db_manager import (
    get_scan_by_id,
    get_scan_devices,
    get_scan_services,
    get_scan_vulnerabilities
)

class ScanComparator:
    """Computes deterministic differentials between two scan snapshots."""

    @classmethod
    def compare_scans(
        cls,
        baseline_scan_id: str,
        current_scan_id: str,
        db_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Compares baseline (older) scan with current (newer) scan.
        Returns a comprehensive differential report.
        """
        scan_a = get_scan_by_id(baseline_scan_id, db_file)
        scan_b = get_scan_by_id(current_scan_id, db_file)

        if not scan_a or not scan_b:
            return {"error": "One or both scan IDs could not be found in the database."}

        # Check for incomplete or timed-out scans
        is_partial_scan = (
            scan_b.get("status") != "completed" or
            scan_b.get("cancellation_status") == "CANCELLED"
        )

        # 1. Compare Devices
        devices_a = {d["ip_address"]: d for d in get_scan_devices(baseline_scan_id, db_file)}
        devices_b = {d["ip_address"]: d for d in get_scan_devices(current_scan_id, db_file)}

        new_devices = [devices_b[ip] for ip in devices_b if ip not in devices_a]
        unobserved_devices = [devices_a[ip] for ip in devices_a if ip not in devices_b]

        # 2. Compare Services & Open Ports
        services_a = {(s["device_ip"], s["port"]): s for s in get_scan_services(baseline_scan_id, db_file)}
        services_b = {(s["device_ip"], s["port"]): s for s in get_scan_services(current_scan_id, db_file)}

        new_ports = [services_b[k] for k in services_b if k not in services_a]
        closed_ports = [services_a[k] for k in services_a if k not in services_b]

        # 3. Compare Vulnerabilities
        vulns_a = get_scan_vulnerabilities(baseline_scan_id, db_file)
        vulns_b = get_scan_vulnerabilities(current_scan_id, db_file)

        # Index findings by (device_ip, rule_id, port)
        def vuln_key(v):
            return (v.get("device_ip", ""), v.get("rule_id", ""), v.get("port", 0))

        v_map_a = {vuln_key(v): v for v in vulns_a}
        v_map_b = {vuln_key(v): v for v in vulns_b}

        new_findings = [v_map_b[k] for k in v_map_b if k not in v_map_a]
        resolved_findings = [v_map_a[k] for k in v_map_a if k not in v_map_b]

        severity_changes = []
        for k in v_map_b:
            if k in v_map_a:
                old_v = v_map_a[k]
                new_v = v_map_b[k]
                if old_v.get("severity") != new_v.get("severity"):
                    severity_changes.append({
                        "key": k,
                        "title": new_v.get("title"),
                        "old_severity": old_v.get("severity"),
                        "new_severity": new_v.get("severity"),
                        "evidence": new_v.get("evidence")
                    })

        # Score delta
        score_a = float(scan_a.get("risk_score", 0.0))
        score_b = float(scan_b.get("risk_score", 0.0))
        score_delta = round(score_b - score_a, 1)

        # Narrative Summary
        summary = (
            f"Comparison between Baseline ({baseline_scan_id}) and Current ({current_scan_id}): "
            f"{len(new_findings)} new findings, {len(resolved_findings)} resolved findings, "
            f"{len(new_ports)} newly opened ports. Risk score shifted by {score_delta:+} points."
        )

        return {
            "baseline_scan_id": baseline_scan_id,
            "current_scan_id": current_scan_id,
            "baseline_timestamp": scan_a.get("timestamp"),
            "current_timestamp": scan_b.get("timestamp"),
            "target": scan_b.get("target"),
            "is_partial_scan": is_partial_scan,
            "incomplete_warning": (
                "Notice: Current scan did not complete cleanly or was canceled. "
                "Unobserved services must NOT be treated as definitively resolved vulnerabilities."
                if is_partial_scan else ""
            ),
            "score_baseline": score_a,
            "score_current": score_b,
            "score_delta": score_delta,
            "new_devices": new_devices,
            "unobserved_devices": unobserved_devices,
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "severity_changes": severity_changes,
            "summary": summary
        }
