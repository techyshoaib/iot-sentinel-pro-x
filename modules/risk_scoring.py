"""
Explainable Risk Scoring Engine for IoT Sentinel Pro — Campus Edition.

Mathematical Model:
For each finding i:
    Risk_i = Base_Severity(i) * Confidence_Factor(i) * Verification_Factor(i)

Raw_Risk = Sum(Risk_i)
Composite_Score = Min(100.0, Round(Raw_Risk * Asset_Criticality_Multiplier * Exposure_Context_Multiplier, 1))

Factors Considered:
1. Finding Severity: Critical=25, High=15, Medium=8, Low=3, Info=1
2. Confidence: High=1.0, Medium=0.75, Low=0.5
3. Verification Status: Confirmed=1.0, Potential Risk=0.85, Needs Verification=0.65, Informational=0.4
4. Asset Criticality: Critical=1.30, High=1.15, Medium=1.00, Low=0.85
5. Exposure Context: Multiple unencrypted management protocols compound exposure risk by 10% (1.10x)

Notice:
This calculation represents a composite architectural risk score. It is explicitly
distinct from official NIST CVSS v3.1 base metrics, which are reported separately
when verified CVE data is retrieved from NVD.
"""

from typing import List, Dict, Any, Optional
from utils.config import SEVERITY_LEVELS, ASSET_CRITICALITY

class RiskScorer:
    """Calculates transparent, explainable composite risk metrics for IoT devices."""

    @classmethod
    def calculate_score(
        cls,
        findings: List[Dict[str, Any]],
        asset_criticality: str = "Medium",
        services: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Computes composite risk score (0.0 to 100.0) with a step-by-step
        factor breakdown for explainability and auditing.
        """
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0
        }

        verification_counts = {
            "Confirmed Technical Finding": 0,
            "Potential Security Risk": 0,
            "Needs Administrative Verification": 0,
            "Informational Observation": 0
        }

        factors_breakdown = []
        raw_points = 0.0

        for f in findings:
            sev = str(f.get("severity", "MEDIUM")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["MEDIUM"] += 1

            base_weight = float(SEVERITY_LEVELS.get(sev, {}).get("weight", 8))

            # 1. Confidence Multiplier
            conf_str = str(f.get("confidence", "HIGH")).upper()
            conf_multiplier = 1.00
            if conf_str == "MEDIUM":
                conf_multiplier = 0.75
            elif conf_str == "LOW":
                conf_multiplier = 0.50

            # 2. Verification Status Multiplier
            v_status = str(f.get("verification_status", "Potential Security Risk"))
            if v_status in verification_counts:
                verification_counts[v_status] += 1
            else:
                verification_counts["Potential Security Risk"] += 1

            if "Confirmed" in v_status:
                verif_multiplier = 1.00
            elif "Potential" in v_status:
                verif_multiplier = 0.85
            elif "Needs" in v_status:
                verif_multiplier = 0.65
            else:
                verif_multiplier = 0.40

            finding_points = round(base_weight * conf_multiplier * verif_multiplier, 2)
            raw_points += finding_points

            factors_breakdown.append({
                "rule_id": f.get("rule_id", "RULE"),
                "title": f.get("title", "Finding"),
                "severity": sev,
                "base_weight": base_weight,
                "confidence": conf_str,
                "conf_multiplier": conf_multiplier,
                "verification_status": v_status,
                "verif_multiplier": verif_multiplier,
                "calculated_points": finding_points
            })

        # 3. Asset Criticality Multiplier
        crit_multiplier = float(ASSET_CRITICALITY.get(asset_criticality, 1.00))

        # 4. Exposure Context Multiplier
        # Compounding penalty if multiple cleartext management services coexist (Telnet + FTP + HTTP)
        exposure_multiplier = 1.00
        if services:
            open_cleartext = [
                s.get("port") for s in services
                if s.get("port") in (21, 23, 80, 1883, 554) and s.get("state", "open") == "open"
            ]
            if len(open_cleartext) >= 2:
                exposure_multiplier = 1.10  # 10% compounding attack surface penalty

        # Final Normalized Score (Strictly Capped at 100.0)
        final_score = min(100.0, round(raw_points * crit_multiplier * exposure_multiplier, 1))

        # Posture Grade Assignment
        if final_score == 0:
            grade = "A+"
            posture = "Hardened / No Identified Risks"
            color = "#10B981"  # Emerald Green
            badge_class = "success"
        elif final_score <= 20.0:
            grade = "A"
            posture = "Low Risk (Minimal Attack Surface)"
            color = "#3B82F6"  # Blue
            badge_class = "info"
        elif final_score <= 45.0:
            grade = "B"
            posture = "Moderate Risk (Standard IoT Surface)"
            color = "#FBBF24"  # Amber
            badge_class = "warning"
        elif final_score <= 75.0:
            grade = "C"
            posture = "Elevated Risk (Unencrypted Services Present)"
            color = "#F97316"  # Orange
            badge_class = "warning-high"
        elif final_score <= 90.0:
            grade = "D"
            posture = "High Risk (Critical Protocol Exposures)"
            color = "#EF4444"  # Red
            badge_class = "danger"
        else:
            grade = "F"
            posture = "Severe Vulnerability Hazard (Immediate Action Required)"
            color = "#DC2626"  # Crimson
            badge_class = "danger-critical"

        return {
            "risk_score": final_score,
            "grade": grade,
            "posture": posture,
            "color": color,
            "badge_class": badge_class,
            "counts": severity_counts,
            "verification_counts": verification_counts,
            "total_findings": len(findings),
            "raw_points": round(raw_points, 2),
            "asset_criticality": asset_criticality,
            "asset_criticality_multiplier": crit_multiplier,
            "exposure_context_multiplier": exposure_multiplier,
            "factors_breakdown": factors_breakdown,
            "formula_documentation": (
                f"Score = Min(100, RawPoints({round(raw_points, 1)}) * "
                f"AssetWeight({crit_multiplier}) * ExposureWeight({exposure_multiplier}))"
            ),
            "metric_disclaimer": (
                "Notice: This score is a composite defensive architectural metric. "
                "It is distinct from official NIST CVSS base metrics, which are reported "
                "separately when reliable NVD CVE references are retrieved."
            )
        }
