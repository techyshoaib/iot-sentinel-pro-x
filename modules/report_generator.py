"""
Professional Report Generator for IoT Sentinel Pro — Campus Edition.
Compiles executive PDF security reports (ReportLab), tabular CSV spreadsheets,
and structured JSON integration files.

Key Requirements:
- Prominent [DEMO MODE — SIMULATION DATA] watermark on fictional demo reports.
- Comprehensive executive summaries, scope authorization statements, and explainable risk breakdowns.
- Findings grouped by severity with evidence, verification status, and admin verification steps.
- Historical comparison deltas included when comparative data is available.
- Zero paid APIs or external document conversion servers.
"""

import io
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

from utils.config import APP_NAME, APP_VERSION, REPORTS_DIR

def generate_pdf_report(
    scan_meta: Dict[str, Any],
    devices: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    comparison_data: Optional[Dict[str, Any]] = None
) -> bytes:
    """
    Builds an executive PDF security report using ReportLab.
    Returns raw PDF bytes and writes a copy to reports/.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A")
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#475569")
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=10,
        spaceAfter=5
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1E293B")
    )
    cell_bold = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )
    cell_text = ParagraphStyle(
        "CellText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155")
    )
    demo_banner_style = ParagraphStyle(
        "DemoBanner",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#B45309"),
        alignment=1  # Centered
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Italic"],
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#64748B")
    )

    story = []

    # 1. Header Banner & Watermark
    is_demo = scan_meta.get("is_demo", 0) == 1

    if is_demo:
        demo_table = Table([[Paragraph("⚠️ DEMO MODE — FICTIONAL SIMULATION DATA FOR ACADEMIC EVALUATION ONLY", demo_banner_style)]], colWidths=[7.4 * inch])
        demo_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
            ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor("#F59E0B")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(demo_table)
        story.append(Spacer(1, 8))

    mode_badge = "[DEMO SIMULATION]" if is_demo else "[AUTHORIZED LIVE AUDIT]"
    mode_color = "#D97706" if is_demo else "#0284C7"

    story.append(Paragraph(f"<b>{APP_NAME}</b>", title_style))
    story.append(Paragraph(
        f"Executive Cyber Audit & Vulnerability Assessment Report | <font color='{mode_color}'><b>{mode_badge}</b></font> | Version {APP_VERSION}",
        subtitle_style
    ))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=10))

    # 2. Executive Scope & Assessment Summary
    story.append(Paragraph("1. Assessment Scope & Executive Summary", h2_style))

    risk_score = risk_data.get("risk_score", 0.0)
    grade = risk_data.get("grade", "N/A")
    posture = risk_data.get("posture", "Unknown")
    counts = risk_data.get("counts", {})

    meta_table_data = [
        [
            Paragraph("<b>Target Host / Scope:</b>", cell_bold),
            Paragraph(str(scan_meta.get("target", "N/A")), cell_text),
            Paragraph("<b>Scan Timestamp:</b>", cell_bold),
            Paragraph(str(scan_meta.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M"))), cell_text)
        ],
        [
            Paragraph("<b>Scan ID / Status:</b>", cell_bold),
            Paragraph(f"{scan_meta.get('scan_id', 'N/A')} ({scan_meta.get('status', 'completed')})", cell_text),
            Paragraph("<b>Duration / Hosts:</b>", cell_bold),
            Paragraph(f"{scan_meta.get('duration_sec', 0.0)}s | {len(devices)} host(s)", cell_text)
        ],
        [
            Paragraph("<b>Overall Risk Score:</b>", cell_bold),
            Paragraph(f"<b>{risk_score} / 100</b> (Grade: <b>{grade}</b>)", cell_bold),
            Paragraph("<b>Assessed Risk Posture:</b>", cell_bold),
            Paragraph(f"<b>{posture}</b>", cell_text)
        ]
    ]

    meta_table = Table(meta_table_data, colWidths=[1.7 * inch, 2.0 * inch, 1.7 * inch, 2.0 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # Severity Metric Grid
    sev_summary_data = [
        [
            Paragraph("<font color='#DC2626'><b>CRITICAL</b></font>", cell_bold),
            Paragraph("<font color='#EA580C'><b>HIGH</b></font>", cell_bold),
            Paragraph("<font color='#D97706'><b>MEDIUM</b></font>", cell_bold),
            Paragraph("<font color='#2563EB'><b>LOW</b></font>", cell_bold),
            Paragraph("<font color='#64748B'><b>INFO</b></font>", cell_bold),
        ],
        [
            Paragraph(f"<font size=11 color='#DC2626'><b>{counts.get('CRITICAL', 0)}</b></font>", cell_bold),
            Paragraph(f"<font size=11 color='#EA580C'><b>{counts.get('HIGH', 0)}</b></font>", cell_bold),
            Paragraph(f"<font size=11 color='#D97706'><b>{counts.get('MEDIUM', 0)}</b></font>", cell_bold),
            Paragraph(f"<font size=11 color='#2563EB'><b>{counts.get('LOW', 0)}</b></font>", cell_bold),
            Paragraph(f"<font size=11 color='#64748B'><b>{counts.get('INFORMATIONAL', 0)}</b></font>", cell_bold),
        ]
    ]
    sev_table = Table(sev_summary_data, colWidths=[1.48 * inch] * 5)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FFFFFF")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 10))

    # 3. Discovered Asset Inventory
    story.append(Paragraph("2. Discovered Asset Inventory & Device Classification", h2_style))
    if devices:
        dev_headers = [
            Paragraph("<b>IP Address</b>", cell_bold),
            Paragraph("<b>MAC / Vendor</b>", cell_bold),
            Paragraph("<b>Hostname</b>", cell_bold),
            Paragraph("<b>Device Type / Role</b>", cell_bold),
            Paragraph("<b>Zone</b>", cell_bold),
        ]
        dev_rows = [dev_headers]
        for d in devices:
            vendor_str = d.get("vendor", "N/A")[:24]
            dev_rows.append([
                Paragraph(d.get("ip_address", "N/A"), cell_text),
                Paragraph(f"{d.get('mac_address', 'N/A')}<br/>{vendor_str}", cell_text),
                Paragraph(d.get("hostname", "Unknown")[:24], cell_text),
                Paragraph(f"{d.get('device_type', 'Generic IoT')}<br/><i>Conf: {d.get('classification_confidence', 'Med')}</i>", cell_text),
                Paragraph(d.get("expected_zone", "Core Campus LAN"), cell_text),
            ])

        dev_table = Table(dev_rows, colWidths=[1.2 * inch, 1.8 * inch, 1.4 * inch, 1.6 * inch, 1.4 * inch])
        dev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(dev_table)
    else:
        story.append(Paragraph("<i>No assets discovered.</i>", body_style))

    story.append(Spacer(1, 10))

    # 4. Discovered Ports Surface Table
    story.append(Paragraph("3. Observed Open Network Services", h2_style))
    if services:
        srv_headers = [
            Paragraph("<b>Port</b>", cell_bold),
            Paragraph("<b>Proto</b>", cell_bold),
            Paragraph("<b>Service</b>", cell_bold),
            Paragraph("<b>Product / Version / Banner</b>", cell_bold),
            Paragraph("<b>State</b>", cell_bold),
        ]
        srv_rows = [srv_headers]
        for s in services:
            banner_desc = s.get("banner") or f"{s.get('product', '')} {s.get('version', '')}".strip() or "Standard Service"
            srv_rows.append([
                Paragraph(str(s.get("port")), cell_text),
                Paragraph(str(s.get("protocol", "tcp")).upper(), cell_text),
                Paragraph(str(s.get("service_name", "unknown")).upper(), cell_text),
                Paragraph(banner_desc[:65], cell_text),
                Paragraph(str(s.get("state", "open")).capitalize(), cell_text),
            ])

        srv_table = Table(srv_rows, colWidths=[0.8 * inch, 0.7 * inch, 1.4 * inch, 3.7 * inch, 0.8 * inch])
        srv_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(srv_table)
    story.append(Spacer(1, 10))

    # 5. Security Findings & Recommended Remediations
    story.append(Paragraph("4. Vulnerability Findings & Strategic Remediation", h2_style))
    if findings:
        for idx, f in enumerate(findings, start=1):
            sev = str(f.get("severity", "MEDIUM")).upper()
            sev_color_hex = {
                "CRITICAL": "#DC2626",
                "HIGH": "#EA580C",
                "MEDIUM": "#D97706",
                "LOW": "#2563EB",
                "INFORMATIONAL": "#64748B"
            }.get(sev, "#64748B")

            v_status = f.get("verification_status", "Potential Security Risk")
            cve_ref = f.get("cve_id", "")
            cve_str = f" | CVE Reference: <b>{cve_ref}</b>" if cve_ref else ""
            rule_id = f.get("rule_id", "IOT-RULE")

            finding_block = [
                [
                    Paragraph(
                        f"<b>#{idx}. [{rule_id}] {f.get('title')}</b>",
                        ParagraphStyle("FTitle", parent=cell_bold, fontSize=9, textColor=colors.HexColor("#0F172A"))
                    ),
                    Paragraph(f"<font color='{sev_color_hex}'><b>[{sev}]</b></font>", cell_bold)
                ],
                [
                    Paragraph(
                        f"<b>Verification Status:</b> <b>{v_status}</b> | "
                        f"<b>Port:</b> {f.get('port')}/tcp | <b>Confidence:</b> {f.get('confidence', 'HIGH')}{cve_str}",
                        cell_text
                    ),
                    ""
                ],
                [
                    Paragraph(f"<b>Observed Evidence:</b> <i>{f.get('evidence', 'N/A')}</i>", cell_text),
                    ""
                ],
                [
                    Paragraph(f"<b>Risk Impact:</b> {f.get('explanation', 'N/A')}", cell_text),
                    ""
                ],
                [
                    Paragraph(f"<b>Recommended Remediation:</b><br/>{f.get('remediation', 'N/A').replace(chr(10), '<br/>')}", cell_text),
                    ""
                ]
            ]

            # If admin verification steps exist, append
            if f.get("admin_verification_steps"):
                finding_block.append([
                    Paragraph(f"<b>Admin Verification Procedure:</b><br/>{f.get('admin_verification_steps').replace(chr(10), '<br/>')}", cell_text),
                    ""
                ])

            f_table = Table(finding_block, colWidths=[6.3 * inch, 1.1 * inch])
            f_table.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("SPAN", (0, 4), (1, 4)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("LINEBEFORE", (0, 0), (0, -1), 3.0, colors.HexColor(sev_color_hex)),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ]))
            story.append(KeepTogether(f_table))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("<i>No vulnerabilities identified.</i>", body_style))

    story.append(Spacer(1, 8))

    # 6. Historical Scan Comparison (if comparative data supplied)
    if comparison_data and not comparison_data.get("error"):
        story.append(Paragraph("5. Historical Differential & Asset Delta", h2_style))
        story.append(Paragraph(comparison_data.get("summary", ""), body_style))
        if comparison_data.get("incomplete_warning"):
            story.append(Paragraph(f"<font color='#B45309'><b>{comparison_data.get('incomplete_warning')}</b></font>", body_style))
        story.append(Spacer(1, 8))

    # 7. Ethical Guidelines, Legal Policy & College Disclaimer
    story.append(Paragraph("6. Assessment Methodology & Educational Disclaimer", h2_style))
    disclaimer_text = (
        "<b>LEGAL & COMPLIANCE NOTICE:</b> This security assessment was conducted using passive and non-destructive "
        "defensive methodologies, including TCP banner inspection and controlled port enumeration. "
        "No brute-force attacks, active exploits, payload injections, credential guessing, or denial-of-service tests were performed. "
        "Identified open ports indicate an accessible attack surface and potential configuration risks rather than "
        "confirmed compromise. This project was developed solely for academic research and authorized defense auditing."
    )
    story.append(Paragraph(disclaimer_text, disclaimer_style))

    # Build PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    # Save local copy in reports/
    try:
        ts_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_sanitized = str(scan_meta.get("target", "target")).replace(".", "_")
        report_file = REPORTS_DIR / f"audit_report_{target_sanitized}_{ts_filename}.pdf"
        report_file.write_bytes(pdf_bytes)
    except Exception:
        pass

    return pdf_bytes

def generate_csv_report(
    scan_meta: Dict[str, Any],
    findings: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
    devices: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Generates structured CSV export of findings and asset inventory."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Scan_ID",
        "Timestamp",
        "Target_IP",
        "Scan_Mode",
        "Rule_ID",
        "Finding_Title",
        "Severity",
        "Confidence",
        "Verification_Status",
        "Port",
        "Service",
        "Evidence",
        "Risk_Explanation",
        "Recommended_Remediation",
        "Admin_Verification_Steps",
        "CVE_ID",
        "CVSS_Score",
        "CVE_URL"
    ])

    scan_id = scan_meta.get("scan_id", "")
    timestamp = scan_meta.get("timestamp", "")
    target = scan_meta.get("target", "")
    mode = "DEMO" if scan_meta.get("is_demo", 0) == 1 else "LIVE"

    if findings:
        for f in findings:
            writer.writerow([
                scan_id,
                timestamp,
                target,
                mode,
                f.get("rule_id", "IOT-RULE"),
                f.get("title", ""),
                f.get("severity", ""),
                f.get("confidence", ""),
                f.get("verification_status", "Potential Security Risk"),
                f.get("port", ""),
                f.get("service", ""),
                f.get("evidence", ""),
                f.get("explanation", ""),
                f.get("remediation", ""),
                f.get("admin_verification_steps", ""),
                f.get("cve_id", ""),
                f.get("cvss_score", ""),
                f.get("cve_url", "")
            ])
    else:
        writer.writerow([
            scan_id, timestamp, target, mode, "NONE", "No Findings Detected",
            "INFORMATIONAL", "HIGH", "Informational Observation", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "", "", ""
        ])

    csv_str = output.getvalue()
    output.close()

    try:
        ts_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_sanitized = str(scan_meta.get("target", "target")).replace(".", "_")
        csv_file = REPORTS_DIR / f"audit_report_{target_sanitized}_{ts_filename}.csv"
        csv_file.write_text(csv_str, encoding="utf-8")
    except Exception:
        pass

    return csv_str

def generate_json_report(
    scan_meta: Dict[str, Any],
    devices: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    comparison_data: Optional[Dict[str, Any]] = None
) -> str:
    """Generates structured machine-readable JSON security audit export."""
    data = {
        "generator": {
            "application": APP_NAME,
            "version": APP_VERSION,
            "exported_at": datetime.now().isoformat()
        },
        "scan_metadata": scan_meta,
        "risk_assessment": {
            "risk_score": risk_data.get("risk_score", 0.0),
            "grade": risk_data.get("grade", "N/A"),
            "posture": risk_data.get("posture", "Unknown"),
            "severity_counts": risk_data.get("counts", {}),
            "verification_counts": risk_data.get("verification_counts", {}),
            "factors_breakdown": risk_data.get("factors_breakdown", [])
        },
        "discovered_assets": devices,
        "observed_services": services,
        "vulnerability_findings": findings,
        "historical_comparison": comparison_data if comparison_data else None,
        "compliance_disclaimer": (
            "This assessment was conducted using passive, non-destructive defensive methodologies. "
            "Findings represent potential risk indicators and architectural exposures."
        )
    }

    json_str = json.dumps(data, indent=2)

    try:
        ts_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_sanitized = str(scan_meta.get("target", "target")).replace(".", "_")
        json_file = REPORTS_DIR / f"audit_report_{target_sanitized}_{ts_filename}.json"
        json_file.write_text(json_str, encoding="utf-8")
    except Exception:
        pass

    return json_str
