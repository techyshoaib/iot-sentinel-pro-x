"""
IoT Sentinel Pro — Campus Edition
Main Streamlit Cyber Defense Dashboard & Assessment Engine
Built with Python 3, Streamlit, Nmap, SQLite, Pandas, and ReportLab.
100% Free, Zero-Cost, Local-First Architecture.
"""

import time
import uuid
import platform
from datetime import datetime
import pandas as pd
# pyrefly: ignore [missing-import]
import streamlit as st

# Application Module Imports
from utils.config import (
    APP_NAME,
    APP_SHORT_NAME,
    APP_VERSION,
    APP_SUBTITLE,
    IOT_COMMON_PORTS,
    DEFAULT_PORT_LIST,
    CCTV_SPECIFIC_PORTS,
    DEVICE_TYPES,
    ASSET_CRITICALITY,
    NETWORK_ZONES,
    SEVERITY_LEVELS,
    DEFAULT_DEMO_MODE,
    is_nmap_available,
    get_nmap_path
)
from utils.validators import (
    validate_ip_address,
    validate_subnet,
    validate_port_list
)
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
    get_asset_profile,
    save_asset_profile,
    get_all_asset_profiles,
    seed_demo_data_if_empty
)
from modules.discovery import discover_network
from modules.port_scanner import scan_target_device
from modules.device_classifier import DeviceClassifier
from modules.cctv_assessor import CCTVSecurityAssessor
from modules.vulnerability_engine import VulnerabilityEngine
from modules.cve_lookup import CVELookup
from modules.risk_scoring import RiskScorer
from modules.scan_comparator import ScanComparator
from modules.network_visualizer import NetworkOverviewManager
from modules.report_generator import (
    generate_pdf_report,
    generate_csv_report,
    generate_json_report
)

# Page Configuration
st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database Schema & Seed Data
init_db()
seed_demo_data_if_empty()

# Custom Cybersecurity Dark Navy CSS Theme
CYBER_CSS = """
<style>
    /* Dark Navy & Slate Theme */
    .stApp {
        background-color: #0B132B;
        color: #E2E8F0;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0F172A;
        border-right: 1px solid #1E293B;
    }
    
    /* Top Header Bar */
    .main-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        border: 1px solid #334155;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        margin-bottom: 1.6rem;
    }
    
    .main-header h1 {
        color: #38BDF8;
        font-size: 1.85rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.5px;
    }
    
    .main-header p {
        color: #94A3B8;
        margin: 0.3rem 0 0 0;
        font-size: 0.92rem;
    }

    /* Metric Cards */
    .metric-card {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 1.1rem;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.25);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        border-color: #38BDF8;
        transform: translateY(-2px);
    }
    .metric-value {
        font-size: 2.1rem;
        font-weight: 700;
        color: #F8FAFC;
        margin: 0.2rem 0;
    }
    .metric-label {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94A3B8;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: rgba(220, 38, 38, 0.2);
        color: #EF4444;
        border: 1px solid #EF4444;
        padding: 2px 7px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.2);
        color: #F97316;
        border: 1px solid #F97316;
        padding: 2px 7px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
    }
    .badge-medium {
        background-color: rgba(251, 191, 36, 0.2);
        color: #FBBF24;
        border: 1px solid #FBBF24;
        padding: 2px 7px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
    }
    .badge-low {
        background-color: rgba(59, 130, 246, 0.2);
        color: #60A5FA;
        border: 1px solid #60A5FA;
        padding: 2px 7px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
    }
    .badge-info {
        background-color: rgba(148, 163, 184, 0.2);
        color: #CBD5E1;
        border: 1px solid #94A3B8;
        padding: 2px 7px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
    }

    /* Verification Status Pill */
    .pill-confirmed {
        background-color: rgba(239, 68, 68, 0.15);
        color: #FCA5A5;
        border: 1px solid rgba(239, 68, 68, 0.4);
        padding: 2px 8px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
    }
    .pill-potential {
        background-color: rgba(245, 158, 11, 0.15);
        color: #FDE68A;
        border: 1px solid rgba(245, 158, 11, 0.4);
        padding: 2px 8px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
    }
    .pill-verify {
        background-color: rgba(59, 130, 246, 0.15);
        color: #93C5FD;
        border: 1px solid rgba(59, 130, 246, 0.4);
        padding: 2px 8px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
    }

    /* Finding Card Container */
    .finding-card {
        background-color: #1E293B;
        border-radius: 8px;
        border: 1px solid #334155;
        padding: 1.1rem;
        margin-bottom: 0.9rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.15);
    }
    .finding-card-critical { border-left: 5px solid #EF4444; }
    .finding-card-high { border-left: 5px solid #F97316; }
    .finding-card-medium { border-left: 5px solid #FBBF24; }
    .finding-card-low { border-left: 5px solid #3B82F6; }
    .finding-card-info { border-left: 5px solid #94A3B8; }

    /* Operational Mode Badges */
    .demo-pill {
        display: inline-block;
        background: rgba(217, 119, 6, 0.2);
        border: 1px solid #F59E0B;
        color: #FBBF24;
        font-size: 0.75rem;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 9999px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .live-pill {
        display: inline-block;
        background: rgba(16, 185, 129, 0.2);
        border: 1px solid #10B981;
        color: #34D399;
        font-size: 0.75rem;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 9999px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)

# Session State Initialization
if "selected_target_ip" not in st.session_state:
    st.session_state["selected_target_ip"] = "192.168.1.105"
if "last_scan_id" not in st.session_state:
    st.session_state["last_scan_id"] = "DEMO-CAM-001"
if "demo_mode" not in st.session_state:
    st.session_state["demo_mode"] = DEFAULT_DEMO_MODE

# SIDEBAR NAVIGATION
with st.sidebar:
    st.markdown("### 🛡️ **IoT Sentinel Pro**")
    st.caption("Campus Edition — Defensive Security Suite")
    st.markdown("---")

    # Operational Mode Switch
    st.markdown("#### **Operational Mode**")
    demo_toggle = st.toggle(
        "Offline Demo Mode (Safe)",
        value=st.session_state["demo_mode"],
        help="When enabled, runs simulated scans without requiring Nmap, physical hardware, or root privileges."
    )
    st.session_state["demo_mode"] = demo_toggle

    if st.session_state["demo_mode"]:
        st.markdown('<span class="demo-pill">● DEMO SIMULATION ACTIVE</span>', unsafe_allow_html=True)
        st.caption("Using verified offline IoT firmware profiles.")
    else:
        st.markdown('<span class="live-pill">● LIVE AUDIT MODE</span>', unsafe_allow_html=True)
        nmap_ok = is_nmap_available()
        if nmap_ok:
            st.caption(f"Nmap detected: `{get_nmap_path()}`")
        else:
            st.warning("⚠️ Nmap executable not detected! Install Nmap or use Demo Mode.")

    st.markdown("---")

    # Navigation Menu
    menu_selection = st.radio(
        "Navigation",
        options=[
            "📊 Executive Dashboard",
            "🔍 Device Discovery & Classification",
            "📹 CCTV Security Assessment",
            "⚡ Vulnerability Scanner",
            "📋 Scan Results & Findings",
            "🔄 Scan Comparison & History",
            "🌐 Network Overview",
            "📑 Reports & Export",
            "⚙️ Settings & Asset Management"
        ],
        index=0
    )

    st.markdown("---")
    st.markdown(
        "<div style='font-size: 0.72rem; color: #64748B;'>"
        "<b>Campus Defensive Policy:</b><br/>"
        "• Private RFC 1918 IPv4 Only<br/>"
        "• Non-destructive banner analysis<br/>"
        "• Zero exploit / Zero brute-force"
        "</div>",
        unsafe_allow_html=True
    )

# TOP BANNER
st.markdown(f"""
<div class="main-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1>🛡️ {APP_NAME}</h1>
            <p>{APP_SUBTITLE}</p>
        </div>
        <div>
            {'<span class="demo-pill" style="font-size:0.85rem; padding: 4px 12px;">DEMO MODE</span>' if st.session_state["demo_mode"] else '<span class="live-pill" style="font-size:0.85rem; padding: 4px 12px;">LIVE NETWORK MODE</span>'}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ==============================================================================
# PAGE 1: EXECUTIVE DASHBOARD
# ==============================================================================
if menu_selection == "📊 Executive Dashboard":
    st.subheader("Campus IoT Security Posture & Metrics Overview")

    all_scans = get_all_scans(limit=100)
    total_scans_count = len(all_scans)
    
    total_devices_count = 0
    total_ports_count = 0
    total_vulns_count = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    device_types_tally = {}
    for s in all_scans:
        total_devices_count += s.get("total_hosts", 0)
        total_ports_count += s.get("total_ports", 0)
        total_vulns_count += s.get("total_findings", 0)

        # Device types
        devs = get_scan_devices(s["scan_id"])
        for d in devs:
            dtype = d.get("device_type", "Generic IoT Device")
            device_types_tally[dtype] = device_types_tally.get(dtype, 0) + 1

    for s in all_scans[:15]:
        vulns = get_scan_vulnerabilities(s["scan_id"])
        for v in vulns:
            sev = v.get("severity", "").upper()
            if sev == "CRITICAL": critical_count += 1
            elif sev == "HIGH": high_count += 1
            elif sev == "MEDIUM": medium_count += 1
            elif sev == "LOW": low_count += 1
            elif sev == "INFORMATIONAL": info_count += 1

    # KPI Metric Cards
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Audits</div>
            <div class="metric-value">{total_scans_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Devices Tracked</div>
            <div class="metric-value">{total_devices_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Open Ports</div>
            <div class="metric-value">{total_ports_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Critical / High Risks</div>
            <div class="metric-value" style="color: #EF4444;">{critical_count + high_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with c5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Findings</div>
            <div class="metric-value" style="color: #FBBF24;">{total_vulns_count}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # Charts: Severity Distribution & Device-Type Distribution
    ch1, ch2 = st.columns(2)
    with ch1:
        st.markdown("#### **Findings Severity Distribution**")
        chart_data = pd.DataFrame({
            "Severity": ["Critical", "High", "Medium", "Low", "Informational"],
            "Count": [critical_count, high_count, medium_count, low_count, info_count]
        })
        st.bar_chart(chart_data.set_index("Severity"), color="#38BDF8", height=280)

    with ch2:
        st.markdown("#### **Device Classification Breakdown**")
        if device_types_tally:
            dt_df = pd.DataFrame({
                "Device Role": list(device_types_tally.keys()),
                "Count": list(device_types_tally.values())
            })
            st.bar_chart(dt_df.set_index("Device Role"), color="#06B6D4", height=280)
        else:
            st.info("No devices classified yet. Run discovery or scan to populate.")

    st.markdown("---")

    # Searchable & Filterable Device Inventory
    st.markdown("#### **Campus IoT Asset Inventory & Status**")
    
    # Gather devices across all scans
    all_devs_list = []
    for s in all_scans:
        devs = get_scan_devices(s["scan_id"])
        mode_label = "Demo" if s.get("is_demo", 0) == 1 else "Live"
        for d in devs:
            all_devs_list.append({
                "Asset ID": d.get("asset_id", "AST-N/A"),
                "IP Address": d.get("ip_address"),
                "Device Type": d.get("device_type", "Generic IoT"),
                "Confidence": d.get("classification_confidence", "Med"),
                "Vendor": d.get("vendor", "N/A"),
                "Hostname": d.get("hostname", "Unknown"),
                "Network Zone": d.get("expected_zone", "Core Campus LAN"),
                "Criticality": d.get("asset_criticality", "Medium"),
                "Scan Mode": mode_label
            })

    if all_devs_list:
        df_inv = pd.DataFrame(all_devs_list).drop_duplicates(subset=["IP Address"])
        
        f1, f2 = st.columns([2, 1])
        with f1:
            search_query = st.text_input("🔍 Search Inventory (IP, Vendor, Hostname, Asset ID)", value="")
        with f2:
            type_filter = st.selectbox("Filter by Role", options=["All Roles"] + DEVICE_TYPES)

        if search_query:
            df_inv = df_inv[
                df_inv["IP Address"].str.contains(search_query, case=False, na=False) |
                df_inv["Vendor"].str.contains(search_query, case=False, na=False) |
                df_inv["Hostname"].str.contains(search_query, case=False, na=False) |
                df_inv["Asset ID"].str.contains(search_query, case=False, na=False)
            ]
        if type_filter != "All Roles":
            df_inv = df_inv[df_inv["Device Type"] == type_filter]

        st.dataframe(df_inv, use_container_width=True, hide_index=True)
    else:
        st.info("Inventory is currently empty. Initiate a scan or discovery sweep.")


# ==============================================================================
# PAGE 2: DEVICE DISCOVERY & CLASSIFICATION
# ==============================================================================
elif menu_selection == "🔍 Device Discovery & Classification":
    st.subheader("Subnet Asset Discovery & Heuristic Classification")
    st.markdown(
        "Conduct a controlled, non-intrusive sweep across an authorized private subnet. "
        "Discovered hosts are automatically classified into standardized roles with stable asset identifiers."
    )

    col_sub, col_btn = st.columns([3, 1])
    with col_sub:
        subnet_target = st.text_input(
            "Authorized Private Subnet CIDR (e.g. 192.168.1.0/24, 10.0.0.0/24)",
            value="192.168.1.0/24",
            help="Strictly RFC 1918 private subnets. Max size /24 (256 hosts)."
        )
    with col_btn:
        st.write("")
        st.write("")
        start_discovery = st.button("🚀 Discover & Classify", use_container_width=True)

    if start_discovery:
        is_valid, msg, net_obj = validate_subnet(subnet_target)
        if not is_valid:
            st.error(f"❌ Validation Error: {msg}")
        else:
            with st.spinner(f"Sweeping subnet {subnet_target} and analyzing hardware signatures..."):
                success, status_msg, devices = discover_network(
                    subnet_cidr=subnet_target,
                    demo_mode=st.session_state["demo_mode"]
                )
                if success:
                    st.success(f"✅ {status_msg}")
                    st.session_state["discovered_devices"] = devices
                    log_audit_event(
                        event_type="DISCOVERY_COMPLETED",
                        details=f"Discovered {len(devices)} devices in {subnet_target}",
                        target=subnet_target,
                        status="SUCCESS"
                    )
                else:
                    st.error(f"❌ {status_msg}")

    # Display Discovered Devices
    discovered_list = st.session_state.get("discovered_devices", [])
    if discovered_list:
        st.markdown(f"### Discovered Campus Assets ({len(discovered_list)} devices)")
        df_dev = pd.DataFrame(discovered_list)[[
            "asset_id", "ip_address", "device_type", "classification_confidence", 
            "vendor", "hostname", "mac_address", "expected_zone"
        ]]
        df_dev.rename(columns={
            "asset_id": "Asset ID",
            "ip_address": "IP Address",
            "device_type": "Classified Role",
            "classification_confidence": "Confidence",
            "vendor": "Hardware Vendor",
            "hostname": "Hostname",
            "mac_address": "MAC Address",
            "expected_zone": "Assigned Zone"
        }, inplace=True)
        st.dataframe(df_dev, use_container_width=True, hide_index=True)

        st.markdown("#### **Quick Action: Initiate Audit on Discovered Host**")
        cols = st.columns(min(len(discovered_list), 4))
        for idx, dev in enumerate(discovered_list[:4]):
            col_target = cols[idx]
            with col_target:
                dev_ip = dev.get("ip_address")
                dev_role = dev.get("device_type", "IoT Device")
                if st.button(f"🎯 Audit {dev_ip}\n({dev_role[:16]})", key=f"quick_scan_{dev_ip}"):
                    st.session_state["selected_target_ip"] = dev_ip
                    st.info(f"Target pre-filled as {dev_ip}. Navigate to '⚡ Vulnerability Scanner' or '📹 CCTV Security Assessment'.")
    else:
        st.info("No subnet hosts currently loaded. Enter your local lab subnet above and click **Discover & Classify**.")


# ==============================================================================
# PAGE 3: CCTV SECURITY ASSESSMENT
# ==============================================================================
elif menu_selection == "📹 CCTV Security Assessment":
    st.subheader("Dedicated Surveillance & CCTV Security Audit")
    st.markdown(
        "Specialized defensive audit for IP cameras, NVRs, and surveillance streams. "
        "Evaluates RTSP port 554 exposure, web consoles, proprietary protocols, and banner flaws. "
        "**Strict policy:** Never retrieves video feeds or guesses passwords."
    )

    with st.form("cctv_form"):
        col_c1, col_c2 = st.columns([2, 1])
        with col_c1:
            cctv_ip = st.text_input(
                "Authorized Surveillance Camera IPv4 Address",
                value=st.session_state.get("selected_target_ip", "192.168.1.105")
            )
        with col_c2:
            st.write("Target Ports Checked:")
            st.caption("RTSP (554), HTTP (80, 8080), HTTPS (443, 8443), Media (8000, 37777)")

        st.markdown("---")
        cctv_auth = st.checkbox(
            "⚠️ **Authorization Certification:** I certify that I own or have written authorization to audit this surveillance device.",
            value=False
        )
        cctv_submit = st.form_submit_button("📹 Execute CCTV Security Assessment", use_container_width=True)

    if cctv_submit:
        if not cctv_auth:
            st.error("⛔ Authorization Required: You must verify explicit authorization before testing.")
        else:
            is_valid, msg, ip_obj = validate_ip_address(cctv_ip)
            if not is_valid:
                st.error(f"❌ Target Error: {msg}")
            else:
                with st.spinner(f"Assessing surveillance endpoint {cctv_ip}..."):
                    scan_ok, scan_msg, services = scan_target_device(
                        target_ip=cctv_ip,
                        ports=CCTV_SPECIFIC_PORTS,
                        demo_mode=st.session_state["demo_mode"]
                    )
                    if not scan_ok:
                        st.error(scan_msg)
                    else:
                        cctv_result = CCTVSecurityAssessor.assess_cctv_device(
                            target_ip=cctv_ip,
                            services=services
                        )
                        st.session_state["last_cctv_result"] = cctv_result

    # Display CCTV Assessment Results
    cctv_res = st.session_state.get("last_cctv_result")
    if cctv_res:
        st.markdown("### **CCTV Assessment Findings & Actionable Roadmap**")
        
        # Risk Badge Banner
        tier_color = {"CRITICAL": "#DC2626", "HIGH": "#F97316", "MEDIUM": "#FBBF24", "LOW": "#10B981"}.get(cctv_res["cctv_risk_level"], "#3B82F6")
        st.markdown(f"""
        <div style="background-color: #1E293B; border-left: 6px solid {tier_color}; padding: 1rem; border-radius: 8px; margin-bottom: 1.2rem;">
            <h4 style="margin: 0; color: #F8FAFC;">Surveillance Risk Level: <span style="color: {tier_color};">[{cctv_res['cctv_risk_level']}]</span></h4>
            <p style="margin: 0.3rem 0 0 0; color: #94A3B8;">{cctv_res['assessment_summary']}</p>
        </div>
        """, unsafe_allow_html=True)

        for idx, f in enumerate(cctv_res["findings"], start=1):
            sev = f.get("severity", "MEDIUM")
            border_cls = f"finding-card-{sev.lower()}"
            v_status = f.get("verification_status", "Potential Security Risk")

            st.markdown(f"""
            <div class="finding-card {border_cls}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span class="badge-{sev.lower()}">{sev}</span>
                        <span class="pill-verify" style="margin-left: 6px;">{v_status}</span>
                        <h4 style="margin: 0.4rem 0; color: #F8FAFC;">#{idx}. {f.get('title')}</h4>
                    </div>
                    <div style="font-size: 0.8rem; color: #94A3B8;">
                        Port: <b>{f.get('port')}/tcp</b> | Rule: <b>{f.get('rule_id')}</b>
                    </div>
                </div>
                <div style="margin-top: 0.6rem; font-size: 0.88rem; color: #CBD5E1;">
                    <p><b>Observation & Evidence:</b> <code>{f.get('observation_evidence')}</code></p>
                    <p><b>Potential Impact:</b> {f.get('potential_impact')}</p>
                    <p style="color: #6EE7B7;"><b>Remediation:</b><br/>{f.get('remediation').replace(chr(10), '<br/>')}</p>
                    <p style="color: #93C5FD;"><b>Admin Verification Steps:</b><br/>{f.get('admin_verification_steps').replace(chr(10), '<br/>')}</p>
                </div>
            </div>
            """, unsafe_allow_html=True)


# ==============================================================================
# PAGE 4: VULNERABILITY SCANNER
# ==============================================================================
elif menu_selection == "⚡ Vulnerability Scanner":
    st.subheader("Target Device Port & Vulnerability Assessment")
    st.markdown("Execute controlled, non-destructive port enumeration with pre-scan dry-run verification.")

    with st.form("scan_form"):
        col_t1, col_t2 = st.columns([2, 1])
        with col_t1:
            target_ip_input = st.text_input(
                "Authorized Target IPv4 Address",
                value=st.session_state.get("selected_target_ip", "192.168.1.105")
            )
        with col_t2:
            port_preset = st.selectbox(
                "Port Selection Preset",
                options=[
                    "Standard IoT TCP Ports (21, 22, 23, 53, 80, 443, 554, 1883, 8883, 8080, 8443)",
                    "CCTV / Surveillance Ports (80, 443, 554, 8000, 8080, 8443, 37777)",
                    "Custom Port List"
                ]
            )

        custom_ports_str = ""
        if port_preset == "Custom Port List":
            custom_ports_str = st.text_input("Custom Ports (comma-separated)", value="80, 443, 8080, 554, 1883")

        col_opt1, col_opt2 = st.columns(2)
        with col_opt1:
            enable_cve_lookup = st.checkbox(
                "Enable Free NIST NVD CVE Lookup (Optional)",
                value=False,
                help="Queries official free NVD API for known CVE matches on identified versions."
            )
        with col_opt2:
            asset_crit_choice = st.selectbox("Asset Criticality Level", options=["Critical", "High", "Medium", "Low"], index=2)

        # Pre-scan Dry Run Preview Box
        st.markdown("#### **Dry-Run Preview & Pre-Flight Validation**")
        st.info(f"Target: `{target_ip_input}` | Mode: `{'Demo Mode' if st.session_state['demo_mode'] else 'Live Safe TCP Connect'}` | Scope: `Private RFC 1918`")

        # Mandatory Ethical Authorization Checkbox
        auth_confirmed = st.checkbox(
            "⚠️ **Authorization Confirmation:** I certify that I own this device or have explicit authorization to perform this security assessment.",
            value=False
        )

        submit_scan = st.form_submit_button("⚡ Initiate Security Scan", use_container_width=True)

    if submit_scan:
        if not auth_confirmed:
            st.error("⛔ Authorization Required: You must verify authorization before scanning.")
        else:
            is_valid_ip, ip_msg, ip_obj = validate_ip_address(target_ip_input)
            if not is_valid_ip:
                st.error(f"❌ Target Error: {ip_msg}")
            else:
                # Determine Ports
                if port_preset == "CCTV / Surveillance Ports (80, 443, 554, 8000, 8080, 8443, 37777)":
                    selected_ports = CCTV_SPECIFIC_PORTS
                elif port_preset == "Custom Port List":
                    is_valid_p, p_msg, parsed_p = validate_port_list(custom_ports_str)
                    if not is_valid_p:
                        st.error(f"❌ Port Error: {p_msg}")
                        st.stop()
                    selected_ports = parsed_p
                else:
                    selected_ports = DEFAULT_PORT_LIST

                scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
                st.session_state["selected_target_ip"] = target_ip_input

                with st.status(f"Conducting Security Audit on {target_ip_input}...", expanded=True) as status_box:
                    st.write("🔍 Step 1: Performing controlled TCP port enumeration...")
                    start_time = time.time()

                    scan_ok, scan_msg, services = scan_target_device(
                        target_ip=target_ip_input,
                        ports=selected_ports,
                        demo_mode=st.session_state["demo_mode"]
                    )

                    if not scan_ok:
                        status_box.update(label="❌ Scan Failed", state="error")
                        st.error(scan_msg)
                        st.stop()

                    st.write(f"✓ Discovered {len(services)} open network services.")

                    # Step 2: Device Classification
                    st.write("🏷️ Step 2: Determining device classification & hardware role...")
                    classification = DeviceClassifier.classify_device(
                        ip_address=target_ip_input,
                        services=services
                    )
                    asset_id = DeviceClassifier.generate_asset_id("", target_ip_input)
                    st.write(f"✓ Classified as **{classification['device_type']}** (Confidence: {classification['confidence']}).")

                    # Step 3: Vulnerability Rules Engine
                    st.write("🧠 Step 3: Executing modular IoT vulnerability rules engine...")
                    findings = VulnerabilityEngine.evaluate_services(services, target_ip_input)
                    st.write(f"✓ Generated {len(findings)} potential security findings.")

                    # Step 4: Optional Free NVD CVE Lookup
                    if enable_cve_lookup and findings:
                        st.write("🌐 Step 4: Querying official free NIST NVD CVE API...")
                        cve_client = CVELookup()
                        for srv in services:
                            prod = srv.get("product", "")
                            ver = srv.get("version", "")
                            if prod:
                                cve_res = cve_client.lookup_cves_for_service(prod, ver, max_results=2)
                                for c in cve_res.get("cves", []):
                                    findings.append({
                                        "device_ip": target_ip_input,
                                        "port": srv.get("port"),
                                        "service": srv.get("service_name"),
                                        "rule_id": "CVE-NVD-MATCH",
                                        "title": f"Verified NVD Reference Match: {c.get('cve_id')}",
                                        "severity": c.get("severity", "MEDIUM"),
                                        "confidence": "MEDIUM",
                                        "verification_status": "Confirmed Technical Finding",
                                        "evidence": f"Service: {prod} {ver} verified in NIST NVD (CVSS: {c.get('cvss_score')})",
                                        "explanation": c.get("description", "Vulnerability disclosed in NIST NVD."),
                                        "remediation": "Apply manufacturer firmware security update.",
                                        "admin_verification_steps": f"Review official advisory at {c.get('cve_url')}",
                                        "cve_id": c.get("cve_id", ""),
                                        "cvss_score": c.get("cvss_score"),
                                        "cve_url": c.get("cve_url", ""),
                                        "references": [c.get("cve_url", "")]
                                    })
                    else:
                        st.write("✓ Step 4: Local offline heuristics completed (NVD query skipped/offline).")

                    # Step 5: Explainable Risk Scoring
                    st.write("📊 Step 5: Computing explainable device risk score & posture grade...")
                    risk_data = RiskScorer.calculate_score(
                        findings=findings,
                        asset_criticality=asset_crit_choice,
                        services=services
                    )
                    duration_sec = round(time.time() - start_time, 2)

                    # Step 6: Save to SQLite Database
                    devices_record = [{
                        "asset_id": asset_id,
                        "ip_address": target_ip_input,
                        "mac_address": "N/A",
                        "hostname": "Target-Host",
                        "vendor": "Generic IoT Host",
                        "device_type": classification["device_type"],
                        "classification_confidence": classification["confidence"],
                        "asset_criticality": asset_crit_choice,
                        "expected_zone": "Core Campus LAN",
                        "user_label": "",
                        "status": "up"
                    }]

                    save_scan_record(
                        scan_id=scan_id,
                        target=target_ip_input,
                        scan_type="vulnerability",
                        status="completed",
                        total_hosts=1,
                        total_ports=len(services),
                        total_findings=len(findings),
                        risk_score=risk_data["risk_score"],
                        duration_sec=duration_sec,
                        is_demo=st.session_state["demo_mode"],
                        devices=devices_record,
                        services=services,
                        vulnerabilities=findings,
                        notes=f"Audit completed ({classification['device_type']})"
                    )

                    st.session_state["last_scan_id"] = scan_id
                    status_box.update(label="✅ Assessment Completed Successfully!", state="complete")

                st.success(f"Audit finished in {duration_sec}s! Risk Score: **{risk_data['risk_score']}/100** (Grade: **{risk_data['grade']}**)")
                st.info("Navigate to **'📋 Scan Results & Findings'** to inspect findings and explainable math.")


# ==============================================================================
# PAGE 5: SCAN RESULTS & FINDINGS
# ==============================================================================
elif menu_selection == "📋 Scan Results & Findings":
    st.subheader("Vulnerability Findings & Explainable Risk Analysis")

    all_scans = get_all_scans(limit=30)
    if not all_scans:
        st.warning("No scans found in database.")
        st.stop()

    scan_ids = [s["scan_id"] for s in all_scans]
    default_idx = 0
    if st.session_state.get("last_scan_id") in scan_ids:
        default_idx = scan_ids.index(st.session_state["last_scan_id"])

    selected_scan_id = st.selectbox(
        "Select Scan Run to Review",
        options=scan_ids,
        index=default_idx,
        format_func=lambda sid: f"{sid} | Target: {next((s['target'] for s in all_scans if s['scan_id']==sid), 'N/A')} | {next((s['timestamp'] for s in all_scans if s['scan_id']==sid), 'N/A')}"
    )

    scan_info = get_scan_by_id(selected_scan_id)
    services = get_scan_services(selected_scan_id)
    findings = get_scan_vulnerabilities(selected_scan_id)
    risk_data = RiskScorer.calculate_score(findings, services=services)

    # Executive Overview Header
    r_col1, r_col2, r_col3, r_col4 = st.columns(4)
    with r_col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Target Scope</div>
            <div class="metric-value" style="font-size: 1.4rem;">{scan_info.get('target')}</div>
        </div>
        """, unsafe_allow_html=True)
    with r_col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Risk Score / Grade</div>
            <div class="metric-value" style="color: {risk_data['color']};">{risk_data['risk_score']} <span style="font-size: 1.1rem;">({risk_data['grade']})</span></div>
        </div>
        """, unsafe_allow_html=True)
    with r_col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Open Ports</div>
            <div class="metric-value">{len(services)}</div>
        </div>
        """, unsafe_allow_html=True)
    with r_col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Findings</div>
            <div class="metric-value">{len(findings)}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # Explainable Scoring Breakdown Expander
    with st.expander("🧮 Explainable Risk Scoring Math & Factor Breakdown", expanded=False):
        st.markdown(f"**Mathematical Formula:** `{risk_data['formula_documentation']}`")
        st.caption(risk_data["metric_disclaimer"])
        if risk_data["factors_breakdown"]:
            factors_df = pd.DataFrame(risk_data["factors_breakdown"])[[
                "rule_id", "title", "severity", "base_weight", "confidence", 
                "conf_multiplier", "verification_status", "verif_multiplier", "calculated_points"
            ]]
            st.dataframe(factors_df, use_container_width=True, hide_index=True)

    # Filter findings
    st.markdown("### **Security Findings Breakdown**")
    f_filter = st.radio(
        "Filter by Severity",
        options=["All", "Critical", "High", "Medium", "Low", "Informational"],
        horizontal=True
    )

    filtered_findings = findings
    if f_filter != "All":
        filtered_findings = [f for f in findings if f.get("severity", "").upper() == f_filter.upper()]

    if not filtered_findings:
        st.info(f"No findings matching severity filter '{f_filter}'.")
    else:
        for idx, f in enumerate(filtered_findings, start=1):
            sev = f.get("severity", "MEDIUM").upper()
            badge_cls = f"badge-{sev.lower()}"
            border_cls = f"finding-card-{sev.lower()}"
            v_status = f.get("verification_status", "Potential Security Risk")

            cve_pill = ""
            if f.get("cve_id"):
                cvss_str = f" (CVSS: {f.get('cvss_score')})" if f.get("cvss_score") else ""
                cve_pill = f"<span class='badge-info' style='margin-left: 8px;'>CVE: <a href='{f.get('cve_url', '#')}' target='_blank' style='color:#38BDF8; text-decoration:none;'>{f.get('cve_id')}{cvss_str}</a></span>"

            st.markdown(f"""
            <div class="finding-card {border_cls}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span class="{badge_cls}">{sev}</span>
                        <span class="pill-verify" style="margin-left: 6px;">{v_status}</span>
                        {cve_pill}
                        <h4 style="margin: 0.4rem 0; color: #F8FAFC;">#{idx}. [{f.get('rule_id', 'RULE')}] {f.get('title')}</h4>
                    </div>
                    <div style="font-size: 0.8rem; color: #94A3B8;">
                        Port: <b>{f.get('port')}/tcp</b> | Confidence: <b>{f.get('confidence', 'HIGH')}</b>
                    </div>
                </div>
                <div style="margin-top: 0.6rem; font-size: 0.88rem; color: #CBD5E1;">
                    <p><b>Observed Evidence:</b> <code>{f.get('evidence', 'N/A')}</code></p>
                    <p><b>Risk Impact:</b> {f.get('explanation', 'N/A')}</p>
                    <p style="color: #6EE7B7;"><b>Recommended Remediation:</b><br/>{f.get('remediation', 'N/A').replace(chr(10), '<br/>')}</p>
                    {f"<p style='color: #93C5FD;'><b>Admin Verification Procedure:</b><br/>{f.get('admin_verification_steps').replace(chr(10), '<br/>')}</p>" if f.get('admin_verification_steps') else ""}
                </div>
            </div>
            """, unsafe_allow_html=True)


# ==============================================================================
# PAGE 6: SCAN COMPARISON & HISTORY
# ==============================================================================
elif menu_selection == "🔄 Scan Comparison & History":
    st.subheader("Scan Snapshot Differentials & Historical Audit Log")

    all_scans = get_all_scans(limit=50)
    if len(all_scans) < 2:
        st.info("At least two scans are required to compute snapshot differentials.")
    else:
        st.markdown("#### **Compare Two Scan Runs (Asset & Finding Deltas)**")
        sc1, sc2 = st.columns(2)
        with sc1:
            baseline_id = st.selectbox(
                "Baseline (Older) Scan",
                options=[s["scan_id"] for s in all_scans],
                index=min(1, len(all_scans)-1)
            )
        with sc2:
            current_id = st.selectbox(
                "Current (Newer) Scan",
                options=[s["scan_id"] for s in all_scans],
                index=0
            )

        if st.button("🔄 Compute Scan Differential"):
            diff = ScanComparator.compare_scans(baseline_id, current_id)
            if diff.get("error"):
                st.error(diff["error"])
            else:
                st.session_state["comparison_diff"] = diff

        diff_res = st.session_state.get("comparison_diff")
        if diff_res:
            st.markdown(f"**Comparison Summary:** {diff_res['summary']}")
            if diff_res.get("incomplete_warning"):
                st.warning(diff_res["incomplete_warning"])

            d1, d2, d3, d4 = st.columns(4)
            with d1:
                st.metric("Risk Score Shift", f"{diff_res['score_current']} / 100", f"{diff_res['score_delta']:+} pts", delta_color="inverse")
            with d2:
                st.metric("New Findings", len(diff_res["new_findings"]))
            with d3:
                st.metric("Resolved Findings", len(diff_res["resolved_findings"]))
            with d4:
                st.metric("New Open Ports", len(diff_res["new_ports"]))

            st.markdown("---")
            if diff_res["new_findings"]:
                st.markdown("##### 🚨 Newly Detected Security Findings:")
                for nf in diff_res["new_findings"]:
                    st.write(f"- **[{nf.get('severity')}]** {nf.get('title')} (Port {nf.get('port')})")

            if diff_res["resolved_findings"]:
                st.markdown("##### ✅ Resolved / Closed Findings:")
                for rf in diff_res["resolved_findings"]:
                    st.write(f"- **[{rf.get('severity')}]** {rf.get('title')} (Port {rf.get('port')})")

    st.markdown("---")
    st.markdown("#### **Scan Snapshot History (SQLite Records)**")
    if all_scans:
        df_sc = pd.DataFrame(all_scans)[[
            "scan_id", "timestamp", "target", "scan_type", "total_ports", 
            "total_findings", "risk_score", "duration_sec", "is_demo"
        ]]
        df_sc["is_demo"] = df_sc["is_demo"].apply(lambda d: "Demo" if d == 1 else "Live")
        st.dataframe(df_sc, use_container_width=True, hide_index=True)


# ==============================================================================
# PAGE 7: NETWORK OVERVIEW
# ==============================================================================
elif menu_selection == "🌐 Network Overview":
    st.subheader("Campus IoT Network Topology & Policy Compliance")
    st.markdown("Visualizes asset distribution across expected campus security zones and identifies policy deviations.")

    all_scans = get_all_scans(limit=20)
    if not all_scans:
        st.warning("No scan data available.")
        st.stop()

    selected_sid = st.selectbox(
        "Select Scan for Topology Overview",
        options=[s["scan_id"] for s in all_scans],
        format_func=lambda sid: f"{sid} ({next((s['target'] for s in all_scans if s['scan_id']==sid), '')})"
    )

    devices = get_scan_devices(selected_sid)
    services = get_scan_services(selected_sid)
    overview = NetworkOverviewManager.generate_network_overview(devices, services)

    st.caption(overview["inferred_disclaimer"])

    # Policy Deviations Alerts
    if overview["policy_deviations"]:
        st.markdown("### ⚠️ **Identified Security Policy Deviations**")
        for dev in overview["policy_deviations"]:
            st.error(f"**[{dev['severity']}] {dev['deviation_title']}** on host `{dev['ip_address']}` ({dev['zone']}): {dev['explanation']}")
    else:
        st.success("✅ No policy deviations identified for current observed assets.")

    st.markdown("---")
    st.markdown("### **Asset Distribution by Security Zone**")
    for zone_name, nodes in overview["zones"].items():
        if nodes:
            with st.expander(f"🏢 {zone_name} ({len(nodes)} assets)", expanded=True):
                for node in nodes:
                    ports_str = ", ".join(str(p) for p in node['open_ports']) or "None"
                    st.write(f"- **{node['ip_address']}** ({node['hostname']}) | Role: **{node['device_type']}** | Open Ports: `{ports_str}` | Reachability: `{node['reachability']}`")


# ==============================================================================
# PAGE 8: REPORTS & EXPORT
# ==============================================================================
elif menu_selection == "📑 Reports & Export":
    st.subheader("Generate Executive Audit Reports (PDF, CSV & JSON)")
    st.markdown("Export comprehensive security audit reports. Fictional demo runs include prominent demonstration watermarks.")

    all_scans = get_all_scans(limit=50)
    if not all_scans:
        st.warning("No scans available to report.")
        st.stop()

    rep_scan_id = st.selectbox(
        "Select Scan Run for Report Generation",
        options=[s["scan_id"] for s in all_scans],
        format_func=lambda sid: f"{sid} | Target: {next((s['target'] for s in all_scans if s['scan_id']==sid), 'N/A')} | {next((s['timestamp'] for s in all_scans if s['scan_id']==sid), 'N/A')}"
    )

    scan_info = get_scan_by_id(rep_scan_id)
    devices = get_scan_devices(rep_scan_id)
    services = get_scan_services(rep_scan_id)
    findings = get_scan_vulnerabilities(rep_scan_id)
    risk_data = RiskScorer.calculate_score(findings, services=services)

    st.markdown("---")
    col_pdf, col_csv, col_json = st.columns(3)

    with col_pdf:
        st.markdown("#### **📄 Executive PDF Report**")
        st.caption("ReportLab compilation with executive summary, tables, and watermarks.")
        try:
            pdf_bytes = generate_pdf_report(
                scan_meta=scan_info,
                devices=devices,
                services=services,
                findings=findings,
                risk_data=risk_data
            )
            st.download_button(
                label="⬇️ Download PDF Security Report",
                data=pdf_bytes,
                file_name=f"IoT_Audit_{scan_info.get('target', 'host')}_{scan_info.get('scan_id')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        except Exception as e:
            st.error(f"Error compiling PDF: {str(e)}")

    with col_csv:
        st.markdown("#### **📊 Tabular CSV Report**")
        st.caption("Spreadsheet format for SIEM or spreadsheet tracking.")
        try:
            csv_data = generate_csv_report(
                scan_meta=scan_info,
                findings=findings,
                services=services,
                devices=devices
            )
            st.download_button(
                label="⬇️ Download CSV Spreadsheet",
                data=csv_data,
                file_name=f"IoT_Findings_{scan_info.get('target', 'host')}_{scan_info.get('scan_id')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        except Exception as e:
            st.error(f"Error compiling CSV: {str(e)}")

    with col_json:
        st.markdown("#### **⚙️ Machine JSON Export**")
        st.caption("Structured JSON for automated security orchestration.")
        try:
            json_data = generate_json_report(
                scan_meta=scan_info,
                devices=devices,
                services=services,
                findings=findings,
                risk_data=risk_data
            )
            st.download_button(
                label="⬇️ Download JSON Data",
                data=json_data,
                file_name=f"IoT_Report_{scan_info.get('target', 'host')}_{scan_info.get('scan_id')}.json",
                mime="application/json",
                use_container_width=True
            )
        except Exception as e:
            st.error(f"Error compiling JSON: {str(e)}")


# ==============================================================================
# PAGE 9: SETTINGS & ASSET MANAGEMENT
# ==============================================================================
elif menu_selection == "⚙️ Settings & Asset Management":
    st.subheader("Asset Profiling, System Diagnostics & Campus Policies")

    tab1, tab2, tab3 = st.tabs(["🏷️ Asset Profiling & Criticality", "🛠️ System Diagnostics & Audit Trail", "🎓 College Defense & Viva Guide"])

    with tab1:
        st.markdown("#### **Configure Expected Asset Profiles & Baselines**")
        st.caption("Define expected roles, network zones, and authorized baseline ports to detect profile deviations.")
        
        prof_ip = st.text_input("Asset IP Address", value="192.168.1.105")
        prof_label = st.text_input("Asset Label / Location", value="Campus Main Gate Camera")
        prof_crit = st.selectbox("Asset Criticality", options=list(ASSET_CRITICALITY.keys()), index=1)
        prof_zone = st.selectbox("Expected Network Zone", options=NETWORK_ZONES, index=0)
        prof_role = st.selectbox("Expected Role", options=DEVICE_TYPES, index=0)
        prof_ports_str = st.text_input("Expected Baseline Ports (comma-separated)", value="80, 554, 8080")

        if st.button("💾 Save Asset Profile"):
            try:
                p_list = [int(p.strip()) for p in prof_ports_str.split(",") if p.strip()]
                save_asset_profile(
                    ip_address=prof_ip,
                    asset_id=DeviceClassifier.generate_asset_id("", prof_ip),
                    user_label=prof_label,
                    asset_criticality=prof_crit,
                    expected_zone=prof_zone,
                    expected_role=prof_role,
                    expected_ports=p_list
                )
                st.success(f"Profile saved for {prof_ip}!")
            except Exception as ex:
                st.error(f"Failed to save profile: {str(ex)}")

    with tab2:
        st.markdown("#### **System Diagnostics**")
        d_c1, d_c2 = st.columns(2)
        with d_c1:
            st.write(f"**Platform OS:** `{platform.system()} {platform.release()}`")
            st.write(f"**Nmap Availability:** `{'✓ Installed' if is_nmap_available() else '✗ Missing (Demo Mode Active)'}`")
            st.write(f"**Nmap Path:** `{get_nmap_path()}`")
        with d_c2:
            st.write(f"**Database Status:** `✓ SQLite Online (iot_scanner.db)`")
            st.write(f"**Application Version:** `{APP_VERSION}`")
            st.write(f"**Default Operational Mode:** `{'Demo Mode (Safe)' if st.session_state['demo_mode'] else 'Live Mode'}`")

        st.markdown("---")
        st.markdown("#### **Local Audit Trail**")
        logs = get_audit_logs(limit=25)
        if logs:
            st.dataframe(pd.DataFrame(logs), use_container_width=True, hide_index=True)
        else:
            st.info("No audit events logged yet.")

    with tab3:
        st.markdown("#### **College Viva / Project Defense Q&A Talking Points**")
        st.markdown("""
        1. **What is the difference between general port scanners and IoT Sentinel Pro?**  
           *General scanners often fuzz or aggressively probe ports, which crashes low-power IoT microcontrollers. IoT Sentinel Pro uses conservative timeouts, light version probes, heuristic asset classification, and an explainable risk scoring model tailored to embedded devices.*
        2. **Why is Demo Mode essential for project defense?**  
           *It provides deterministic, realistic simulation of CCTV cameras, routers, and sensor nodes, allowing professors to evaluate all 9 pages, PDF/CSV/JSON reporting, and risk scoring without needing physical lab hardware.*
        3. **How does the scanner avoid false CVE reporting?**  
           *It rejects generic banner strings (e.g., 'http', 'linux') and only queries NVD API v2.0 when reliable product and version strings are confirmed. It caches results locally and operates 100% offline if the internet is unavailable.*
        """)
