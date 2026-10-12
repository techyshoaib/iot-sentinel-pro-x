>>>>>>> HEAD
# IoT Sentinel Pro — Campus Edition 🛡️

**IoT Sentinel Pro — Campus Edition** is an advanced, professional, zero-cost cybersecurity auditing, asset classification, and vulnerability assessment engine tailored for Internet of Things (IoT) ecosystems on authorized private campus networks.

![Project Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Kali%20Linux-blue)
![Cost](https://img.shields.io/badge/Cost-100%25%20Free%20%26%20Open%20Source-brightgreen)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Architecture](https://img.shields.io/badge/Architecture-Local--First%20%2F%20Serverless-purple)

---

## 🌟 Executive Summary & Key Upgrades

- **Zero-Cost & Local-First:** 100% free and open-source. Requires **no paid APIs, cloud credits, mandatory keys, software licenses, or credit cards**. Runs completely on your local workstation or virtual machine.
- **Dedicated CCTV & Surveillance Assessor:** Specialized audit pipeline assessing RTSP (554), cleartext HTTP/HTTPS consoles, proprietary media ports (8000/37777), and legacy server banners with step-by-step verification procedures for security administrators.
- **Heuristic Device Classification & Stable Asset IDs:** Automatically classifies discovered hosts into standardized roles (*CCTV / IP Camera, Router / Gateway, Network Switch, Network Printer, MQTT Broker / IoT Hub, Server / Storage (NAS), Generic IoT*) with deterministic asset UUIDs for longitudinal tracking.
- **Modular Vulnerability Rules Engine:** Fully testable, deterministic rule system with verified evidence requirements, confidence metrics, and explicit verification taxonomies (*Confirmed Technical Finding, Potential Security Risk, Needs Administrative Verification, Informational Observation*).
- **Explainable Mathematical Risk Scoring:** Transparent, documented scoring model evaluating Base Severity, Confidence, Verification Status, Asset Criticality, and Exposure Context with step-by-step mathematical breakdowns (explicitly distinct from official CVSS scores).
- **Scan Snapshot Differential Engine:** Identifies scan-to-scan deltas: newly discovered devices, disappeared devices, opened/closed ports, new/resolved findings, and score shifts, with safeguards against treating partial/timed-out scans as false resolutions.
- **Network Zone & Policy Deviation Topology:** Groups assets into campus zones (*Surveillance Zone, Management Network, Core Campus LAN, Lab Sandbox, Guest IoT*) and flags policy violations.
- **Enterprise Reporting Suite:** One-click generation of **Executive PDF reports** (with ReportLab, including scope statements, tables, and watermarks), **Tabular CSV spreadsheets**, and **Structured JSON files** for SIEM integration.
- **100% Offline Demo Mode:** Pre-loaded with realistic firmware profiles (Dahua IP Camera, TP-Link OpenWrt Router, ESP32 FreeRTOS sensor, Synology NAS) allowing full evaluation without physical hardware or live Nmap setups.

---

## 🛠️ Free Technology Stack

| Layer | Component | License / Cost | Purpose |
| :--- | :--- | :--- | :--- |
| **Core Backend** | Python 3.9+ | Open Source (PSF) | Modular rule evaluation, XML parsing, scoring algorithms |
| **Web Dashboard** | Streamlit | Apache 2.0 (Free) | Reactive dark cybersecurity dashboard across 9 pages |
| **Port / Network Engine** | Nmap | Free / Open Source | Non-destructive TCP connect scanning and banner extraction |
| **Relational Database** | SQLite 3 | Public Domain (Free) | Embedded serverless database for scans, assets, audit trails |
| **Data Processing** | Pandas | BSD-3 (Free) | Tabular analytics, inventory filtering, differential matching |
| **Executive PDF Reporting** | ReportLab | BSD (Free) | Professional security audit PDF compiler |
| **Data Export** | `csv` & `json` | Built-in (Free) | Standard tabular and machine-readable security exports |
| **Vulnerability Data** | Official NIST NVD API v2.0 | Public Domain (Free) | Optional CVE reference lookup (with local cache & offline fallback) |
| **Automated Testing** | `unittest` / `pytest` | Built-in / MIT (Free) | Synthetic offline regression and validation test suite |

---

## 📁 System Architecture & Directory Layout

```text
iot-sentinel-pro/
├── app.py                      # Streamlit Cyber Defense Dashboard (9 comprehensive pages)
├── modules/
│   ├── discovery.py            # Subnet sweep, host detection, and classification
│   ├── port_scanner.py         # Safe TCP connect scanner & Nmap XML parser
│   ├── device_classifier.py    # Hardware role classifier & stable asset ID generator
│   ├── cctv_assessor.py        # Dedicated CCTV & IP camera assessment module
│   ├── vulnerability_engine.py # Modular IoT vulnerability rules registry & evaluators
│   ├── cve_lookup.py           # Free NIST NVD CVE API integration with local cache
│   ├── risk_scoring.py         # Explainable 0-100 device risk score & posture grading
│   ├── scan_comparator.py      # Snapshot differential engine (asset & finding deltas)
│   ├── network_visualizer.py   # Logical zone topology & policy deviation analyzer
│   └── report_generator.py     # Executive PDF (ReportLab), CSV, and JSON report generator
├── database/
│   └── db_manager.py           # SQLite database schema, asset profiles, and audit log
├── utils/
│   ├── validators.py           # Strict RFC 1918 private IPv4 validation & injection sanitization
│   └── config.py               # IoT port dictionary, severity tiers, and Nmap path finder
├── data/                       # Local SQLite database directory (data/iot_scanner.db)
├── reports/                    # Generated audit PDF, CSV, and JSON reports
├── tests/
│   ├── test_validators.py      # Scope, private IPv4, and injection unit tests
│   ├── test_vulnerability_engine.py # Rules engine, CCTV assessor, and scoring tests
│   ├── test_database.py        # SQLite schema, CRUD, audit trail, and profile tests
│   └── test_reports.py         # PDF, CSV, JSON, comparator, and topology tests
├── requirements.txt            # Python dependencies (all free & open-source)
├── .env.example                # Free environment configuration template
├── .gitignore                  # Git exclusions for venv, cache, and DB files
├── README.md                   # Complete documentation, VMware guide, and viva Q&A
├── run_windows.bat             # One-click launcher for Windows 11
└── run_kali.sh                 # One-click launcher for Kali Linux (VMware)
```

---

## 🪟 Windows 11 Installation & Launch Guide

### Step 1: Install Python 3 (Free)
1. Download Python 3.10+ from the official website: [python.org/downloads](https://www.python.org/downloads/).
2. Run the installer.
3. ⚠️ **CRITICAL STEP:** On the very first setup screen, check the box:  
   ☑️ **"Add python.exe to PATH"**
4. Click **Install Now**.

### Step 2: Install Nmap (Free)
1. Download the free Windows installer: [nmap.org/download.html](https://nmap.org/download.html) (select `nmap-<version>-setup.exe`).
2. Run the installer with default settings (Npcap will be installed automatically).
3. *Note:* If Nmap is omitted, the scanner functions completely in **100% Offline Demo Mode**.

### Step 3: Launch with One Click
Double-click:
```cmd
run_windows.bat
```
The batch script will:
- Check for Python and Nmap.
- Create an isolated virtual environment (`.venv`).
- Install dependencies from `requirements.txt`.
- Open the application in your browser at `http://localhost:8501`.

---

## 🐉 Kali Linux (inside VMware) Installation Guide

### Step 1: Install System Packages
Open a terminal in your Kali Linux virtual machine:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap
```

### Step 2: Execute Launcher
```bash
cd ~/Desktop/AI\ PROJECT
chmod +x run_kali.sh
./run_kali.sh
```

### Step 3: VMware Networking Modes

| VMware Network Mode | Mechanism | Can it Scan Real IoT Hardware on WiFi? | When to Use |
| :--- | :--- | :--- | :--- |
| **Bridged Networking** | Kali VM receives its own distinct IP directly on your physical home WiFi router (e.g. `192.168.1.185`). | **YES ✅** | **Recommended for Live Audits** of physical IoT devices (cameras, ESP32, routers). |
| **NAT (Default)** | Kali VM shares Windows host IP through internal virtual NAT router (e.g. `192.168.128.x`). | **NO** (blocked by host NAT) | **Recommended for Demo Mode & Presentations.** Provides VM internet for NVD CVE lookup. |
| **Host-Only** | Completely private virtual switch between Windows and Kali. | **NO** | Air-gapped testing without any external connectivity. |

---

## 📹 Dedicated CCTV Security Assessment Pipeline

The dedicated CCTV audit module (`modules/cctv_assessor.py`) evaluates observable surveillance indicators:
1. **RTSP Stream Exposure (Port 554):** Flags unencrypted Real-Time Streaming Protocol feeds. Provides admin verification procedures to enforce Digest authentication and RTSPS (TLS).
2. **Web Administrative Console (Port 80/8080):** Confirms cleartext web management consoles lacking HTTPS encryption.
3. **Legacy Telnet Shells (Port 23):** Flags critical remote terminal exposure susceptible to Mirai, Persirai, and Reaper botnet variants.
4. **Proprietary Media Ports (Port 8000 / 37777):** Audits auxiliary surveillance management ports commonly used by Dahua and Hikvision VMS client tools.
5. **Legacy Server Banners:** Matches banners against known discontinued embedded web servers (e.g., Boa 0.94.14, CVE-2017-9833).

*Policy:* **Never opens live streams, never pulls video frames, never attempts credential guessing, and never modifies settings.**

---

## 🧮 Explainable Mathematical Risk Scoring

$$\text{Risk}_i = \text{BaseSeverity}_i \times \text{ConfidenceFactor}_i \times \text{VerificationFactor}_i$$

$$\text{RawRisk} = \sum_{i=1}^{N} \text{Risk}_i$$

$$\text{FinalScore} = \min\left(100.0, \text{round}\left(\text{RawRisk} \times \text{AssetCriticality} \times \text{ExposureContext}, 1\right)\right)$$

### Factor Multipliers:
- **Base Severity:** Critical = 25, High = 15, Medium = 8, Low = 3, Info = 1
- **Confidence:** High = 1.00, Medium = 0.75, Low = 0.50
- **Verification Status:** Confirmed = 1.00, Potential Risk = 0.85, Needs Verification = 0.65, Informational = 0.40
- **Asset Criticality:** Critical = 1.30, High = 1.15, Medium = 1.00, Low = 0.85
- **Exposure Context:** 1.10x compounding penalty if multiple unencrypted management protocols (Telnet, FTP, HTTP) coexist.

*Disclaimer:* This metric represents an architectural defensive assessment score and is explicitly separate from official NIST CVSS v3.1 base metrics.

---

## 🧪 Automated Testing & Verification

Run the test suite offline without scanning live networks or requiring physical hardware:

```bash
# Using Python unittest
python -m unittest discover tests -v

# Or using pytest
pytest tests/ -v
```

### Coverage Overview:
- `test_validators.py`: RFC 1918 private IPv4 validation, public IP rejection (e.g. 8.8.8.8), subnet prefix constraints (/24 maximum), command injection sanitization.
- `test_vulnerability_engine.py`: Modular rules engine evaluation, CCTV assessor, device classifier heuristics, profile deviation checks, and explainable risk scoring math.
- `test_database.py`: SQLite schema, CRUD operations, cascading deletes, audit log persistence, and asset profile configuration.
- `test_reports.py`: PDF report compilation (ReportLab `%PDF-` verification and watermark check), CSV export, JSON export schema, scan snapshot comparison deltas, and offline CVE fallback.

---

## 🎓 College Viva / Project Defense Q&A

**Q1: Why is a dedicated IoT scanner needed when tools like Nmap exist?**  
*Answer:* Nmap is an underlying port and network discovery utility. IoT Sentinel Pro provides an entire application architecture: specialized IoT rule-based evaluation, automated hardware classification, CCTV-specific vulnerability checks, explainable risk scoring, scan-to-scan differential tracking, network zone compliance auditing, and executive PDF/CSV/JSON report generation.

**Q2: How does the tool prevent damage to fragile IoT endpoints?**  
*Answer:* Low-power microcontrollers (e.g., ESP32, embedded camera SoCs) can crash when fuzzed or hit with aggressive SYN floods. IoT Sentinel Pro enforces safe TCP connect probes (`-sT`), light version discovery (`--version-light`), and conservative timeouts without brute-forcing or intrusive payloads.

**Q3: How do you verify that the application operates offline?**  
*Answer:* All core detection heuristics, asset classification, SQLite database operations, PDF/CSV/JSON reporting, and Demo Mode profiles run 100% locally. The NIST NVD lookup operates with strict timeouts, local database caching, and graceful offline fallback.
=======
# iot-sentinel-pro-x
IoT Sentinel Pro X - IoT Device Vulnerability Scanner
>>>>>>> 7be878a5d93346f3db9f038a4f72c7e3380028cb
