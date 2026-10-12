#!/usr/bin/env bash
# ==============================================================================
# IoT Sentinel Pro — Campus Edition (Kali Linux VMware Launcher)
# Defensive IoT Security Auditor & Vulnerability Engine (100% Free & Open Source)
# ==============================================================================

set -e

# Terminal Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}===============================================================================${NC}"
echo -e "${CYAN}        IoT Sentinel Pro — Campus Edition (Kali Linux VMware Launcher)        ${NC}"
echo -e "${CYAN}               Defensive Cyber Audit & Risk Assessment Engine                  ${NC}"
echo -e "${CYAN}===============================================================================${NC}\n"

# 1. Check Python 3
echo -e "${CYAN}[*] Checking Python 3...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] ERROR: python3 is not installed.${NC}"
    echo -e "Run: ${YELLOW}sudo apt update && sudo apt install -y python3 python3-venv python3-pip${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Detected: $(python3 --version)${NC}"

# 2. Check Nmap
echo -e "${CYAN}[*] Checking Nmap...${NC}"
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}[i] Nmap is not installed. You can still use 100% Offline Demo Mode.${NC}"
    echo -e "${YELLOW}    To enable live network scans: sudo apt install -y nmap${NC}"
else
    echo -e "${GREEN}[✓] Detected: $(nmap --version | head -n 1)${NC}"
fi

# 3. Create Virtual Environment
if [ ! -d ".venv" ]; then
    echo -e "${CYAN}[*] Creating Python virtual environment in .venv...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}[✓] Virtual environment created.${NC}"
fi

# 4. Activate Virtual Environment
echo -e "${CYAN}[*] Activating virtual environment...${NC}"
source .venv/bin/activate
echo -e "${GREEN}[✓] Virtual environment active (.venv).${NC}"

# 5. Install Dependencies
echo -e "${CYAN}[*] Installing dependencies from requirements.txt...${NC}"
pip install --upgrade pip > /dev/null 2>&1 || true
pip install -r requirements.txt
echo -e "${GREEN}[✓] Dependencies installed.${NC}"

# 6. Ensure runtime directories exist
mkdir -p data reports

# 7. Detect IP Address for Host-to-VM Access
KALI_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo -e "\n${CYAN}===============================================================================${NC}"
echo -e "${GREEN}[*] Launching Streamlit Cyber Defense Dashboard!${NC}"
echo -e "    • Local VM Browser:   ${CYAN}http://localhost:8501${NC}"
echo -e "    • Host Windows Access: ${CYAN}http://${KALI_IP}:8501${NC}"
echo -e "    • Press ${YELLOW}Ctrl+C${NC} in this terminal to stop the server."
echo -e "${CYAN}===============================================================================${NC}\n"

streamlit run app.py --server.address=0.0.0.0 --server.port=8501
