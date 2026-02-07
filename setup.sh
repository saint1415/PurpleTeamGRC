#!/usr/bin/env bash
#
# Purple Team Portable - Setup Script
# Initializes the portable installation, creates venv, and validates tools.
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PURPLE_TEAM_HOME="$SCRIPT_DIR"

echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          PURPLE TEAM PORTABLE v4.0 SETUP                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}Installation directory: $PURPLE_TEAM_HOME${NC}"
echo ""

# Check Python
echo -e "${YELLOW}Checking Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    echo -e "${GREEN}✓${NC} $PYTHON_VERSION"
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.9+${NC}"
    exit 1
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$PURPLE_TEAM_HOME"/{bin,lib,scanners,utilities,config/{templates,active},data/{results,evidence,logs,reports,archives},docs,tools}
echo -e "${GREEN}✓${NC} Directories created"

# Create virtual environment
echo -e "${YELLOW}Creating virtual environment...${NC}"
if [ ! -d "$PURPLE_TEAM_HOME/venv" ]; then
    python3 -m venv "$PURPLE_TEAM_HOME/venv"
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${GREEN}✓${NC} Virtual environment exists"
fi

# Activate venv and install dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
source "$PURPLE_TEAM_HOME/venv/bin/activate"

pip install --quiet --upgrade pip

# Install required packages
pip install --quiet \
    pyyaml \
    requests \
    python-dateutil \
    colorama \
    tabulate \
    netifaces \
    psutil

echo -e "${GREEN}✓${NC} Python dependencies installed"

# Create default configuration
echo -e "${YELLOW}Creating default configuration...${NC}"
if [ ! -f "$PURPLE_TEAM_HOME/config/active/config.yaml" ]; then
    cat > "$PURPLE_TEAM_HOME/config/active/config.yaml" << 'EOF'
# Purple Team Portable Configuration
# 365-day retention for compliance

version: '4.0.0'

platform:
  name: Purple Team Portable
  mode: portable
  auto_detect_networks: true

scanning:
  stealth_level: 3
  delay_min_seconds: 30
  delay_max_seconds: 300
  concurrent_scans: 1
  timeout_minutes: 120
  excluded_hosts: []
  excluded_ports: []

scheduling:
  enabled: false
  window_start: '18:00'
  window_end: '20:00'
  randomize_start: true
  frequency: monthly
  day_of_month: 1
  run_until_complete: true

retention:
  days: 365
  compress_after_days: 30
  archive_format: tar.gz
  auto_cleanup: true

evidence:
  collect_screenshots: false
  hash_algorithm: sha256
  include_raw_output: true
  timestamp_format: '%Y-%m-%d %H:%M:%S UTC'

compliance:
  frameworks:
    - NIST-800-53
    - HIPAA
    - SOC1-Type2
    - SOC2-Type2
    - PCI-DSS-v4
    - ISO27001-2022
    - CMMC
    - FedRAMP
    - GDPR
    - SOX
  auto_map_findings: true
  generate_attestations: true
  include_remediation: true

reporting:
  formats:
    - json
    - html
    - csv
    - pdf
  executive_summary: true
  technical_details: true
  include_evidence_refs: true

export:
  oscal: true
  scap: false
  csv_grc: true
  json_api: true

network:
  auto_detect: true
  scan_ranges: []
  exclude_ranges:
    - 127.0.0.0/8
  dns_resolution: true

tools:
  nmap:
    enabled: true
    extra_args: ''
  nikto:
    enabled: true
    extra_args: ''
  nuclei:
    enabled: true
    extra_args: ''
    templates: default
  testssl:
    enabled: true
    extra_args: ''

notifications:
  enabled: false
  email:
    enabled: false
    smtp_server: ''
    smtp_port: 587
    use_tls: true
    recipients: []
  on_critical: true
  on_complete: true

integrations:
  thehive:
    enabled: false
    url: ''
    api_key: ''
  wazuh:
    enabled: false
    url: ''
    api_key: ''
  siem:
    enabled: false
    type: ''
    endpoint: ''
EOF
    echo -e "${GREEN}✓${NC} Default configuration created (365-day retention)"
else
    echo -e "${GREEN}✓${NC} Configuration exists"
fi

# Make scripts executable
echo -e "${YELLOW}Setting permissions...${NC}"
chmod +x "$PURPLE_TEAM_HOME/bin/"* 2>/dev/null || true
chmod +x "$PURPLE_TEAM_HOME/scanners/"*.py 2>/dev/null || true
chmod +x "$PURPLE_TEAM_HOME/utilities/"*.py 2>/dev/null || true
echo -e "${GREEN}✓${NC} Permissions set"

# Check for required tools
echo ""
echo -e "${YELLOW}Checking required security tools...${NC}"

MISSING_TOOLS=()
TOOL_LOCATIONS=()

# Check each tool
check_tool() {
    local tool=$1
    if command -v $tool &> /dev/null; then
        location=$(which $tool)
        echo -e "${GREEN}✓${NC} $tool: $location"
        return 0
    else
        echo -e "${RED}✗${NC} $tool: NOT FOUND"
        MISSING_TOOLS+=("$tool")
        return 1
    fi
}

check_tool nmap
check_tool nikto
check_tool nuclei
check_tool testssl.sh

# Function to install missing tools
install_tool() {
    local tool=$1
    echo ""

    case $tool in
        nmap)
            echo -e "${BLUE}Installing nmap...${NC}"
            if command -v apt &> /dev/null; then
                sudo apt update && sudo apt install -y nmap
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y nmap
            elif command -v pacman &> /dev/null; then
                sudo pacman -S --noconfirm nmap
            else
                echo -e "${RED}Could not detect package manager. Install nmap manually.${NC}"
                return 1
            fi
            ;;
        nikto)
            echo -e "${BLUE}Installing nikto...${NC}"
            if command -v apt &> /dev/null; then
                sudo apt update && sudo apt install -y nikto
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y nikto
            elif command -v pacman &> /dev/null; then
                sudo pacman -S --noconfirm nikto
            else
                echo -e "${RED}Could not detect package manager. Install nikto manually.${NC}"
                return 1
            fi
            ;;
        nuclei)
            echo -e "${BLUE}Installing nuclei...${NC}"
            # Check if go is available
            if command -v go &> /dev/null; then
                echo "Installing via Go..."
                go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
                # Add Go bin to path if needed
                if [ -d "$HOME/go/bin" ]; then
                    export PATH="$PATH:$HOME/go/bin"
                fi
            # Check if apt has nuclei (Kali)
            elif command -v apt &> /dev/null && apt-cache show nuclei &> /dev/null; then
                sudo apt update && sudo apt install -y nuclei
            else
                # Direct download
                echo "Downloading nuclei binary..."
                NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
                if [ -z "$NUCLEI_VERSION" ]; then
                    NUCLEI_VERSION="v3.2.4"
                fi
                ARCH=$(uname -m)
                case $ARCH in
                    x86_64) ARCH="amd64" ;;
                    aarch64) ARCH="arm64" ;;
                esac
                NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_${ARCH}.zip"

                mkdir -p "$PURPLE_TEAM_HOME/tools"
                cd "$PURPLE_TEAM_HOME/tools"
                curl -sL "$NUCLEI_URL" -o nuclei.zip
                unzip -o nuclei.zip nuclei
                rm nuclei.zip
                chmod +x nuclei

                # Create symlink or add to path
                if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
                    sudo ln -sf "$PURPLE_TEAM_HOME/tools/nuclei" /usr/local/bin/nuclei
                elif [ -d "$HOME/.local/bin" ]; then
                    ln -sf "$PURPLE_TEAM_HOME/tools/nuclei" "$HOME/.local/bin/nuclei"
                else
                    echo -e "${YELLOW}nuclei installed to $PURPLE_TEAM_HOME/tools/nuclei${NC}"
                    echo "Add to PATH or run: sudo ln -s $PURPLE_TEAM_HOME/tools/nuclei /usr/local/bin/nuclei"
                fi
                cd "$PURPLE_TEAM_HOME"
            fi
            # Update nuclei templates
            if command -v nuclei &> /dev/null || [ -x "$PURPLE_TEAM_HOME/tools/nuclei" ]; then
                echo "Updating nuclei templates..."
                nuclei -update-templates 2>/dev/null || "$PURPLE_TEAM_HOME/tools/nuclei" -update-templates 2>/dev/null || true
            fi
            ;;
        testssl.sh)
            echo -e "${BLUE}Installing testssl.sh...${NC}"
            # Check if apt has it (Kali)
            if command -v apt &> /dev/null && apt-cache show testssl.sh &> /dev/null; then
                sudo apt update && sudo apt install -y testssl.sh
            else
                # Clone from git
                mkdir -p "$PURPLE_TEAM_HOME/tools"
                if [ ! -d "$PURPLE_TEAM_HOME/tools/testssl.sh" ]; then
                    git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$PURPLE_TEAM_HOME/tools/testssl.sh"
                else
                    cd "$PURPLE_TEAM_HOME/tools/testssl.sh" && git pull
                    cd "$PURPLE_TEAM_HOME"
                fi
                chmod +x "$PURPLE_TEAM_HOME/tools/testssl.sh/testssl.sh"

                # Create symlink
                if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
                    sudo ln -sf "$PURPLE_TEAM_HOME/tools/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh
                elif [ -d "$HOME/.local/bin" ]; then
                    ln -sf "$PURPLE_TEAM_HOME/tools/testssl.sh/testssl.sh" "$HOME/.local/bin/testssl.sh"
                else
                    echo -e "${YELLOW}testssl.sh installed to $PURPLE_TEAM_HOME/tools/testssl.sh/testssl.sh${NC}"
                    echo "Add to PATH or run: sudo ln -s $PURPLE_TEAM_HOME/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh"
                fi
            fi
            ;;
    esac

    # Verify installation
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}✓${NC} $tool installed successfully"
        return 0
    elif [ -x "$PURPLE_TEAM_HOME/tools/$tool" ] || [ -x "$PURPLE_TEAM_HOME/tools/$tool/$tool" ]; then
        echo -e "${GREEN}✓${NC} $tool installed to tools directory"
        return 0
    else
        echo -e "${RED}✗${NC} $tool installation may have failed - please verify"
        return 1
    fi
}

# If tools are missing, offer to install
if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Missing tools: ${MISSING_TOOLS[*]}${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Options:"
    echo "  1) Install all missing tools automatically"
    echo "  2) Choose which tools to install"
    echo "  3) Skip - I'll install them manually later"
    echo ""
    read -p "Select option [1]: " INSTALL_CHOICE
    INSTALL_CHOICE=${INSTALL_CHOICE:-1}

    case $INSTALL_CHOICE in
        1)
            echo ""
            echo -e "${BLUE}Installing all missing tools...${NC}"
            for tool in "${MISSING_TOOLS[@]}"; do
                install_tool "$tool"
            done
            ;;
        2)
            for tool in "${MISSING_TOOLS[@]}"; do
                echo ""
                read -p "Install $tool? (y/n) [y]: " INSTALL_THIS
                INSTALL_THIS=${INSTALL_THIS:-y}
                if [[ "$INSTALL_THIS" =~ ^[Yy] ]]; then
                    install_tool "$tool"
                fi
            done
            ;;
        3)
            echo ""
            echo -e "${YELLOW}Skipping tool installation. Manual installation instructions:${NC}"
            echo ""
            for tool in "${MISSING_TOOLS[@]}"; do
                case $tool in
                    nmap)
                        echo "  nmap:      sudo apt install nmap"
                        ;;
                    nikto)
                        echo "  nikto:     sudo apt install nikto"
                        ;;
                    nuclei)
                        echo "  nuclei:    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                        echo "             or: sudo apt install nuclei (Kali)"
                        echo "             or: https://github.com/projectdiscovery/nuclei/releases"
                        ;;
                    testssl.sh)
                        echo "  testssl:   sudo apt install testssl.sh (Kali)"
                        echo "             or: git clone https://github.com/drwetter/testssl.sh.git"
                        ;;
                esac
            done
            echo ""
            ;;
    esac

    # Re-check tools after installation
    echo ""
    echo -e "${YELLOW}Verifying tools...${NC}"
    FINAL_MISSING=()
    for tool in nmap nikto nuclei testssl.sh; do
        if command -v $tool &> /dev/null; then
            echo -e "${GREEN}✓${NC} $tool: $(which $tool)"
        elif [ -x "$PURPLE_TEAM_HOME/tools/$tool" ]; then
            echo -e "${GREEN}✓${NC} $tool: $PURPLE_TEAM_HOME/tools/$tool"
        elif [ -x "$PURPLE_TEAM_HOME/tools/testssl.sh/testssl.sh" ] && [ "$tool" = "testssl.sh" ]; then
            echo -e "${GREEN}✓${NC} $tool: $PURPLE_TEAM_HOME/tools/testssl.sh/testssl.sh"
        else
            echo -e "${RED}✗${NC} $tool: NOT AVAILABLE"
            FINAL_MISSING+=("$tool")
        fi
    done

    if [ ${#FINAL_MISSING[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Warning: Some tools still missing: ${FINAL_MISSING[*]}${NC}"
        echo "Scans requiring these tools will be skipped."
    fi
fi

# Initialize evidence database
echo ""
echo -e "${YELLOW}Initializing evidence database...${NC}"
"$PURPLE_TEAM_HOME/venv/bin/python3" -c "
import sys
sys.path.insert(0, '$PURPLE_TEAM_HOME/lib')
from evidence import get_evidence_manager
em = get_evidence_manager()
print('Evidence database initialized')
" 2>/dev/null || echo "Will initialize on first use"
echo -e "${GREEN}✓${NC} Database ready"

# Create requirements.txt
cat > "$PURPLE_TEAM_HOME/requirements.txt" << 'EOF'
pyyaml>=6.0
requests>=2.28.0
python-dateutil>=2.8.0
colorama>=0.4.0
tabulate>=0.9.0
netifaces>=0.11.0
psutil>=5.9.0
EOF

# Summary
echo ""
echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "To get started:"
echo ""
echo "  1. Run the launcher:"
echo -e "     ${CYAN}$PURPLE_TEAM_HOME/bin/purple-team${NC}"
echo ""
echo "  2. Or set up scheduled scans:"
echo -e "     ${CYAN}$PURPLE_TEAM_HOME/bin/purple-team schedule${NC}"
echo ""
echo "  3. Or run a quick scan:"
echo -e "     ${CYAN}$PURPLE_TEAM_HOME/bin/purple-team quick${NC}"
echo ""
echo "Configuration: $PURPLE_TEAM_HOME/config/active/config.yaml"
echo "Results: $PURPLE_TEAM_HOME/data/results/"
echo "Reports: $PURPLE_TEAM_HOME/data/reports/"
echo ""
