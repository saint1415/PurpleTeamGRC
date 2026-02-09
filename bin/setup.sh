#!/usr/bin/env bash
# ============================================================
# Purple Team Platform v7.0 - Linux/macOS Setup
# Creates venv and installs dependencies.
# Mirror of setup-windows.bat for Unix systems.
# ============================================================

set -e

# Resolve PURPLE_TEAM_HOME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PURPLE_TEAM_HOME="$(dirname "$SCRIPT_DIR")"

echo ""
echo "  ============================================================"
echo "   Purple Team Platform v7.0 - Setup"
echo "  ============================================================"
echo ""
echo "  Installation directory: $PURPLE_TEAM_HOME"
echo ""

# --- Find Python ---
PYTHON_CMD=""

if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    # Verify it's Python 3
    if python -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" 2>/dev/null; then
        PYTHON_CMD="python"
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "  [ERROR] Python 3 not found."
    echo ""
    if [ "$(uname)" = "Darwin" ]; then
        echo "  Install Python 3 via Homebrew:"
        echo "    brew install python@3.11"
    else
        echo "  Install Python 3 for your distribution:"
        echo "    Ubuntu/Debian/Kali: sudo apt install python3 python3-venv python3-pip"
        echo "    Fedora/RHEL:        sudo dnf install python3 python3-pip"
        echo "    Arch:               sudo pacman -S python python-pip"
    fi
    echo ""
    exit 1
fi

# --- Check Python version ---
PY_VERSION=$($PYTHON_CMD --version 2>&1)
echo "  [*] Found Python: $PYTHON_CMD"
echo "  [*] Version: $PY_VERSION"

if ! $PYTHON_CMD -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
    echo ""
    echo "  [ERROR] Python 3.10 or later is required."
    echo "  Current version: $PY_VERSION"
    echo ""
    exit 1
fi

echo "  [OK] Python version is 3.10+"
echo ""

# --- Check for venv module ---
if ! $PYTHON_CMD -m venv --help &>/dev/null; then
    echo "  [ERROR] Python venv module not found."
    echo ""
    echo "  Install it:"
    echo "    Ubuntu/Debian/Kali: sudo apt install python3-venv"
    echo "    Fedora/RHEL:        sudo dnf install python3-virtualenv"
    echo ""
    exit 1
fi

# --- Check for requirements.txt ---
SKIP_INSTALL=0
if [ ! -f "$PURPLE_TEAM_HOME/requirements.txt" ]; then
    echo "  [WARNING] requirements.txt not found."
    echo "  Continuing with venv creation only..."
    echo ""
    SKIP_INSTALL=1
fi

# --- Create virtual environment ---
VENV_DIR="$PURPLE_TEAM_HOME/venv"

if [ -f "$VENV_DIR/bin/python3" ] || [ -f "$VENV_DIR/bin/python" ]; then
    echo "  [*] Virtual environment already exists at:"
    echo "    $VENV_DIR"
    echo ""
    read -p "  Recreate venv? (y/N): " RECREATE
    if [[ "$RECREATE" =~ ^[Yy] ]]; then
        echo "  [*] Removing existing venv..."
        rm -rf "$VENV_DIR"
        echo "  [*] Creating new virtual environment..."
        $PYTHON_CMD -m venv "$VENV_DIR"
        echo "  [OK] Virtual environment created."
    else
        echo "  [*] Keeping existing venv."
    fi
else
    echo "  [*] Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "  [ERROR] Failed to create virtual environment."
        exit 1
    fi
    echo "  [OK] Virtual environment created at:"
    echo "    $VENV_DIR"
fi

echo ""

# --- Determine venv Python and pip ---
if [ -f "$VENV_DIR/bin/python3" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python3"
elif [ -f "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
fi
VENV_PIP="$VENV_DIR/bin/pip"

# --- Install requirements ---
if [ "$SKIP_INSTALL" -eq 0 ]; then
    echo "  [*] Upgrading pip..."
    "$VENV_PYTHON" -m pip install --upgrade pip -q
    echo "  [OK] pip upgraded."
    echo ""

    echo "  [*] Installing requirements..."
    echo "    Source: $PURPLE_TEAM_HOME/requirements.txt"
    echo ""

    if "$VENV_PIP" install -r "$PURPLE_TEAM_HOME/requirements.txt"; then
        echo ""
        echo "  [OK] All requirements installed successfully."
    else
        echo ""
        echo "  [WARNING] Some packages failed to install."
        echo "  You may need development headers:"
        echo "    Ubuntu/Debian: sudo apt install python3-dev build-essential"
        echo "    Fedora/RHEL:   sudo dnf install python3-devel gcc"
        echo ""
        echo "  The platform may still work with reduced functionality."
    fi
fi

echo ""

# --- Create data directories ---
echo "  [*] Ensuring data directories exist..."
mkdir -p "$PURPLE_TEAM_HOME/data/results"
mkdir -p "$PURPLE_TEAM_HOME/data/evidence"
mkdir -p "$PURPLE_TEAM_HOME/data/reports"
mkdir -p "$PURPLE_TEAM_HOME/data/logs"
echo "  [OK] Data directories ready."
echo ""

# --- Verify installation ---
echo "  ============================================================"
echo "   Verification"
echo "  ============================================================"
echo ""

echo "  [*] Checking Python in venv..."
"$VENV_PYTHON" --version
echo ""

echo "  [*] Checking core imports..."
"$VENV_PYTHON" -c "
import sys
sys.path.insert(0, '$PURPLE_TEAM_HOME/lib')
from paths import paths
from config import config
print('  [OK] Core modules load successfully')
print(f'  [OK] Platform home: {paths.home}')
" 2>/dev/null || echo "  [WARNING] Some imports may not be available."

echo ""

# --- Platform detection ---
echo "  [*] Detecting deployment mode..."
"$VENV_PYTHON" -c "
import sys
sys.path.insert(0, '$PURPLE_TEAM_HOME/lib')
from platform_detect import get_platform_info
pi = get_platform_info()
print(f'  [OK] OS: {pi.os_name}')
print(f'  [OK] Mode: {pi.deployment_mode}')
print(f'  [OK] Admin: {pi.is_admin}')
" 2>/dev/null || true

echo ""
echo "  ============================================================"
echo "   Setup Complete"
echo "  ============================================================"
echo ""
echo "  To launch the platform:"
echo "    python3 $PURPLE_TEAM_HOME/bin/purple-launcher"
echo ""
echo "  Or use the bash wrapper:"
echo "    $PURPLE_TEAM_HOME/bin/purple-team"
echo ""
echo "  Quick scan:"
echo "    python3 $PURPLE_TEAM_HOME/bin/purple-launcher quick"
echo ""
echo "  ============================================================"
echo ""
