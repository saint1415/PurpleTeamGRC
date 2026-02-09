#!/usr/bin/env bash
# ============================================================
# Purple Team Platform v7.0 - Install from USB to Local System
# Copies the platform from USB/portable media to a fixed location.
# Works on Linux and macOS.
# ============================================================

set -e

# Resolve source directory (where we're running from)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "  ============================================================"
echo "   Purple Team Platform v7.0 - Local Installation"
echo "  ============================================================"
echo ""
echo "  Source: $SOURCE_DIR"
echo ""

# --- Determine default install path ---
if [ "$(id -u)" -eq 0 ]; then
    DEFAULT_TARGET="/opt/purple-team"
else
    DEFAULT_TARGET="$HOME/PurpleTeamGRC"
fi

# --- Ask for install location ---
read -p "  Install location [$DEFAULT_TARGET]: " TARGET_DIR
TARGET_DIR="${TARGET_DIR:-$DEFAULT_TARGET}"

# Expand ~ if used
TARGET_DIR="${TARGET_DIR/#\~/$HOME}"

echo ""
echo "  Will install to: $TARGET_DIR"
echo ""

# --- Check if target exists ---
if [ -d "$TARGET_DIR" ]; then
    echo "  [WARNING] Directory already exists: $TARGET_DIR"
    echo ""
    echo "    1) Overwrite (replace existing files)"
    echo "    2) Cancel"
    echo ""
    read -p "  Select [2]: " OVERWRITE_CHOICE
    OVERWRITE_CHOICE="${OVERWRITE_CHOICE:-2}"

    if [ "$OVERWRITE_CHOICE" != "1" ]; then
        echo "  Installation cancelled."
        exit 0
    fi
    echo ""
fi

# --- Check if source and target are the same ---
SOURCE_REAL="$(cd "$SOURCE_DIR" && pwd -P)"
if [ -d "$TARGET_DIR" ]; then
    TARGET_REAL="$(cd "$TARGET_DIR" && pwd -P)"
    if [ "$SOURCE_REAL" = "$TARGET_REAL" ]; then
        echo "  [ERROR] Source and target are the same directory."
        echo "  Cannot install over the running copy."
        exit 1
    fi
fi

# --- Copy files ---
echo "  [*] Creating target directory..."
mkdir -p "$TARGET_DIR"

echo "  [*] Copying platform files..."
echo ""

# Use rsync if available (better progress, exclude support)
if command -v rsync &>/dev/null; then
    rsync -a --info=progress2 \
        --exclude='.git' \
        --exclude='venv' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='data/evidence/*' \
        --exclude='data/results/*' \
        --exclude='data/reports/*' \
        --exclude='data/logs/*' \
        "$SOURCE_DIR/" "$TARGET_DIR/"
else
    # Fallback to cp with manual exclusions
    # First copy everything
    cp -r "$SOURCE_DIR/"* "$TARGET_DIR/" 2>/dev/null || true
    cp "$SOURCE_DIR/.gitignore" "$TARGET_DIR/" 2>/dev/null || true

    # Remove what shouldn't be there
    rm -rf "$TARGET_DIR/.git" 2>/dev/null || true
    rm -rf "$TARGET_DIR/venv" 2>/dev/null || true
    find "$TARGET_DIR" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
    find "$TARGET_DIR" -name '*.pyc' -delete 2>/dev/null || true

    # Clean data directories (keep structure, remove contents)
    for subdir in evidence results reports logs; do
        rm -rf "$TARGET_DIR/data/$subdir/"* 2>/dev/null || true
    done
fi

echo ""
echo "  [OK] Files copied."
echo ""

# --- Create data directories ---
echo "  [*] Ensuring data directories exist..."
mkdir -p "$TARGET_DIR/data/results"
mkdir -p "$TARGET_DIR/data/evidence"
mkdir -p "$TARGET_DIR/data/reports"
mkdir -p "$TARGET_DIR/data/logs"
echo "  [OK] Data directories ready."
echo ""

# --- Make scripts executable ---
chmod +x "$TARGET_DIR/bin/purple-launcher" 2>/dev/null || true
chmod +x "$TARGET_DIR/bin/purple-team" 2>/dev/null || true
chmod +x "$TARGET_DIR/bin/setup.sh" 2>/dev/null || true
chmod +x "$TARGET_DIR/bin/install.sh" 2>/dev/null || true
chmod +x "$TARGET_DIR/bin/run-scheduled-scan.sh" 2>/dev/null || true

# --- Run setup ---
echo "  [*] Running setup to create venv and install dependencies..."
echo ""

bash "$TARGET_DIR/bin/setup.sh"

SETUP_EXIT=$?
if [ $SETUP_EXIT -ne 0 ]; then
    echo ""
    echo "  [WARNING] Setup encountered issues. You may need to run it manually:"
    echo "    bash $TARGET_DIR/bin/setup.sh"
    echo ""
fi

# --- Offer to create symlink ---
echo ""
echo "  ============================================================"
echo "   Installation Complete"
echo "  ============================================================"
echo ""
echo "  Installed to: $TARGET_DIR"
echo ""
echo "  Launch with:"
echo "    python3 $TARGET_DIR/bin/purple-launcher"
echo ""
echo "  Or:"
echo "    $TARGET_DIR/bin/purple-team"
echo ""

# Offer symlink if we can write to /usr/local/bin
SYMLINK_DIR="/usr/local/bin"
if [ -w "$SYMLINK_DIR" ] || [ "$(id -u)" -eq 0 ]; then
    read -p "  Create symlink at $SYMLINK_DIR/purple-team? (Y/n): " CREATE_LINK
    CREATE_LINK="${CREATE_LINK:-y}"
    if [[ "$CREATE_LINK" =~ ^[Yy] ]]; then
        ln -sf "$TARGET_DIR/bin/purple-team" "$SYMLINK_DIR/purple-team"
        ln -sf "$TARGET_DIR/bin/purple-launcher" "$SYMLINK_DIR/purple-launcher"
        echo "  [OK] Symlinks created. You can now run:"
        echo "    purple-team"
        echo "    purple-launcher"
    fi
else
    echo "  To add to PATH, run:"
    echo "    echo 'export PATH=\"$TARGET_DIR/bin:\$PATH\"' >> ~/.bashrc"
    echo "    source ~/.bashrc"
fi

echo ""
echo "  The platform will detect 'installed' mode (full features enabled)."
echo "  USB data (evidence, reports) was NOT copied -- start fresh."
echo ""
echo "  ============================================================"
echo ""
