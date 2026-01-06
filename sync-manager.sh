#!/bin/bash
#
# Purple Team GRC Platform v3.0 - Sync Manager
# Synchronizes files between system (/opt/purple-team) and user (~/purple-team) installations
#
# Usage:
#   sync-manager.sh [--check|--force|--verbose|--initial]
#
# Options:
#   --check     Check sync status without making changes
#   --force     Force sync even if timestamps match
#   --verbose   Show detailed output
#   --initial   Initial sync (copy everything from /opt to ~)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SYSTEM_DIR="/opt/purple-team"
USER_DIR="$HOME/purple-team"
USER_CONFIG_DIR="$HOME/.purple-team"
LOG_FILE="$USER_CONFIG_DIR/logs/sync.log"

# Flags
CHECK_ONLY=false
FORCE_SYNC=false
VERBOSE=false
INITIAL_SYNC=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --force)
            FORCE_SYNC=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --initial)
            INITIAL_SYNC=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--check|--force|--verbose|--initial]"
            exit 1
            ;;
    esac
done

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    if [ "$VERBOSE" = true ] || [ "$level" = "ERROR" ] || [ "$level" = "WARN" ]; then
        case $level in
            ERROR)
                echo -e "${RED}[ERROR]${NC} $message"
                ;;
            WARN)
                echo -e "${YELLOW}[WARN]${NC} $message"
                ;;
            INFO)
                echo -e "${GREEN}[INFO]${NC} $message"
                ;;
            *)
                echo "[INFO] $message"
                ;;
        esac
    fi
}

# Check if system installation exists
check_system_installation() {
    if [ ! -d "$SYSTEM_DIR" ]; then
        log ERROR "System installation not found: $SYSTEM_DIR"
        return 1
    fi
    
    if [ ! -d "$SYSTEM_DIR/scanners" ]; then
        log ERROR "System installation incomplete (missing scanners directory)"
        return 1
    fi
    
    return 0
}

# Check if user installation exists
check_user_installation() {
    if [ ! -d "$USER_DIR" ]; then
        log INFO "User installation not found: $USER_DIR"
        return 1
    fi
    
    return 0
}

# Create user installation directory structure
create_user_dirs() {
    log INFO "Creating user directory structure..."
    
    mkdir -p "$USER_DIR"/{bin,config,scanners,utilities}
    mkdir -p "$USER_CONFIG_DIR"/{logs,results,evidence,reports}
    
    log INFO "User directories created"
}

# Initial sync from system to user
initial_sync() {
    log INFO "Starting initial sync from $SYSTEM_DIR to $USER_DIR"
    
    if ! check_system_installation; then
        log ERROR "Cannot perform initial sync: system installation invalid"
        exit 1
    fi
    
    create_user_dirs
    
    # Sync directories
    for dir in bin scanners utilities; do
        if [ -d "$SYSTEM_DIR/$dir" ]; then
            log INFO "Syncing $dir..."
            rsync -av --exclude='*.pyc' --exclude='__pycache__' \
                "$SYSTEM_DIR/$dir/" "$USER_DIR/$dir/" >> "$LOG_FILE" 2>&1
        fi
    done
    
    # Copy config templates (but don't overwrite user config)
    if [ -d "$SYSTEM_DIR/config/templates" ]; then
        mkdir -p "$USER_DIR/config/templates"
        rsync -av "$SYSTEM_DIR/config/templates/" "$USER_DIR/config/templates/" >> "$LOG_FILE" 2>&1
    fi
    
    log INFO "Initial sync complete"
}

# Check for differences between system and user installations
check_differences() {
    log INFO "Checking for differences between installations..."
    
    local differences=0
    
    # Check each directory
    for dir in bin scanners utilities; do
        if [ -d "$SYSTEM_DIR/$dir" ] && [ -d "$USER_DIR/$dir" ]; then
            # Find files in system that are newer than user
            while IFS= read -r file; do
                rel_path="${file#$SYSTEM_DIR/$dir/}"
                user_file="$USER_DIR/$dir/$rel_path"
                
                if [ ! -f "$user_file" ]; then
                    log WARN "File missing in user installation: $rel_path"
                    ((differences++))
                elif [ "$file" -nt "$user_file" ]; then
                    log WARN "File newer in system: $rel_path"
                    ((differences++))
                fi
            done < <(find "$SYSTEM_DIR/$dir" -type f -name '*.py' -o -name '*.sh')
            
            # Find files in user that don't exist in system
            while IFS= read -r file; do
                rel_path="${file#$USER_DIR/$dir/}"
                system_file="$SYSTEM_DIR/$dir/$rel_path"
                
                if [ ! -f "$system_file" ]; then
                    log WARN "File exists in user but not in system: $rel_path"
                    ((differences++))
                fi
            done < <(find "$USER_DIR/$dir" -type f -name '*.py' -o -name '*.sh' 2>/dev/null || true)
        fi
    done
    
    if [ $differences -eq 0 ]; then
        log INFO "No differences found - installations are in sync"
    else
        log WARN "Found $differences differences between installations"
    fi
    
    return $differences
}

# Sync from system to user
sync_to_user() {
    log INFO "Syncing from system to user installation..."
    
    local synced=0
    
    for dir in bin scanners utilities; do
        if [ -d "$SYSTEM_DIR/$dir" ]; then
            log INFO "Syncing $dir..."
            
            # Use rsync to sync only newer files
            if rsync -avu --exclude='*.pyc' --exclude='__pycache__' \
                "$SYSTEM_DIR/$dir/" "$USER_DIR/$dir/" >> "$LOG_FILE" 2>&1; then
                ((synced++))
            else
                log ERROR "Failed to sync $dir"
            fi
        fi
    done
    
    log INFO "Sync complete ($synced directories synced)"
}

# Main sync logic
perform_sync() {
    # Check if system installation exists
    if ! check_system_installation; then
        log ERROR "System installation not found or invalid"
        log INFO "Attempting to use user installation as primary"
        return 1
    fi
    
    # Check if user installation exists
    if ! check_user_installation; then
        log WARN "User installation not found"
        
        if [ "$CHECK_ONLY" = true ]; then
            log INFO "Would create user installation (check mode - no changes made)"
            return 0
        fi
        
        log INFO "Creating user installation..."
        initial_sync
        return 0
    fi
    
    # Check for differences
    if check_differences; then
        log INFO "Installations are in sync"
        
        if [ "$FORCE_SYNC" = true ] && [ "$CHECK_ONLY" = false ]; then
            log INFO "Force sync requested..."
            sync_to_user
        fi
    else
        if [ "$CHECK_ONLY" = true ]; then
            log INFO "Differences found (check mode - no changes made)"
            return 0
        fi
        
        log INFO "Syncing differences..."
        sync_to_user
    fi
}

# Display sync status
show_status() {
    echo ""
    echo -e "${BLUE}=== Purple Team Sync Manager Status ===${NC}"
    echo ""
    
    # System installation
    if check_system_installation 2>/dev/null; then
        echo -e "${GREEN}✓${NC} System Installation: $SYSTEM_DIR"
        if [ -d "$SYSTEM_DIR/scanners" ]; then
            local sys_count=$(find "$SYSTEM_DIR/scanners" -name '*.py' | wc -l)
            echo "  - Scanners: $sys_count scripts"
        fi
    else
        echo -e "${RED}✗${NC} System Installation: Not found or invalid"
    fi
    
    # User installation
    if check_user_installation 2>/dev/null; then
        echo -e "${GREEN}✓${NC} User Installation: $USER_DIR"
        if [ -d "$USER_DIR/scanners" ]; then
            local user_count=$(find "$USER_DIR/scanners" -name '*.py' | wc -l)
            echo "  - Scanners: $user_count scripts"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  User Installation: Not found"
    fi
    
    # User config
    if [ -d "$USER_CONFIG_DIR" ]; then
        echo -e "${GREEN}✓${NC} User Config: $USER_CONFIG_DIR"
        if [ -f "$USER_CONFIG_DIR/config.yaml" ]; then
            echo "  - Config file exists"
        else
            echo -e "  ${YELLOW}⚠${NC}  Config file missing"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  User Config: Not found"
    fi
    
    echo ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

log INFO "Sync manager started (check=$CHECK_ONLY, force=$FORCE_SYNC, verbose=$VERBOSE, initial=$INITIAL_SYNC)"

# Show status
show_status

# Perform initial sync if requested
if [ "$INITIAL_SYNC" = true ]; then
    initial_sync
    log INFO "Initial sync complete"
    exit 0
fi

# Perform sync
if [ "$CHECK_ONLY" = true ]; then
    echo -e "${BLUE}Running in check mode (no changes will be made)${NC}"
    echo ""
fi

perform_sync
sync_result=$?

# Summary
echo ""
if [ $sync_result -eq 0 ]; then
    echo -e "${GREEN}✓ Sync completed successfully${NC}"
else
    echo -e "${YELLOW}⚠ Sync completed with warnings${NC}"
    echo "  Check log file: $LOG_FILE"
fi

echo ""
echo "Log file: $LOG_FILE"
echo ""

exit $sync_result
