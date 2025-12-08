#!/bin/bash
# utils.sh - Utility functions for CyberPatriot Linux hardening

[[ -n "${UTILS_SH_LOADED:-}" ]] && return 0
readonly UTILS_SH_LOADED=1

# Color codes
readonly COLOR_RESET='\033[0m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_BOLD='\033[1m'

# Log levels
readonly LOG_DEBUG=0
readonly LOG_INFO=1
readonly LOG_WARN=2
readonly LOG_ERROR=3
readonly LOG_SUCCESS=4

# Global log level
LOG_LEVEL=${LOG_LEVEL:-$LOG_INFO}

# Set up log file
if [ -n "$SUDO_USER" ]; then
  ACTUAL_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  ACTUAL_USER_HOME="$HOME"
fi
LOG_FILE="${LOG_FILE:-$ACTUAL_USER_HOME/Desktop/hardening.log}"

# Logging functions
log_debug() {
    [[ $LOG_LEVEL -le $LOG_DEBUG ]] && echo -e "${COLOR_CYAN}[DEBUG]${COLOR_RESET} $*" >&2
}

log_info() {
    [[ $LOG_LEVEL -le $LOG_INFO ]] && echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*" >&2
}

log_warn() {
    [[ $LOG_LEVEL -le $LOG_WARN ]] && echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*" >&2
}

log_error() {
    [[ $LOG_LEVEL -le $LOG_ERROR ]] && echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
}

log_success() {
    [[ $LOG_LEVEL -le $LOG_SUCCESS ]] && echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $*" >&2
}

log_section() {
    echo -e "\n${COLOR_BOLD}${COLOR_MAGENTA}==== $* ====${COLOR_RESET}\n" >&2
}

log_action() {
  local timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"
  local message="$timestamp $*"
  echo "$message"
  echo "$message" >>"$LOG_FILE" 2>/dev/null
}

# Helper functions
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

backup_file() {
  if [ -f "$1" ]; then
    cp "$1" "$1.bak.$(date +%s)"
    log_action "Backed up $1"
  fi
}

get_timestamp() {
    date +%Y-%m-%d_%H:%M:%S
}

# Export functions
export -f log_debug log_info log_warn log_error log_success log_section log_action
export -f require_root command_exists backup_file get_timestamp
