#!/bin/bash

[[ -n "${UTILS_SH_LOADED:-}" ]] && return 0
readonly UTILS_SH_LOADED=1

readonly COLOR_RESET='\033[0m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_BOLD='\033[1m'

readonly LOG_DEBUG=0
readonly LOG_INFO=1
readonly LOG_WARN=2
readonly LOG_ERROR=3
readonly LOG_SUCCESS=4

LOG_LEVEL=${LOG_LEVEL:-$LOG_INFO}

if [ -n "$SUDO_USER" ]; then
  ACTUAL_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  ACTUAL_USER_HOME="$HOME"
fi
LOG_FILE="${LOG_FILE:-$ACTUAL_USER_HOME/Desktop/hardening.log}"

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

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

check_dependencies() {
    local missing=()

    for cmd in "$@"; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_info "Install them with: sudo apt-get install ${missing[*]}"
        return 1
    fi

    return 0
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

detect_os_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$VERSION_ID"
    else
        echo "unknown"
    fi
}

is_supported_os() {
    local os=$(detect_os)
    local version=$(detect_os_version)

    if [[ "$os" == "linuxmint" && "$version" == "21"* ]]; then
        return 0
    elif [[ "$os" == "ubuntu" && "$version" == "24."* ]]; then
        return 0
    else
        return 1
    fi
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

export -f log_debug log_info log_warn log_error log_success log_section log_action
export -f require_root command_exists check_dependencies
export -f detect_os detect_os_version is_supported_os
export -f backup_file get_timestamp
