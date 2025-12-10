#!/bin/bash
# engine.sh - Simple Security Hardening Engine
# Discovers and runs all security modules

set -euo pipefail

# Get engine directory
ENGINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ENGINE_DIR

AUTHORIZED_USERS=()
ADMIN_USERS=()

# Load utilities
source "$ENGINE_DIR/lib/utils.sh"

# Require root
require_root

# Check system compatibility
check_system() {
    log_section "System Check"

    local os=$(detect_os)
    local version=$(detect_os_version)

    log_info "Operating System: $os"
    log_info "OS Version: $version"

    if ! is_supported_os; then
        log_warn "This OS may not be fully supported"
        log_warn "Supported: Linux Mint 21.x, Ubuntu 24.x"
    else
        log_success "OS is supported"
    fi
}

# Banner
echo "======================================"
echo " Security Hardening Engine"
echo " OS: $(detect_os) $(detect_os_version)"
echo "======================================"
echo ""

# Check system
check_system
echo ""

# Discover all modules
MODULES=()
while IFS= read -r module_path; do
    module_name="$(basename "$module_path" .sh)"
    MODULES+=("$module_name")
done < <(find "$ENGINE_DIR/modules" -maxdepth 1 -type f -name '*.sh' -print | sort)

echo "Found ${#MODULES[@]} modules to run"
echo ""

# Source all modules
for module in "${MODULES[@]}"; do
    module_file="$ENGINE_DIR/modules/${module}.sh"
    log_debug "Sourcing $module..."
    source "$module_file"
done

# Run all modules
for module in "${MODULES[@]}"; do
    runner_function="run_${module}"

    if declare -f "$runner_function" >/dev/null; then
        log_section "Running Module: $module"

        if $runner_function; then
            log_success "Module $module completed successfully"
        else
            log_error "Module $module failed with exit code $?"
        fi

        echo ""
    else
        log_warn "No runner function found for $module (expected: $runner_function)"
    fi
done

log_success "All modules completed!"
echo ""
echo "Check the log file at: $LOG_FILE"