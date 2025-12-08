#!/bin/bash
# unwanted_software.sh - Unwanted Software Removal

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Unwanted Software Removal
# Category: Software Management
# Description: Unwanted Software Removal

remove_unauthorized_software() {
  log_action "=== REMOVING UNAUTHORIZED SOFTWARE ==="

  local BLACKLIST_FILE="${1:-}"

  # If no file provided, skip this function
  if [[ -z "$BLACKLIST_FILE" ]]; then
    log_action "WARNING: No package blacklist file provided"
    log_action "Usage: remove_unauthorized_software <blacklist_file>"
    log_action "Skipping software removal..."
    return 0
  fi

  # Check if file exists
  if [[ ! -f "$BLACKLIST_FILE" ]]; then
    log_action "ERROR: Package blacklist file not found: $BLACKLIST_FILE"
    return 1
  fi

  log_action "Reading prohibited packages from: $BLACKLIST_FILE"

  # Read packages from file (one per line, ignore comments and empty lines)
  local package_count=0
  local removed_count=0

  while IFS= read -r package || [[ -n "$package" ]]; do
    # Skip empty lines and comments
    [[ -z "$package" || "$package" =~ ^[[:space:]]*# ]] && continue

    # Clean up whitespace
    package=$(echo "$package" | xargs)
    [[ -z "$package" ]] && continue

    ((package_count++))

    # Check if package is installed
    if dpkg -l 2>/dev/null | grep -q "^ii  $package "; then
      log_action "Removing package: $package"
      if apt purge -y "$package" &>/dev/null; then
        ((removed_count++))
        log_action "Successfully removed: $package"
      else
        log_action "Failed to remove: $package"
      fi
    else
      log_action "Package $package not installed (skipping)"
    fi
  done <"$BLACKLIST_FILE"

  # Clean up dependencies
  log_action "Cleaning up orphaned dependencies..."
  apt autoremove -y &>/dev/null

  log_action "Processed $package_count packages, removed $removed_count"
}

# Implement another function for auditing installed packages?
# ^^ yes will be audited by AI

# Main runner
run_unwanted_software() {
    log_section "Starting Unwanted Software Removal"
    remove_unauthorized_software "$@"
    log_success "Unwanted Software Removal completed"
}

export -f run_unwanted_software
