#!/bin/bash
# service_auditing.sh - Service Auditing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Service Auditing
# Category: Service Management
# Description: Service Auditing


disable_unnecessary_services() {
  log_action "=== DISABLING UNNECESSARY SERVICES ==="

  local BLACKLIST_FILE="${1:-}"

  # If no file provided, skip this function
  if [[ -z "$BLACKLIST_FILE" ]]; then
    log_action "WARNING: No service blacklist file provided"
    log_action "Usage: disable_unnecessary_services <blacklist_file>"
    log_action "Skipping service disabling..."
    return 0
  fi

  # Check if file exists
  if [[ ! -f "$BLACKLIST_FILE" ]]; then
    log_action "ERROR: Service blacklist file not found: $BLACKLIST_FILE"
    return 1
  fi

  log_action "Reading prohibited services from: $BLACKLIST_FILE"

  # Read services from file (one per line, ignore comments and empty lines)
  local service_count=0
  local disabled_count=0

  while IFS= read -r service || [[ -n "$service" ]]; do
    # Skip empty lines and comments
    [[ -z "$service" || "$service" =~ ^[[:space:]]*# ]] && continue

    # Clean up whitespace
    service=$(echo "$service" | xargs)
    [[ -z "$service" ]] && continue

    ((service_count++))

    # Check if service exists
    if systemctl list-unit-files | grep -q "^${service}.service"; then
      if systemctl is-active --quiet "$service"; then
        log_action "Stopping and disabling: $service"
        systemctl stop "$service" &>/dev/null
        systemctl disable "$service" &>/dev/null
        ((disabled_count++))
        log_action "Stopped and disabled: $service"
      elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
        log_action "Disabling: $service"
        systemctl disable "$service" &>/dev/null
        ((disabled_count++))
        log_action "Disabled: $service"
      else
        log_action "Service $service is already disabled"
      fi
    else
      log_action "Service $service not found on system (skipping)"
    fi
  done <"$BLACKLIST_FILE"

  log_action "Processed $service_count services, disabled $disabled_count"
}

audit_running_services() {
  log_action "=== AUDITING RUNNING SERVICES ==="

  systemctl list-units --type=service --state=running --no-pager | grep "loaded active running" | awk '{print $1}' | while read service; do
    log_action "RUNNING: $service"
  done

  log_action "Perform manual review of log for services that shouldn't be running"
}

# Main runner
run_service_auditing() {
    log_section "Starting Service Auditing"
    disable_unnecessary_services "../" #TODO: this
    audit_running_services
    log_success "Service Auditing completed"
}

export -f run_service_auditing
