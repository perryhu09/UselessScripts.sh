#!/usr/bin/env bash

# Set up log  directory and file
if [ -n "$SUDO_USER" ]; then
  ACTUAL_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  ACTUAL_USER_HOME="$HOME"
fi
LOG_FILE="$ACTUAL_USER_HOME/Desktop/hardening.log"

# Logging Function
log_action() {
  local timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"
  local message="$timestamp $1"

  echo "$message"
  echo "$message" >>"$LOG_FILE" 2>/dev/null
}

backup_file() {
  if [ -f "$1" ]; then
    cp "$1" "$1.bak.$(date +%s)"
    log_action "Backed up $1"
  fi
}

pkg_install_pam_modules() {
  log_action "Installing required PAM modules if missing"

  local -a pkgs=()

  ls /lib/*/security/pam_pwquality.so >/dev/null 2>&1 || pkgs+=("libpam-pwquality")
  ls /lib/*/security/pam_faillock.so  >/dev/null 2>&1 || pkgs+=("libpam-modules")
  command -v faillock >/dev/null 2>&1 || pkgs+=("libpam-modules-bin")

  if (( ${#pkgs[@]} )); then
    apt-get update -y -qq &>/dev/null
    if apt-get install -y -qq "${pkgs[@]}" &>/dev/null; then
      log_action "Installed: ${pkgs[*]}"
    else
      log_action "ERROR: failed to install: ${pkgs[*]}"
      exit 1
    fi
  else
    log_action "PAM modules already present"
  fi

  for mod in pam_pwquality.so pam_pwhistory.so pam_faillock.so; do
    if ! ls /lib/*/security/"$mod" >/dev/null 2>&1; then
      log_action "ERROR: missing $mod even after install"
      exit 1
    fi
  done
}

configure_pam() {
        #implementation here
}

configure_pam
