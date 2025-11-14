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
  log_action "=== CONFIGURING PAM: PWD COMPLEXITY, HISTORY, & ACCOUNT LOCKOUT=="
  
  apt install -y libpam-pwquality libpam-modules libpam-modules-bin &>/dev/null
  
  # PASSWORD COMPLEXITY & HISTORY (your existing code)
  backup_file /etc/pam.d/common-password
  sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password &>/dev/null
  sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=3 reject_username enforce_for_root' /etc/pam.d/common-password &>/dev/null
  log_action "Configured password complexity requirements"
  
  sed -i '/pam_pwhistory.so/d' /etc/pam.d/common-password &>/dev/null
  sed -i '/pam_unix.so/a password requisite pam_pwhistory.so remember=5 enforce_for_root use_authtok' /etc/pam.d/common-password &>/dev/null
  log_action "Configured password history (remember=5)"
  
  # ACCOUNT LOCKOUT - Rewrite the file cleanly
  backup_file /etc/pam.d/common-auth
  
  cat > /etc/pam.d/common-auth << 'EOF'
# Added by hardening script - Account lockout
auth required pam_faillock.so preauth silent deny=5 unlock_time=1800

# Standard Unix authentication
auth [success=2 default=ignore] pam_unix.so nullok try_first_pass

# Faillock on auth failure
auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800
auth sufficient pam_faillock.so authsucc

# PAM configuration (common-auth)
auth requisite pam_deny.so
auth required pam_permit.so
EOF
  
  log_action "Rewrote common-auth with faillock"
  
  # ACCOUNT PHASE
  backup_file /etc/pam.d/common-account
  if ! grep -q "pam_faillock.so" /etc/pam.d/common-account; then
    sed -i '1i account required pam_faillock.so' /etc/pam.d/common-account
  fi
  
  log_action "Account lockout configured"
}

configure_pam
