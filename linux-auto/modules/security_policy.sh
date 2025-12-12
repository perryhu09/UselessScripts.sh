#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

harden_auditd() {
  log_action "=== HARDENING AUDITD (SYSTEM AUDITING) ==="

  # Install auditd
  if ! command -v auditctl &>/dev/null; then
    log_action "Installing auditd and plugins..."
    apt-get update -qq &>/dev/null
    apt-get install -y -qq auditd audispd-plugins &>/dev/null
    log_action "auditd installed successfully"
  else
    log_action "auditd already installed"
  fi

  # Enable auditd at runtime
  log_action "Enabling auditd in current session..."
  auditctl -e 1 &>/dev/null
  log_action "auditd enabled (auditctl -e 1)"

  # Set GRUB to persist audit=1 across reboot
  if [ -f /etc/default/grub ] && grep -q 'GRUB_CMDLINE_LINUX=' /etc/default/grub; then
    backup_file "/etc/default/grub"

    # Check if audit=1 is already present
    if ! grep -q 'audit=1' /etc/default/grub; then
      log_action "Adding audit=1 to GRUB kernel parameters..."
      sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="audit=1 /' /etc/default/grub &>/dev/null
      update-grub &>/dev/null
      log_action "GRUB updated to enable persistent audit logging"
    else
      log_action "GRUB already configured with audit=1"
    fi
  fi

  # Backup and update auditd.conf
  backup_file "/etc/audit/auditd.conf"
  log_action "Configuring auditd.conf with hardened settings..."

  cat >/etc/audit/auditd.conf <<'EOF'
# CyberPatriot auditd configuration
log_file = /var/log/audit/audit.log
log_format = RAW
flush = INCREMENTAL
freq = 50
num_logs = 10
max_log_file = 20
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF
  log_action "auditd.conf configured successfully"

  # Create hardened audit rules
  local RULE_FILE="/etc/audit/rules.d/hardening.rules"
  log_action "Creating hardened audit rules in $RULE_FILE..."
  backup_file "$RULE_FILE"

  cat >"$RULE_FILE" <<'EOF'
# CyberPatriot Audit Rules - Monitor security-critical events

# Permission changes
-w /bin/chmod -p x -k perm_mod
-w /bin/chown -p x -k perm_mod

# Password changes
-w /usr/bin/passwd -p x -k passwd_change
-w /etc/shadow -p wa -k shadow_access
-w /etc/passwd -p wa -k passwd_access

# Sudo usage
-w /usr/bin/sudo -p x -k sudo_usage

# All program executions (comprehensive but may be noisy)
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

# Login monitoring
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k failed_logins
-w /var/log/faillog -p wa -k login_failures

# Privilege escalation attempts
-a always,exit -F arch=b64 -S setuid,setgid -k priv_esc
-a always,exit -F arch=b32 -S setuid,setgid -k priv_esc
EOF
  log_action "Audit rules created successfully"

  # Load audit rules and restart auditd
  log_action "Loading audit rules and restarting auditd..."
  augenrules --load &>/dev/null
  systemctl restart auditd &>/dev/null
  log_action "auditd restarted with new rules"

  # Verify auditd is running
  if systemctl is-active --quiet auditd; then
    log_action "auditd is running and monitoring system events"
  else
    log_action "WARNING: auditd may not be running correctly"
  fi

  log_action "auditd hardening complete"
}

enable_app_armor() {
  log_action "=== ENABLING APP ARMOR ==="

  log_action "Installing AppArmor packages"

  if apt install -y apparmor apparmor-utils apparmor-profiles &>/dev/null; then
    log_action "Installed successfully"
  else
    log_action "WARNING: Failed to fully install AppArmor packages"
  fi

  systemctl enable apparmor && systemctl start apparmor
  log_action "App Armor has been enabled"
}

#===============================================
# Lynis
#===============================================

audit_with_lynis() {
  log_action "=== RUNNING LYNIS SECURITY AUDIT ==="

  apt install -y -qq lynis &>/dev/null

  log_action "Running Lynis system audit..."
  lynis audit system &>/dev/null
  log_action "Lynis audit completed"

  log_action "Full report available at: /var/log/lynis-report.dat"
  log_action "Lynis security audit completed"
}

run_security_policy() {
    log_section "Starting Security Policy Configuration"
    harden_auditd
    enable_app_armor
    audit_with_lynis
    log_success "Security Policy Configuration completed"
}

export -f run_security_policy
