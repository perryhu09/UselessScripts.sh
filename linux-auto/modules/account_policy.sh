#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

disallow_empty_passwords() {
  log_action "=== DISALLOWING EMPTY PASSWORDS ==="
  backup_file /etc/pam.d/common-auth

  if grep -q "nullok" /etc/pam.d/common-auth; then
    sed -i 's/nullok//g' /etc/pam.d/common-auth
    log_action "Removed nullok from common-auth"
  else
    log_action "No nullok found in common-auth"
  fi

  log_action "Disallowed empty user passwords"
}

configure_account_lockout() {
    log_action "=== CONFIGURING ACCOUNT LOCKOUT POLICY ==="

    if ! find /lib* /usr/lib* -name "pam_faillock.so" 2>/dev/null | grep -q .; then
        log_action "WARNING: pam_faillock.so not found, skipping lockout config"
        return 1
    fi

    # Create pam-config profile: faillock_notify (runs BEFORE authentication)
    cat >/usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
    requisite                       pam_faillock.so preauth
EOF
    log_action "Created faillock_notify profile"

    # Create pam-config profile: faillock (runs AFTER failed auth)
    cat >/usr/share/pam-configs/faillock <<'EOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die]                   pam_faillock.so authfail
EOF
    log_action "Created faillock profile"

    # Create pam-config profile: faillock_reset (runs AFTER successful auth)
    cat >/usr/share/pam-configs/faillock_reset <<'EOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
    required                        pam_faillock.so authsucc
EOF
    log_action "Created faillock_reset profile"

    if pam-auth-update --enable faillock faillock_reset faillock_notify --force 2>/dev/null; then
        log_action "Enabled faillock profiles via pam-auth-update"
    else
        log_action "ERROR: pam-auth-update failed"
        return 1
    fi

    backup_file /etc/security/faillock.conf
    cat >/etc/security/faillock.conf <<'EOF'
# Account Lockout Configuration

# Lock account after 5 failed attempts
deny = 5

# Unlock after 15 minutes (900 seconds)
unlock_time = 900

# Count failures within 15 minute window
fail_interval = 900

# Also lock root account on failed attempts
even_deny_root
EOF
    log_action "Configured /etc/security/faillock.conf"

    log_action "Account lockout policy configured (lock after 5 failures, unlock after 15 min)"
}

configure_pam() {
  log_action "=== CONFIGURING PAM: PWD COMPLEXITY, HISTORY, & ACCOUNT LOCKOUT ==="

  apt install -y libpam-pwquality libpam-modules libpam-modules-bin &>/dev/null

  backup_file /etc/pam.d/common-password

  sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password &>/dev/null
  sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=3 reject_username enforce_for_root' /etc/pam.d/common-password &>/dev/null
  log_action "Configured password complexity requirements"

  sed -i '/pam_pwhistory.so/d' /etc/pam.d/common-password &>/dev/null
  sed -i '/pam_unix.so/a password requisite pam_pwhistory.so remember=5 enforce_for_root use_authtok' /etc/pam.d/common-password &>/dev/null
  log_action "Configured password history (remember=5)"

  backup_file /etc/pam.d/common-auth
}

set_password_aging() {
  log_action "=== CONFIGURE PASSWORD AGING POLICIES ==="

  backup_file /etc/login.defs

  # max password age
  if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   14/' /etc/login.defs &>/dev/null
  else
    echo "PASS_MAX_DAYS   14" >>/etc/login.defs
  fi

  # min password age
  if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   5/' /etc/login.defs &>/dev/null
  else
    echo "PASS_MIN_DAYS   5" >>/etc/login.defs
  fi

  # pwd expiration warning
  if grep -q "^PASS_WARN_DAYS" /etc/login.defs; then
    sed -i 's/^PASS_WARN_DAYS.*/PASS_WARN_DAYS   7/' /etc/login.defs &>/dev/null
  else
    echo "PASS_WARN_DAYS   7" >>/etc/login.defs
  fi

  log_action "Set password aging: max=14 days, min=5 days, warn=7 days"

  CURRENT_USERS=$(awk -F: '($3 >=1000 || $3 == 0) && $1 != "nobody" {print $1}' /etc/passwd)

  for user in $CURRENT_USERS; do
    if [ "$user" = "root" ]; then
      continue
    fi
    if [[ " ${AUTHORIZED_USERS[@]} ${ADMIN_USERS[@]} " =~ " ${user} " ]]; then
      chage -M 14 -m 5 -W 7 "$user" &>/dev/null
      log_action "Applied aging policy to user: $user"
    fi
  done
}

run_account_policy() {
    log_section "Starting Account Policy Configuration"
    disallow_empty_passwords
    # configure_account_lockout
    configure_pam
    set_password_aging
    log_success "Account Policy Configuration completed"
}

export -f run_account_policy
