#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

secure_file_permissions() {
  log_action "=== SECURING FILE PERMISSIONS ==="

  local fixed_count=0
  local total_checks=0

  # ================================
  # AUTHENTICATION & PASSWORD FILES
  # ================================
  
  if [[ -f /etc/passwd ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/passwd &>/dev/null && chown root:root /etc/passwd &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -f /etc/shadow ]]; then
    total_checks=$((total_checks + 1))
    if ! getent group shadow &>/dev/null; then
      groupadd shadow &>/dev/null
    fi
    chmod 640 /etc/shadow &>/dev/null && chown root:shadow /etc/shadow &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -f /etc/group ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/group &>/dev/null && chown root:root /etc/group &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -f /etc/gshadow ]]; then
    total_checks=$((total_checks + 1))
    if ! getent group shadow &>/dev/null; then
      groupadd shadow &>/dev/null
    fi
    chmod 640 /etc/gshadow &>/dev/null && chown root:shadow /etc/gshadow &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -f /etc/security/opasswd ]]; then
    total_checks=$((total_checks + 1))
    chmod 600 /etc/security/opasswd &>/dev/null && chown root:root /etc/security/opasswd &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  log_action "Secured password/authentication files ($fixed_count/$total_checks)"

  # ================================
  # SUDOERS CONFIGURATION
  # ================================

  if [[ -f /etc/sudoers ]]; then
    total_checks=$((total_checks + 1))
    chmod 440 /etc/sudoers &>/dev/null && chown root:root /etc/sudoers &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -d /etc/sudoers.d ]]; then
    chmod 750 /etc/sudoers.d &>/dev/null && chown root:root /etc/sudoers.d &>/dev/null
    while IFS= read -r -d '' file; do
      total_checks=$((total_checks + 1))
      chmod 440 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
  fi

  log_action "Secured sudoers configuration"

  # ================================
  # SSH CONFIGURATION & KEYS
  # ================================

  if [[ -d /etc/ssh ]]; then
    chmod 755 /etc/ssh &>/dev/null && chown root:root /etc/ssh &>/dev/null
  fi

  if [[ -f /etc/ssh/sshd_config ]]; then
    total_checks=$((total_checks + 1))
    chmod 600 /etc/ssh/sshd_config &>/dev/null && chown root:root /etc/ssh/sshd_config &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -d /etc/ssh/sshd_config.d ]]; then
    while IFS= read -r -d '' file; do
      total_checks=$((total_checks + 1))
      chmod 600 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    done < <(find /etc/ssh/sshd_config.d -type f -name "*.conf" -print0 2>/dev/null)
  fi

  # SSH host keys (private keys)
  for key in /etc/ssh/ssh_host_*_key; do
    if [[ -f "$key" ]]; then
      total_checks=$((total_checks + 1))
      chmod 600 "$key" &>/dev/null && chown root:root "$key" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    fi
  done

  # SSH host keys (public keys)
  for key in /etc/ssh/ssh_host_*_key.pub; do
    if [[ -f "$key" ]]; then
      total_checks=$((total_checks + 1))
      chmod 644 "$key" &>/dev/null && chown root:root "$key" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    fi
  done

  log_action "Secured SSH configuration and host keys"

  # ================================
  # GRUB BOOTLOADER FILES
  # ================================

  local grub_files=(
    "/boot/grub/grub.cfg"
    "/boot/grub2/grub.cfg"
    "/boot/grub/grub.conf"
    "/boot/efi/EFI/ubuntu/grub.cfg"
    "/boot/efi/EFI/linuxmint/grub.cfg"
    "/boot/efi/EFI/BOOT/grub.cfg"
  )

  for grub_file in "${grub_files[@]}"; do
    if [[ -f "$grub_file" ]]; then
      total_checks=$((total_checks + 1))
      chmod 600 "$grub_file" &>/dev/null && chown root:root "$grub_file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    fi
  done

  if [[ -d /boot/grub ]]; then
    chmod 755 /boot/grub &>/dev/null && chown root:root /boot/grub &>/dev/null
  fi

  log_action "Secured GRUB bootloader files"

  # ================================
  # CRON SYSTEM
  # ================================

  if [[ -f /etc/crontab ]]; then
    total_checks=$((total_checks + 1))
    chmod 600 /etc/crontab &>/dev/null && chown root:root /etc/crontab &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -d /etc/cron.d ]]; then
    chmod 700 /etc/cron.d &>/dev/null && chown root:root /etc/cron.d &>/dev/null
    while IFS= read -r -d '' file; do
      total_checks=$((total_checks + 1))
      chmod 600 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    done < <(find /etc/cron.d -type f -print0 2>/dev/null)
  fi

  # Cron time-based directories
  for cron_dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d "$cron_dir" ]]; then
      chmod 700 "$cron_dir" &>/dev/null && chown root:root "$cron_dir" &>/dev/null
      while IFS= read -r -d '' file; do
        total_checks=$((total_checks + 1))
        chmod 700 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
        [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
      done < <(find "$cron_dir" -type f -print0 2>/dev/null)
    fi
  done

  if [[ -d /var/spool/cron/crontabs ]]; then
    chmod 700 /var/spool/cron/crontabs &>/dev/null
    if getent group crontab &>/dev/null; then
      chown root:crontab /var/spool/cron/crontabs &>/dev/null
    else
      chown root:root /var/spool/cron/crontabs &>/dev/null
    fi
  fi

  # at and cron allow/deny files
  for control_file in /etc/at.allow /etc/at.deny /etc/cron.allow /etc/cron.deny; do
    if [[ -f "$control_file" ]]; then
      total_checks=$((total_checks + 1))
      chmod 600 "$control_file" &>/dev/null && chown root:root "$control_file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    fi
  done

  log_action "Secured cron system configuration"

  # ================================
  # LOGGING SYSTEM
  # ================================

  if [[ -d /var/log ]]; then
    if ! getent group syslog &>/dev/null; then
      groupadd syslog &>/dev/null
    fi
    chmod 750 /var/log &>/dev/null && chown root:syslog /var/log &>/dev/null
  fi

  local log_files=(
    "/var/log/auth.log"
    "/var/log/syslog"
    "/var/log/messages"
    "/var/log/secure"
    "/var/log/kern.log"
    "/var/log/daemon.log"
    "/var/log/boot.log"
  )

  for log_file in "${log_files[@]}"; do
    if [[ -f "$log_file" ]]; then
      total_checks=$((total_checks + 1))
      chmod 640 "$log_file" &>/dev/null
      chown root:adm "$log_file" 2>/dev/null || chown root:syslog "$log_file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    fi
  done

  # Audit log directory
  if [[ -d /var/log/audit ]]; then
    chmod 750 /var/log/audit &>/dev/null && chown root:root /var/log/audit &>/dev/null
  fi

  if [[ -f /var/log/audit/audit.log ]]; then
    total_checks=$((total_checks + 1))
    chmod 600 /var/log/audit/audit.log &>/dev/null && chown root:root /var/log/audit/audit.log &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  log_action "Secured logging system"

  # ================================
  # LOG ROTATION CONFIGURATION
  # ================================

  if [[ -f /etc/logrotate.conf ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/logrotate.conf &>/dev/null && chown root:root /etc/logrotate.conf &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -d /etc/logrotate.d ]]; then
    chmod 755 /etc/logrotate.d &>/dev/null && chown root:root /etc/logrotate.d &>/dev/null
    while IFS= read -r -d '' file; do
      total_checks=$((total_checks + 1))
      chmod 644 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    done < <(find /etc/logrotate.d -type f -print0 2>/dev/null)
  fi

  log_action "Secured log rotation configuration"

  # ================================
  # SECURITY & PAM DIRECTORIES
  # ================================

  if [[ -d /etc/security ]]; then
    chmod 755 /etc/security &>/dev/null && chown root:root /etc/security &>/dev/null
  fi

  if [[ -d /etc/pam.d ]]; then
    chmod 755 /etc/pam.d &>/dev/null && chown root:root /etc/pam.d &>/dev/null
    while IFS= read -r -d '' file; do
      total_checks=$((total_checks + 1))
      chmod 644 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    done < <(find /etc/pam.d -type f -print0 2>/dev/null)
  fi

  log_action "Secured PAM and security directories"

  # ================================
  # APPARMOR CONFIGURATION
  # ================================

  if [[ -d /etc/apparmor.d ]]; then
    chmod 755 /etc/apparmor.d &>/dev/null && chown root:root /etc/apparmor.d &>/dev/null
    while IFS= read -r -d '' file; do
      total_checks=$((total_checks + 1))
      chmod 644 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    done < <(find /etc/apparmor.d -type f -print0 2>/dev/null)
  fi

  if [[ -d /etc/apparmor ]]; then
    chmod 755 /etc/apparmor &>/dev/null && chown root:root /etc/apparmor &>/dev/null
  fi

  log_action "Secured AppArmor configuration"

  # ================================
  # FIREWALL CONFIGURATION
  # ================================

  if [[ -d /etc/ufw ]]; then
    chmod 755 /etc/ufw &>/dev/null && chown root:root /etc/ufw &>/dev/null
  fi

  if [[ -f /etc/ufw/ufw.conf ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/ufw/ufw.conf &>/dev/null && chown root:root /etc/ufw/ufw.conf &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -f /etc/default/ufw ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/default/ufw &>/dev/null && chown root:root /etc/default/ufw &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  log_action "Secured firewall configuration"

  # ================================
  # SSL/TLS CERTIFICATES & KEYS
  # ================================

  if [[ -d /etc/ssl/private ]]; then
    chmod 710 /etc/ssl/private &>/dev/null
    if getent group ssl-cert &>/dev/null; then
      chown root:ssl-cert /etc/ssl/private &>/dev/null
    else
      chown root:root /etc/ssl/private &>/dev/null
    fi
  fi

  # Secure private SSL keys
  for keydir in /etc/ssl/private /etc/letsencrypt/live /etc/letsencrypt/archive; do
    if [[ -d "$keydir" ]]; then
      while IFS= read -r -d '' key; do
        total_checks=$((total_checks + 1))
        chmod 600 "$key" &>/dev/null && chown root:root "$key" &>/dev/null
        [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
      done < <(find "$keydir" -type f \( -name "*.key" -o -name "*-key.pem" -o -name "privkey*.pem" \) -print0 2>/dev/null)
    fi
  done

  log_action "Secured SSL/TLS certificates and keys"

  # ================================
  # FTP SERVER DIRECTORIES
  # ================================

  for ftp_root in /srv/ftp /var/ftp; do
    if [[ -d "$ftp_root" ]]; then
      chmod 755 "$ftp_root" &>/dev/null
      if getent group ftp &>/dev/null; then
        chown root:ftp "$ftp_root" &>/dev/null
      else
        chown root:root "$ftp_root" &>/dev/null
      fi
    fi
  done

  log_action "Secured FTP directories"

  # ================================
  # ROOT HOME DIRECTORY
  # ================================

  if [[ -d /root ]]; then
    chmod 700 /root &>/dev/null && chown root:root /root &>/dev/null
  fi

  if [[ -f /root/.ssh/authorized_keys ]]; then
    total_checks=$((total_checks + 1))
    chmod 600 /root/.ssh/authorized_keys &>/dev/null && chown root:root /root/.ssh/authorized_keys &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  log_action "Secured root home directory"

  # ================================
  # SYSTEM BINARIES
  # ================================

  for bin_dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
    if [[ -d "$bin_dir" ]]; then
      chmod 755 "$bin_dir" &>/dev/null && chown root:root "$bin_dir" &>/dev/null
    fi
  done

  log_action "Secured system binary directories"

  # ================================
  # KERNEL & SYSTEM CONFIGURATION
  # ================================

  if [[ -f /etc/sysctl.conf ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/sysctl.conf &>/dev/null && chown root:root /etc/sysctl.conf &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -d /etc/sysctl.d ]]; then
    chmod 755 /etc/sysctl.d &>/dev/null && chown root:root /etc/sysctl.d &>/dev/null
    while IFS= read -r -d '' file; do
      total_checks=$((total_checks + 1))
      chmod 644 "$file" &>/dev/null && chown root:root "$file" &>/dev/null
      [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
    done < <(find /etc/sysctl.d -type f -name "*.conf" -print0 2>/dev/null)
  fi

  log_action "Secured kernel configuration files"

  # ================================
  # NETWORK CONFIGURATION
  # ================================

  if [[ -f /etc/hosts ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/hosts &>/dev/null && chown root:root /etc/hosts &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -f /etc/hosts.allow ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/hosts.allow &>/dev/null && chown root:root /etc/hosts.allow &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  if [[ -f /etc/hosts.deny ]]; then
    total_checks=$((total_checks + 1))
    chmod 644 /etc/hosts.deny &>/dev/null && chown root:root /etc/hosts.deny &>/dev/null
    [[ $? -eq 0 ]] && fixed_count=$((fixed_count + 1))
  fi

  log_action "Secured network configuration files"

  # ================================
  # FINAL SUMMARY
  # ================================

  log_action ""
  log_action "File Permissions Hardening Complete:"
  log_action "  Total checks performed: $total_checks"
  log_action "  Files/directories secured: $fixed_count"
  log_action ""
}

verify_critical_file_permissions() {
  log_action "=== VERIFYING CRITICAL FILE PERMISSIONS ==="

  local total_checks=0
  local issues_found=0
  local files_correct=0

  # Define critical files with expected permissions
  # Format: "path:permissions:owner:group"
  local critical_files=(
    "/etc/passwd:644:root:root"
    "/etc/shadow:640:root:shadow"
    "/etc/group:644:root:root"
    "/etc/gshadow:640:root:shadow"
    "/etc/security/opasswd:600:root:root"
    "/etc/sudoers:440:root:root"
    "/etc/ssh/sshd_config:600:root:root"
    "/etc/crontab:600:root:root"
    "/etc/at.allow:600:root:root"
    "/etc/at.deny:600:root:root"
    "/etc/cron.allow:600:root:root"
    "/etc/cron.deny:600:root:root"
    "/boot/grub/grub.cfg:600:root:root"
    "/boot/grub2/grub.cfg:600:root:root"
    "/var/log/auth.log:640:root:adm"
    "/var/log/syslog:640:root:adm"
    "/var/log/audit/audit.log:600:root:root"
    "/etc/sysctl.conf:644:root:root"
    "/etc/hosts:644:root:root"
    "/etc/hosts.allow:644:root:root"
    "/etc/hosts.deny:644:root:root"
    "/etc/logrotate.conf:644:root:root"
    "/etc/ufw/ufw.conf:644:root:root"
    "/etc/default/ufw:644:root:root"
  )

  # SSH host keys (private)
  for key in /etc/ssh/ssh_host_*_key; do
    if [[ -f "$key" && ! "$key" =~ \.pub$ ]]; then
      critical_files+=("$key:600:root:root")
    fi
  done

  # SSH host keys (public)
  for key in /etc/ssh/ssh_host_*_key.pub; do
    if [[ -f "$key" ]]; then
      critical_files+=("$key:644:root:root")
    fi
  done

  log_action "Checking critical files..."
  log_action ""

  for entry in "${critical_files[@]}"; do
    IFS=':' read -r file expected_perm expected_owner expected_group <<< "$entry"
    
    if [[ ! -f "$file" ]]; then
      continue
    fi

    total_checks=$((total_checks + 1))
    
    local actual_perm=$(stat -c '%a' "$file" 2>/dev/null)
    local actual_owner=$(stat -c '%U' "$file" 2>/dev/null)
    local actual_group=$(stat -c '%G' "$file" 2>/dev/null)
    
    local file_correct=true
    local issues=""

    if [[ "$actual_perm" != "$expected_perm" ]]; then
      file_correct=false
      issues="${issues}perm:$actual_perm(exp:$expected_perm) "
    fi

    if [[ "$actual_owner" != "$expected_owner" ]]; then
      file_correct=false
      issues="${issues}owner:$actual_owner(exp:$expected_owner) "
    fi

    if [[ "$actual_group" != "$expected_group" ]]; then
      # Allow alternative groups for log files
      if [[ "$file" =~ /var/log/ && ("$actual_group" == "adm" || "$actual_group" == "syslog") ]]; then
        :  # This is acceptable
      else
        file_correct=false
        issues="${issues}group:$actual_group(exp:$expected_group) "
      fi
    fi

    if [[ "$file_correct" == true ]]; then
      log_action "$file ($actual_perm $actual_owner:$actual_group)"
      files_correct=$((files_correct + 1))
    else
      log_action " $file - $issues"
      issues_found=$((issues_found + 1))
    fi
  done

  log_action ""
  log_action "Checking critical directories..."
  log_action ""

  local critical_dirs=(
    "/etc/ssh:755:root:root"
    "/etc/sudoers.d:750:root:root"
    "/etc/cron.d:700:root:root"
    "/etc/cron.hourly:700:root:root"
    "/etc/cron.daily:700:root:root"
    "/etc/cron.weekly:700:root:root"
    "/etc/cron.monthly:700:root:root"
    "/var/spool/cron/crontabs:700:root:crontab"
    "/var/log:750:root:syslog"
    "/var/log/audit:750:root:root"
    "/etc/security:755:root:root"
    "/etc/pam.d:755:root:root"
    "/etc/apparmor.d:755:root:root"
    "/etc/logrotate.d:755:root:root"
    "/root:700:root:root"
    "/etc/ssl/private:710:root:ssl-cert"
  )

  for entry in "${critical_dirs[@]}"; do
    IFS=':' read -r dir expected_perm expected_owner expected_group <<< "$entry"
    
    if [[ ! -d "$dir" ]]; then
      continue
    fi

    total_checks=$((total_checks + 1))
    
    local actual_perm=$(stat -c '%a' "$dir" 2>/dev/null)
    local actual_owner=$(stat -c '%U' "$dir" 2>/dev/null)
    local actual_group=$(stat -c '%G' "$dir" 2>/dev/null)
    
    local dir_correct=true
    local issues=""

    if [[ "$actual_perm" != "$expected_perm" ]]; then
      dir_correct=false
      issues="${issues}perm:$actual_perm(exp:$expected_perm) "
    fi

    if [[ "$actual_owner" != "$expected_owner" ]]; then
      dir_correct=false
      issues="${issues}owner:$actual_owner(exp:$expected_owner) "
    fi

    if [[ "$actual_group" != "$expected_group" ]]; then
      # Allow fallback to root:root for some directories
      if [[ "$expected_group" == "ssl-cert" || "$expected_group" == "crontab" || "$expected_group" == "syslog" ]]; then
        if [[ "$actual_group" == "root" ]]; then
          :  # This is acceptable fallback
        else
          dir_correct=false
          issues="${issues}group:$actual_group(exp:$expected_group) "
        fi
      else
        dir_correct=false
        issues="${issues}group:$actual_group(exp:$expected_group) "
      fi
    fi

    if [[ "$dir_correct" == true ]]; then
      log_action "$dir ($actual_perm $actual_owner:$actual_group)"
      files_correct=$((files_correct + 1))
    else
      log_action "$dir - $issues"
      issues_found=$((issues_found + 1))
    fi
  done

  log_action ""
  log_action "========================================="
  log_action "Verification Summary:"
  log_action "  Total checks: $total_checks"
  log_action "  Correct: $files_correct"
  log_action "  Issues found: $issues_found"
  log_action "========================================="

  if [[ $issues_found -eq 0 ]]; then
    log_action "ALL CRITICAL FILE PERMISSIONS ARE SECURE"
  else
    log_action "WARNING: $issues_found permission issue(s) detected"
    log_action "Run secure_file_permissions() to fix these issues"
  fi
  log_action ""
}

fix_sudoers_nopasswd() {
  log_action "=== CHECKING SUDOERS FOR NOPASSWD ENTRIES ==="

  local found_issues=0
  local sudoers_files=()
  [ -f /etc/sudoers ] && sudoers_files+=(/etc/sudoers)

  if [ -d /etc/sudoers.d ]; then
    for file in /etc/sudoers.d/*; do
      [ -f "$file" ] && sudoers_files+=("$file")
    done
  fi

  for sudoers_file in "${sudoers_files[@]}"; do
    if grep -q "NOPASSWD" "$sudoers_file"; then
      log_action "WARNING: Found NOPASSWD in $sudoers_file"
      backup_file "$sudoers_file"

      sed -i 's/^\(.*NOPASSWD.*\)$/# DISABLED BY HARDENING SCRIPT: \1/' "$sudoers_file"
      log_action "Disabled NOPASSWD entries in $sudoers_file"
      ((found_issues++))
    fi
  done

  if [ $found_issues -eq 0 ]; then
    log_action "No NOPASSWD entries found in sudoers files"
  else
    log_action "Fixed $found_issues sudoers file(s) with NOPASSWD entries"
  fi

  if [[ -f /etc/sudoers ]]; then
    grep -q "Defaults.*use_pty" /etc/sudoers || echo "Defaults use_pty" >> /etc/sudoers
    grep -q 'Defaults.*logfile=' /etc/sudoers || echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
    log_action "Added sudo PTY requirement and logging"
  fi
}

find_world_writable_files() {
  log_action "=== CHECKING FOR WORLD-WRITABLE FILES ==="
  
  local exclude_paths=(
    -path /proc -prune -o
    -path /sys -prune -o
    -path /dev -prune -o
    -path /run -prune -o
    -path /tmp -prune -o
    -path /var/tmp -prune -o
    -path /var/crash -prune -o
    -path /var/lock -prune -o
    -path /var/spool -prune -o
    -path /snap -prune -o
    -path '/home/*/.cache' -prune -o
    -path '/home/*/.local/share/Trash' -prune -o
  )
  
  log_action "Scanning for suspicious world-writable files (excluding system paths)..."
  
  while IFS= read -r file; do
    # Additional filtering - skip if in /home and owned by regular user
    if [[ "$file" =~ ^/home/ ]]; then
      local file_owner=$(stat -c '%U' "$file" 2>/dev/null)
      local file_dir=$(dirname "$file")
      # Skip if file is in user's own directory and owned by them
      if [[ "$file_dir" =~ ^/home/$file_owner ]]; then
        continue
      fi
    fi
    log_action "  WORLD-WRITABLE: $file"
    log_action "    Owner: $(stat -c '%U:%G' "$file" 2>/dev/null)"
    log_action "    Perms: $(stat -c '%a' "$file" 2>/dev/null)"
  done < <(find / "${exclude_paths[@]}" -type f -perm -0002 -print 2>/dev/null)
  log_action "  To fix: chmod o-w /path/to/file"
}

check_suid_sgid() {
  log_action "=== CHECKING SUID/SGID BINARIES ==="

  local LEGIT_SUID=(
    # Core system binaries
    "/bin/su"
    "/bin/sudo"
    "/usr/bin/sudo"
    "/bin/mount"
    "/bin/umount"
    "/usr/bin/mount"
    "/usr/bin/umount"
    
    # Password management
    "/usr/bin/passwd"
    "/usr/bin/gpasswd"
    "/usr/bin/newgrp"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/expiry"
    "/usr/bin/chage"
    
    # Network utilities
    "/bin/ping"
    "/usr/bin/ping"
    "/usr/bin/ping6"
    "/bin/ping6"
    "/usr/sbin/pppd"
    
    # Filesystem utilities
    "/usr/bin/fusermount"
    "/usr/bin/fusermount3"
    "/bin/fusermount"
    "/usr/bin/ntfs-3g"
    
    # Policy/privilege escalation
    "/usr/bin/pkexec"
    "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/lib/x86_64-linux-gnu/polkit-1/polkit-agent-helper-1"
    
    # D-Bus
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/dbus-1/dbus-daemon-launch-helper"
    
    # SSH
    "/usr/lib/openssh/ssh-keysign"
    
    # Desktop environment
    "/usr/lib/xorg/Xorg.wrap"
    "/usr/bin/Xorg"
    
    # CUPS printing
    "/usr/lib/cups/backend/cups-pdf"
    
    # Other common legitimate binaries
    "/usr/bin/at"
    "/usr/bin/crontab"
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/sbin/unix_chkpwd"
    "/usr/sbin/pam_timestamp_check"
    "/sbin/unix_chkpwd"
  )
  
  local count=0
  local suspicious_count=0
  
  local exclude_paths=(
    -path /proc -prune -o
    -path /sys -prune -o
    -path /snap -prune -o
    -path '/var/lib/snapd' -prune -o
  )
  
  log_action "Scanning for SUID/SGID binaries..."
  
  while IFS= read -r file; do
    ((count++))
    local is_legit=false
    for legit in "${LEGIT_SUID[@]}"; do
      if [[ "$file" == "$legit" ]]; then
        is_legit=true
        break
      fi
    done
    
    if [ "$is_legit" = false ]; then
      ((suspicious_count++))
      log_action "SUSPICIOUS SUID/SGID: $file"
      
      local perms=$(stat -c '%a' "$file" 2>/dev/null)
      local owner=$(stat -c '%U:%G' "$file" 2>/dev/null)
      local package=$(dpkg -S "$file" 2>/dev/null | cut -d: -f1 || echo "unknown")

      log_action "    Permissions: $perms"
      log_action "    Owner: $owner"
      log_action "    Package: $package"
      log_action "    To remove SUID: chmod u-s $file"
      log_action "    To remove SGID: chmod g-s $file"
    fi
  done < <(find / "${exclude_paths[@]}" -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
  
  log_action ""
  log_action "SUID/SGID Summary:"
  log_action "  Total SUID/SGID binaries found: $count"
  log_action "  Suspicious binaries: $suspicious_count"
}

find_orphaned_files() {
  log_action "=== CHECKING FOR ORPHANED FILES ==="
  local count=0
  
  local exclude_paths=(
    -path /proc -prune -o
    -path /sys -prune -o
    -path /dev -prune -o
    -path /run -prune -o
    -path /snap -prune -o
    -path '/var/lib/snapd' -prune -o
    -path '/var/lib/docker' -prune -o
    -path '/var/cache' -prune -o
    -path '/tmp' -prune -o
    -path '/var/tmp' -prune -o
  )
  
  log_action "Scanning for Orphaned Files (files without valid owner or group)..."
  
  while IFS= read -r file; do
    ((count++))
    local uid=$(stat -c '%u' "$file" 2>/dev/null)
    local gid=$(stat -c '%g' "$file" 2>/dev/null)
    local perms=$(stat -c '%a' "$file" 2>/dev/null)
    
    log_action "  ORPHANED: $file"
    log_action "    UID: $uid (no user), GID: $gid"
    log_action "    Permissions: $perms"
    log_action "    To fix: chown root:root $file"
  done < <(find / "${exclude_paths[@]}" \( -nouser -o -nogroup \) -print 2>/dev/null)
}

run_file_permissions() {
    log_section "File Perms Check"
    secure_file_permissions
    verify_critical_file_permissions
    fix_sudoers_nopasswd
    find_world_writable_files
    check_suid_sgid
    find_orphaned_files

    log_success "File Perms check completed"
}

export -f run_file_permissions
