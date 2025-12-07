#===============================================
# Cronjobs
#===============================================

secure_cron_system() {
  log_action "=== SECURING CRON SYSTEM ==="

  # Check current user's crontab
  if crontab -l &>/dev/null; then
    log_action "Current user has crontab entries (logged to file)"
    crontab -l >>"$LOG_FILE" 2>&1
  else
    log_action "No crontab for current user"
  fi

  # Scan system cron directories
  log_action "Scanning system cron directories..."
  for file in /etc/crontab /etc/cron.*/* /var/spool/cron/crontabs/*; do
    if [ -e "$file" ]; then
      log_action "Found cron file: $file"
      cat "$file" >>"$LOG_FILE" 2>&1
    fi
  done

  # Check init files
  log_action "Checking init files..."
  for init_file in /etc/init/*.conf /etc/init.d/*; do
    if [ -e "$init_file" ]; then
      log_action "Found init file: $init_file"
    fi
  done

  # Clear /etc/rc.local (startup script)
  log_action "Clearing /etc/rc.local..."
  backup_file "/etc/rc.local"
  echo "exit 0" >/etc/rc.local 2>/dev/null
  chmod +x /etc/rc.local &>/dev/null
  log_action "/etc/rc.local reset to 'exit 0'"

  # List all user crontabs
  log_action "Listing all user crontabs..."
  while IFS=: read -r user _; do
    if crontab -u "$user" -l &>/dev/null; then
      log_action "Crontab for $user (logged to file)"
      crontab -u "$user" -l >>"$LOG_FILE" 2>&1
    fi
  done </etc/passwd

  # Deny all users from using cron (restrictive approach)
  log_action "Denying all users from using cron..."
  backup_file "/etc/cron.deny"
  echo "ALL" >>/etc/cron.deny 2>/dev/null
  log_action "Appended 'ALL' to /etc/cron.deny"

  log_action "Cron security lockdown completed"
}
