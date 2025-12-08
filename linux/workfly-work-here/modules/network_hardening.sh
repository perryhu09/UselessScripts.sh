#!/bin/bash
# network_hardening.sh - Network security settings

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Network Hardening
# Category: Network security
# Description: Network security and firewall configuration

fix_hosts_file() {
  log_action "=== SECURING /etc/hosts FILE ==="

  if [ ! -f /etc/hosts ]; then
    log_action "WARNING: /etc/hosts not found"
    return 1
  fi

  backup_file /etc/hosts

  local suspicious_entries=$(grep -vE '^(127\.0\.0\.1|127\.0\.1\.1|::1|fe00::|ff00::|ff02::)' /etc/hosts | grep -vE '^\s*#' | grep -vE '^\s*$')
  local suspicious_count=$(echo "$suspicious_entries" | grep -c "^" 2>/dev/null || echo "0")

  if [ "$suspicious_count" -gt 0 ]; then
    log_action "WARNING: Found $suspicious_count suspicious/non-standard entries in /etc/hosts"
    log_action "Suspicious Entries:"
    echo "$suspicious_entries" | while read line; do
      log_action "	$line"
    done
  fi

  CURRENT_HOSTNAME=$(hostname)

  cat >/etc/hosts <<EOF
127.0.0.1 localhost
127.0.1.1 $CURRENT_HOSTNAME
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

  log_action "Reset /etc/hosts to secure default config"
  log_action "Removed any malicious redirects or blocking entries"
}

harden_ssh() {
  log_action "=== HARDENING SSH CONFIGURATION ==="

  # Check if SSH is installed
  if [ ! -f /etc/ssh/sshd_config ]; then
    log_action "SSH not installed (no sshd_config found), skipping"
    return 0
  fi

  backup_file /etc/ssh/sshd_config

  # Helper function to set a config option
  set_ssh_config() {
    local setting="$1"
    local value="$2"
    # Remove any existing lines (commented or not) for this setting
    sed -i "/^#*\s*${setting}\s/d" /etc/ssh/sshd_config
    # Append the new setting
    echo "${setting} ${value}" >> /etc/ssh/sshd_config
  }

  log_action "Configuring authentication settings..."

  set_ssh_config "PermitRootLogin" "no"
  set_ssh_config "PermitEmptyPasswords" "no"
  set_ssh_config "PasswordAuthentication" "yes"
  set_ssh_config "KbdInteractiveAuthentication" "no"
  set_ssh_config "ChallengeResponseAuthentication" "no"
  set_ssh_config "PubkeyAuthentication" "yes"
  set_ssh_config "GSSAPIAuthentication" "no"
  set_ssh_config "PermitUserEnvironment" "no"
  set_ssh_config "UsePAM" "yes"
  set_ssh_config "AuthorizedKeysFile" ".ssh/authorized_keys"

  log_action "Authentication settings configured"

  log_action "Configuring access restrictions..."

  set_ssh_config "HostbasedAuthentication" "no"
  set_ssh_config "IgnoreRhosts" "yes"

  log_action "Access restrictions configured"

  log_action "Configuring session limits and timeouts..."

  set_ssh_config "StrictModes" "yes"
  set_ssh_config "LoginGraceTime" "30"
  set_ssh_config "MaxAuthTries" "3"
  set_ssh_config "MaxSessions" "2"
  set_ssh_config "ClientAliveInterval" "300"
  set_ssh_config "ClientAliveCountMax" "2"
  set_ssh_config "TCPKeepAlive" "no"

  log_action "Session limits and timeouts configured"

  log_action "Configuring forwarding and tunneling (all disabled)..."

  set_ssh_config "X11Forwarding" "no"
  set_ssh_config "AllowAgentForwarding" "no"
  set_ssh_config "AllowTcpForwarding" "no"
  set_ssh_config "GatewayPorts" "no"
  set_ssh_config "PermitTunnel" "no"

  log_action "Forwarding and tunneling disabled"

  log_action "Configuring logging and DNS..."

  set_ssh_config "SyslogFacility" "AUTHPRIV"
  set_ssh_config "LogLevel" "VERBOSE"
  set_ssh_config "UseDNS" "no"
  set_ssh_config "VersionAddendum" "none"
  set_ssh_config "PrintMotd" "no"
  set_ssh_config "PrintLastLog" "yes"

  log_action "Logging and DNS configured"

  log_action "Configuring cryptographic algorithms..."

  set_ssh_config "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr"
  set_ssh_config "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
  set_ssh_config "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
  log_action "Cryptographic algorithms configured"

  log_action "Configuring SFTP subsystem..."

  sed -i '/^#*\s*Subsystem\s\+sftp/d' /etc/ssh/sshd_config
  echo "Subsystem sftp internal-sftp" >> /etc/ssh/sshd_config

  log_action "SFTP subsystem configured"

  # SSH banner
  log_action "Creating SSH warning banner..."

  local banner_file="/etc/issue.net"
  if [ -f "$banner_file" ]; then
    backup_file "$banner_file"
  fi

  cat > "$banner_file" << 'EOF'
***************************************************************************
                            AUTHORIZED USE ONLY
***************************************************************************
This system is for authorized users only. All activity may be monitored
and reported. Unauthorized access is prohibited and the guys from enlo
cypat team will get u >:(
***************************************************************************
EOF

  chmod 644 "$banner_file"
  set_ssh_config "Banner" "/etc/issue.net"

  log_action "SSH banner created at $banner_file"

  # Secure dir/file perms
  log_action "Securing SSH directory and file permissions..."

  chown root:root /etc/ssh
  chmod 755 /etc/ssh

  chmod 600 /etc/ssh/sshd_config
  chown root:root /etc/ssh/sshd_config

  for key in /etc/ssh/ssh_host_*_key; do
    if [ -f "$key" ]; then
      chmod 600 "$key"
      chown root:root "$key"
    fi
  done

  for pubkey in /etc/ssh/ssh_host_*_key.pub; do
    if [ -f "$pubkey" ]; then
      chmod 644 "$pubkey"
      chown root:root "$pubkey"
    fi
  done

  if [ -d /etc/ssh/sshd_config.d ]; then
    chmod 755 /etc/ssh/sshd_config.d
    for conf in /etc/ssh/sshd_config.d/*.conf; do
      if [ -f "$conf" ]; then
        chmod 644 "$conf"
        chown root:root "$conf"
      fi
    done
  fi

  log_action "SSH directory permissions secured"

  # moduli hardening
  log_action "Hardening SSH moduli (removing weak DH groups)..."

  local moduli_file="/etc/ssh/moduli"
  if [ -f "$moduli_file" ]; then
    backup_file "$moduli_file"

    # Keep only moduli with bit length >= 3071 (column 5)
    local temp_moduli="${moduli_file}.tmp"
    awk '$5 >= 3071' "$moduli_file" > "$temp_moduli" 2>/dev/null

    # Only replace if we have valid entries left
    if [ -s "$temp_moduli" ]; then
      mv "$temp_moduli" "$moduli_file"
      chmod 644 "$moduli_file"
      chown root:root "$moduli_file"
      log_action "Removed weak DH groups from moduli (keeping >= 3071-bit)"
    else
      rm -f "$temp_moduli"
      log_action "WARNING: No strong moduli found, keeping original file"
    fi
  else
    log_action "Moduli file not found, skipping"
  fi

  log_action "Validating SSH configuration..."

  if sshd -t 2>&1; then
    log_action "SSH configuration is valid"
  else
    log_action "ERROR: SSH configuration has errors!"
    log_action "Run 'sshd -t' to see details"
    log_action "Restoring backup may be necessary"
    return 1
  fi

  # Restart ssh
  log_action "Restarting SSH service to apply changes..."

  if command -v systemctl &>/dev/null; then
    if systemctl list-unit-files | grep -q "^ssh\.service"; then
      systemctl restart ssh &>/dev/null
      if [ $? -eq 0 ]; then
        log_action "SSH service (ssh) restarted successfully"
      else
        log_action "WARNING: Failed to restart ssh service"
      fi
    elif systemctl list-unit-files | grep -q "^sshd\.service"; then
      systemctl restart sshd &>/dev/null
      if [ $? -eq 0 ]; then
        log_action "SSH service (sshd) restarted successfully"
      else
        log_action "WARNING: Failed to restart sshd service"
      fi
    else
      log_action "WARNING: SSH service not found in systemctl"
    fi
  elif command -v service &>/dev/null; then
    service ssh restart &>/dev/null || service sshd restart &>/dev/null
    log_action "SSH service restarted (using service command)"
  else
    log_action "WARNING: Could not restart SSH service - do it manually"
  fi

  log_action "SSH hardening complete"
}

# Main runner
run_network_hardening() {
    log_section "Starting network hardening module"

    fix_hosts_file
    harden_ssh
    configure_firewall

    log_success "Network hardening complete"
}

export -f run_network_hardening
