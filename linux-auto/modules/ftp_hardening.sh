#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

harden_ftp() {
  log_action "=== HARDENING VSFTP ==="

  local config=""
  if [ -f "/etc/vsftpd.conf" ]; then
    config="/etc/vsftpd.conf"
  elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    config="/etc/vsftpd/vsftpd.conf"
  else
    log_action "vsftpd not installed (no config found), skipping"
    return 0
  fi

  log_action "Found vsftpd config: $config"
  backup_file "$config"

  set_option() {
    local option="$1"
    local value="$2"

    if grep -q "^#*\s*${option}=" "$config"; then
      sed -i "s/^#*\s*${option}=.*/${option}=${value}/" "$config"
    else
      echo "${option}=${value}" >> "$config"
    fi
  }

  log_action "Configuring user access settings..."

  set_option "anonymous_enable" "NO"
  set_option "local_enable" "YES"
  set_option "write_enable" "NO"
  set_option "chroot_local_user" "YES"
  set_option "allow_writable_chroot" "NO"
  set_option "hide_ids" "YES"

  log_action "User access settings configured"

  log_action "Configuring server identity and security..."

  set_option "ftpd_banner" "FTP server ready..."
  set_option "nopriv_user" "nobody"

  log_action "Server identity configured"

  log_action "Configuring logging"

  set_option "xferlog_enable" "YES"
  set_option "xferlog_std_format" "NO"
  set_option "log_ftp_protocol" "YES"

  log_action "Logging configured"

  log_action "Configuring passive mode..."

  set_option "pasv_enable" "YES"
  set_option "pasv_min_port" "40000"
  set_option "pasv_max_port" "50000"
  set_option "pasv_promiscuous" "NO"
  set_option "port_promiscuous" "NO"

  log_action "Passive mode configured (ports 40k-50k)"

  log_action "Configuring TLS encryption..."

  set_option "ssl_enable" "YES"
  set_option "force_local_logins_ssl" "YES"
  set_option "force_local_data_ssl" "YES"
  set_option "allow_anon_ssl" "NO"
  set_option "require_ssl_reuse" "NO"

  set_option "ssl_sslv2" "NO"
  set_option "ssl_sslv3" "NO"
  set_option "ssl_tlsv1" "NO"

  set_option "ssl_ciphers" "HIGH"

  set_option "rsa_cert_file" "/etc/ssl/certs/ssl-cert-snakeoil.pem"
  set_option "rsa_private_key_file" "/etc/ssl/private/ssl-cert-snakeoil.key"

  log_action "TLS encryption configured"

  log_action "Configuring PAM and networks settings"

  set_option "pam_service_name" "vsftpd"

  set_option "listen" "YES"
  set_option "listen_ipv6" "NO"

  log_action "PAM and network settings configured"

  log_action "Securing config file permissions..."

  chmod 600 "$config"
  chown root:root "$config"

  log_action "Config file secured (chmod 600, owned by root)"

  log_action "Restarting vsftpd service"
  if systemctl is-active vsftpd &>/dev/null; then
    systemctl restart vsftpd &>/dev/null
    if [ $? -eq 0 ]; then
      log_action "vsftpd service restarted successfully"
    else
      log_action "WARNING: failed to restart vsftpd"
    fi
  elif service vsftpd status &>/dev/null; then
    service vsftpd restart &>/dev/null
    log_action "vsftpd service restarted (using service command)"
  else
    log_action "vsftpd service not running - start manually with: sudo systemctl start vsftpd"
  fi

  log_action "vsftpd hardening complete"
}

run_ftp_hardening() {
    log_section "Starting Ftp Hardening"
    harden_ftp
    log_success "Ftp Hardening completed"
}

export -f run_ftp_hardening
