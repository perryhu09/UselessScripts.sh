#!/bin/bash
# samba_hardening.sh - Samba Hardening Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Samba Hardening
# Category: Service Hardening
# Description: Hardens Samba configuration
harden_samba(){
  log_action "=== HARDENING SAMBA CONFIGURATION ==="

  if ! command -v smbd &>/dev/null; then
    log_action "Samba not installed, skipping"
    return 0
  fi

  local SMB_CONF=""
  for cfg in /etc/samba/smb.conf /etc/smb.conf /usr/local/samba/lib/smb.conf; do
    if [ -f "$cfg" ]; then
      SMB_CONF="$cfg"
      break
    fi
  done

  if [ -z "$SMB_CONF" ]; then
    log_action "WARNING: smb.conf not found"
    return 0
  fi
  log_action "Found smb.conf: $SMB_CONF"

  log_action "Backing up Samba configuration"
  backup_file "$SMB_CONF"

  log_action "Extracting existing share definitions"
  local EXISTING_SHARES=""
  if [ -f "$SMB_CONF" ]; then
    EXISTING_SHARES=$(awk '/^\[.+\]$/ && !/^\[global\]$/ {p=1} p' "$SMB_CONF")
  fi

  log_action "Creating hardened smb.conf"
  cat > "$SMB_CONF" <<'EOF'
# === CyberPatriot Samba Security Hardening ===

[global]
# Basic Settings
workgroup = WORKGROUP
server string = Samba Server %v
netbios name = FILESERVER

# CRITICAL: Protocol Security - Disable SMBv1 (WannaCry protection)
server min protocol = SMB2
client min protocol = SMB2
server max protocol = SMB3

# CRITICAL: Encryption - Require for all connections
smb encrypt = required

# CRITICAL: Authentication
security = user
map to guest = never
guest account = nobody
ntlm auth = disabled
lanman auth = no
encrypt passwords = yes
passdb backend = tdbsam

# CRITICAL: SMB Signing - Prevent packet tampering
server signing = mandatory
client signing = mandatory

# CRITICAL: Anonymous Access Prevention
restrict anonymous = 2
null passwords = no

# Network Access Control
hosts allow = 127.0.0.1 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12
hosts deny = 0.0.0.0/0

# Logging
log level = 2
log file = /var/log/samba/log.%m
max log size = 1000

# Auditing
vfs objects = acl_xattr full_audit
full_audit:prefix = %u|%I|%m|%S
full_audit:failure = connect
full_audit:success = connect disconnect opendir mkdir rmdir open close read write rename unlink chmod chown

# Connection Limits
max connections = 100
deadtime = 15
socket options = TCP_NODELAY IPTOS_LOWDELAY

# Disable Printer Sharing
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes

# Disable Master Browser
domain master = no
local master = no
preferred master = no
wins support = no
dns proxy = no

# File System
use sendfile = yes
map acl inherit = yes
store dos attributes = yes

EOF

  if [ -n "$EXISTING_SHARES" ]; then
    log_action "Restoring existing share definitions"
    echo "" >> "$SMB_CONF"
    echo "# === Existing Shares ===" >> "$SMB_CONF"
    echo "$EXISTING_SHARES" >> "$SMB_CONF"
  fi

  cat >> "$SMB_CONF" <<'EOF'

# === Secure Share Template (Example) ===
# [secure_share]
# comment = Secure File Share
# path = /srv/samba/secure_share
# browseable = no
# guest ok = no
# read only = yes
# write list = @samba_admins
# valid users = @samba_users
# create mask = 0660
# directory mask = 2770
# force group = samba_users
EOF

  log_action "Securing Samba file permissions"
  chown root:root "$SMB_CONF"
  chmod 644 "$SMB_CONF"

  if [ -d /etc/samba ]; then
    chown -R root:root /etc/samba
    chmod 755 /etc/samba
  fi

  if [ -d /var/lib/samba/private ]; then
    chmod 700 /var/lib/samba/private
    chown root:root /var/lib/samba/private
    log_action "Secured /var/lib/samba/private (700)"
  fi

  log_action "Creating samba_users group"
  if ! getent group samba_users &>/dev/null; then
    groupadd samba_users
    log_action "Created 'samba_users' group"
  else
    log_action "Group 'samba_users' already exists"
  fi

  log_action "Validating Samba configuration"
  if command -v testparm &>/dev/null; then
    if testparm -s "$SMB_CONF" &>/dev/null; then
      log_action "Samba configuration is valid"
    else
      log_action "WARNING: Samba configuration has errors"
      testparm -s "$SMB_CONF" 2>&1 | head -20
    fi
  fi

  log_action "Restarting Samba services"
  local RESTARTED=0
  if systemctl is-active smbd &>/dev/null || systemctl is-enabled smbd &>/dev/null; then
    systemctl restart smbd 2>/dev/null && RESTARTED=1 && log_action "Restarted smbd"
  fi
  if systemctl is-active nmbd &>/dev/null || systemctl is-enabled nmbd &>/dev/null; then
    systemctl restart nmbd 2>/dev/null && log_action "Restarted nmbd"
  fi
  if systemctl is-active samba &>/dev/null || systemctl is-enabled samba &>/dev/null; then
    systemctl restart samba 2>/dev/null && RESTARTED=1 && log_action "Restarted samba"
  fi

  if [ "$RESTARTED" -eq 0 ]; then
    log_action "Samba services not running, changes apply on next start"
  fi

  log_action "Samba hardening complete"
  log_action "Security applied: SMBv1 disabled, encryption required, guest disabled, NTLMv1 disabled, signing mandatory"
  log_action "Next steps: Add users with 'smbpasswd -a <user>' and 'usermod -aG samba_users <user>'"
}
# Main runner
run_samba_hardening() {
    log_section "Starting Samba Hardening"
    harden_samba
    log_success "Samba Hardening completed"
}

export -f run_samba_hardening
