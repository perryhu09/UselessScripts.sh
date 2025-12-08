#!/bin/bash
# os_settings.sh - OS Security Settings (Network & Firewall)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: OS Settings
# Category: OS Security
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

harden_kernel_sysctl() {
  log_action "=== HARDENING KERNEL VIA SYSCTL ==="

  backup_file /etc/sysctl.conf

  cat > /etc/sysctl.conf <<'EOF'
##### KERNEL HARDENING
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.perf_event_max_sample_rate = 1
kernel.perf_cpu_time_max_percent = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.unprivileged_bpf_disabled = 1
kernel.ftrace_enabled = 0
kernel.debugfs.restrict = 1
kernel.yama.ptrace_scope = 3
kernel.panic_on_oops = 1
kernel.maps_protect = 1
kernel.core_uses_pid = 1
kernel.pid_max = 65536
dev.tty.ldisc_autoload = 0

##### MEMORY SAFETY
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.file-max = 65535
vm.unprivileged_userfaultfd = 0
vm.mmap_min_addr = 65536

##### DISABLE FORWARDING
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

##### DISABLE IPV6 ENTIRELY
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

##### SOURCE ROUTING & REDIRECTS
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

##### REVERSE PATH FILTERING
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

##### ARP HARDENING
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.default.arp_ignore = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

##### ICMP HYGIENE
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

##### TCP HARDENING
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fastopen = 0
net.ipv4.tcp_max_syn_backlog = 2048

##### TCP PERFORMANCE (OPTIONAL)
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
net.ipv4.ip_local_port_range = 2000 65000
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000

##### LOGGING
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

##### IPV6 RA/AUTOCONF (STRICT IF IPV6 ENABLED)
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1

##### BOOTP/ARP PROXIES
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.proxy_arp = 0

##### eBPF HARDENING
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2

##### BRIDGING (ONLY IF br_netfilter IS LOADED)
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1
EOF

  log_action "Applied comprehensive hardening settings to /etc/sysctl.conf"
  log_action "Applying settings with sysctl -p..."
  
  sysctl -p 2>&1 | tee -a "$LOG_FILE" | while IFS= read -r line; do
    if echo "$line" | grep -qE "No such file|cannot stat|error"; then
      log_action "  INFO: $line (some parameters may not exist on this kernel)"
    fi
  done

  if [ ${PIPESTATUS[0]} -eq 0 ]; then
    log_action "Sysctl hardening applied successfully"
  else
    log_action "WARNING: Some settings may have failed (check log)"
  fi

  log_action "Kernel hardening complete"
}

verify_sysctl_settings() {
  log_action "=== VERIFYING SYSCTL SECURITY SETTINGS ==="

  local checks_passed=0
  local checks_failed=0

  declare -A critical_checks=(
    ["kernel.randomize_va_space"]="2"
    ["kernel.sysrq"]="0"
    ["kernel.kptr_restrict"]="2"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.unprivileged_userns_clone"]="0"
    ["kernel.unprivileged_bpf_disabled"]="1"
    ["kernel.yama.ptrace_scope"]="3"
    ["fs.suid_dumpable"]="0"
    ["fs.protected_hardlinks"]="1"
    ["fs.protected_symlinks"]="1"
    ["fs.protected_fifos"]="2"
    ["fs.protected_regular"]="2"
    ["vm.mmap_min_addr"]="65536"
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.all.rp_filter"]="2"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.conf.all.arp_ignore"]="2"
    ["net.ipv4.conf.all.arp_announce"]="2"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.tcp_syn_retries"]="2"
    ["net.ipv4.tcp_synack_retries"]="2"
    ["net.ipv4.tcp_rfc1337"]="1"
    ["net.ipv4.tcp_timestamps"]="0"
    ["net.ipv4.icmp_echo_ignore_all"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
    ["net.ipv6.conf.all.disable_ipv6"]="1"
    ["net.core.bpf_jit_harden"]="2"
  )

  log_action "Checking critical security parameters..."
  log_action ""

  for param in "${!critical_checks[@]}"; do
    local expected="${critical_checks[$param]}"
    local actual
    actual=$(sysctl -n "$param" 2>/dev/null)

    if [[ -z "$actual" ]]; then
      log_action "  ⚠ $param = NOT AVAILABLE (parameter doesn't exist on this kernel)"
      checks_failed=$((checks_failed + 1))
    elif [[ "$actual" == "$expected" ]]; then
      log_action "  ✓ $param = $actual"
      checks_passed=$((checks_passed + 1))
    else
      log_action "  ✗ $param = $actual (expected: $expected)"
      checks_failed=$((checks_failed + 1))
    fi
  done

  log_action ""
  log_action "Verification Summary:"
  log_action "  Checks passed: $checks_passed"
  log_action "  Checks failed: $checks_failed"

  if [[ $checks_failed -eq 0 ]]; then
    log_action "All critical security settings verified successfully!"
  else
    log_action "WARNING: Some security settings failed verification"
    log_action "Review the failed checks above. Some may not be available on your kernel version."
  fi

  return 0
}

harden_grub() {
  log_action "=== HARDENING GRUB BOOTLOADER ==="

  # perms
  log_action "Securing GRUB configuration files..."
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
      backup_file "$grub_file"
      chown root:root "$grub_file" &>/dev/null
      chmod 600 "$grub_file" &>/dev/null
      log_action "Secured $grub_file (600, root:root)"
    fi
  done

  log_action "Enforcing GRUB signature verification..."
  local grub_default="/etc/default/grub"
  local grub_custom="/etc/grub.d/40_custom"
  local needs_update=false

  if [[ -f "$grub_default" ]]; then
    backup_file "$grub_default"

    if grep -q "^GRUB_VERIFY_SIGNATURES" "$grub_default"; then
      sed -i 's/^GRUB_VERIFY_SIGNATURES=.*/GRUB_VERIFY_SIGNATURES=true/' "$grub_default"
    else
      echo 'GRUB_VERIFY_SIGNATURES=true' >> "$grub_default"
    fi
    needs_update=true
    log_action "Enabled GRUB_VERIFY_SIGNATURES in $grub_default"
  fi

  if [[ -f "$grub_custom" ]]; then
    backup_file "$grub_custom"

    local temp_file=$(mktemp)
    local removed_insecure=false

    while IFS= read -r line; do
      if [[ "$line" =~ ^set[[:space:]]+superusers || "$line" =~ ^password ]]; then
        removed_insecure=true
        continue
      fi
      echo "$line" >> "$temp_file"
    done < "$grub_custom"

    if ! grep -q "^set check_signatures" "$temp_file"; then
      echo "set check_signatures=enforce" >> "$temp_file"
    fi

    cat "$temp_file" > "$grub_custom"
    rm -f "$temp_file"

    [[ "$removed_insecure" == true ]] && log_action "Removed insecure superuser entries from $grub_custom"
    needs_update=true
  fi

  if [[ "$needs_update" == true ]] && command -v update-grub &>/dev/null; then
    update-grub &>/dev/null && log_action "Regenerated GRUB configuration"
  fi

  # NEED MANUALLY SET GRUB PASSWORD
  if [[ ! -f /etc/grub.d/01_password ]]; then
    log_action "GRUB password not configured. Manual steps required:"
    log_action "  1. sudo grub-mkpasswd-pbkdf2"
    log_action "  2. Create /etc/grub.d/01_password containing:"
    log_action "     set superusers=\"admin\""
    log_action "     password_pbkdf2 admin <YOUR_HASH>"
    log_action "  3. sudo chmod 600 /etc/grub.d/01_password"
    log_action "  4. sudo update-grub"
  else
    log_action "GRUB password configuration exists at /etc/grub.d/01_password"
  fi

  log_action "GRUB hardening complete"
}

remove_rbash() {
  log_action "=== REMOVING RESTRICTED BASH ARTIFACTS ==="

  local targets=("/usr/bin/rbash" "/usr/share/doc/bash/RBASH")
  local removed=0

  for target in "${targets[@]}"; do
    if [[ -e "$target" ]]; then
      rm -rf "$target" &>/dev/null && ((removed++))
      log_action "Removed: $target"
    fi
  done

  [[ $removed -eq 0 ]] && log_action "No restricted bash artifacts found"
}

# 027 file permission for new files
enforce_umask() {
  log_action "=== ENFORCING SECURE UMASK ==="

  local login_defs="/etc/login.defs"

  if [[ -f "$login_defs" ]]; then
    backup_file "$login_defs"
    if grep -qE "^\s*UMASK" "$login_defs"; then
      sed -i 's/^\s*UMASK.*/UMASK 027/' "$login_defs"
    else
      echo "UMASK 027" >> "$login_defs"
    fi
    log_action "Set UMASK to 027 in $login_defs"
  fi

  for profile in /etc/profile /etc/bash.bashrc; do
    if [[ -f "$profile" ]] && ! grep -q "^umask 027" "$profile"; then
      echo "umask 027" >> "$profile"
      log_action "Added umask 027 to $profile"
    fi
  done
}

secure_home_directories() {
  log_action "=== SECURING HOME DIRECTORY PERMISSIONS ==="

  local adjusted=0

  for dir in /home/*; do
    [[ -d "$dir" ]] || continue
    local current_perm=$(stat -c "%a" "$dir" 2>/dev/null)

    if [[ "$current_perm" -gt 750 ]]; then
      chmod 750 "$dir" &>/dev/null
      ((adjusted++))
      log_action "Tightened $dir: $current_perm -> 750"
    fi
  done

  [[ $adjusted -eq 0 ]] && log_action "All home directories already secure"
}

# secure /tmp and /dev/shm
secure_tmp_mount() {
  log_action "=== SECURING /tmp MOUNT ==="

  [[ -d /tmp ]] && chmod 1777 /tmp &>/dev/null && log_action "Set /tmp sticky bit (1777)"

  if [[ -L /tmp ]]; then
    log_action "/tmp is a symlink, skipping mount unit"
    return 0
  fi

  if ! command -v systemctl &>/dev/null; then
    log_action "systemctl not available, skipping tmp.mount"
    return 0
  fi

  local tmp_mount="/etc/systemd/system/tmp.mount"
  [[ -f "$tmp_mount" ]] && backup_file "$tmp_mount"

  cat > "$tmp_mount" <<'EOF'
[Unit]
Description=Temporary Directory (/tmp)
Documentation=man:hier(7)
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec

[Install]
WantedBy=local-fs.target
EOF

  systemctl daemon-reload &>/dev/null
  systemctl enable tmp.mount &>/dev/null
  systemctl start tmp.mount &>/dev/null && log_action "Created and started secure tmp.mount" || log_action "tmp.mount enabled (applies on reboot)"
}

secure_dev_shm() {
  log_action "=== SECURING /dev/shm ==="

  backup_file /etc/fstab

  if grep -qE '^\s*tmpfs\s+/dev/shm\s+tmpfs' /etc/fstab; then
    sed -i 's|^\s*tmpfs\s\+/dev/shm\s\+tmpfs\s\+.*|tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0|' /etc/fstab
    log_action "Updated /dev/shm entry in /etc/fstab"
  else
    echo 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
    log_action "Added /dev/shm to /etc/fstab"
  fi

  mount -o remount,noexec,nosuid,nodev /dev/shm &>/dev/null && log_action "Remounted /dev/shm with secure options"
  chmod 1777 /dev/shm &>/dev/null
}

# locks doen /proc with hidepid=2 (user can only see their own processes)
setup_proc_hidepid() {
  log_action "=== CONFIGURING /proc PROCESS HIDING ==="

  if ! getent group proc &>/dev/null; then
    groupadd -f proc &>/dev/null
    log_action "Created 'proc' group"
  fi

  local proc_gid=$(getent group proc | cut -d: -f3)

  backup_file /etc/fstab

  if grep -qE '^\s*proc\s+/proc\s+proc' /etc/fstab; then
    sed -i "s|^\s*proc\s\+/proc\s\+proc\s\+.*|proc /proc proc defaults,hidepid=2,gid=$proc_gid 0 0|" /etc/fstab
    log_action "Updated /proc entry in /etc/fstab"
  else
    echo "proc /proc proc defaults,hidepid=2,gid=$proc_gid 0 0" >> /etc/fstab
    log_action "Added /proc to /etc/fstab"
  fi

  mount -o remount,hidepid=2,gid="$proc_gid" /proc &>/dev/null && log_action "Remounted /proc with hidepid=2"
  log_action "Add admins to 'proc' group: usermod -aG proc <user>"
}

configure_host_conf() {
  log_action "=== CONFIGURING /etc/host.conf ==="

  local host_conf="/etc/host.conf"
  [[ -f "$host_conf" ]] && backup_file "$host_conf"

  cat > "$host_conf" <<'EOF'
order bind,hosts
multi on
nospoof on
EOF

  chown root:root "$host_conf" &>/dev/null
  chmod 644 "$host_conf" &>/dev/null
  log_action "Configured anti-spoofing in $host_conf"
}

configure_screen_security() {
  log_action "=== CONFIGURING SCREEN TIMEOUT AND LOCKING ==="

  local dconf_dir="/etc/dconf/db/local.d"
  local lock_dir="/etc/dconf/db/local.d/locks"

  mkdir -p "$dconf_dir" "$lock_dir"

  cat > "$dconf_dir/00-cyberpatriot-screen" <<'EOF'
[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/desktop/screensaver]
idle-activation-enabled=true
lock-delay=uint32 0
lock-enabled=true

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-type='suspend'
sleep-inactive-ac-timeout=1800
sleep-inactive-battery-type='suspend'
sleep-inactive-battery-timeout=1200
power-button-action='interactive'

[org/cinnamon/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/screensaver]
idle-activation-enabled=true
lock-delay=uint32 0
lock-enabled=true

[org/cinnamon/settings-daemon/plugins/power]
sleep-inactive-ac-type='suspend'
sleep-inactive-ac-timeout=1800
sleep-inactive-battery-type='suspend'
sleep-inactive-battery-timeout=1200
power-button-action='interactive'
EOF

  cat > "$lock_dir/00-cyberpatriot-screen" <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
/org/gnome/settings-daemon/plugins/power/power-button-action
/org/cinnamon/desktop/session/idle-delay
/org/cinnamon/desktop/screensaver/idle-activation-enabled
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-battery-type
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-battery-timeout
/org/cinnamon/settings-daemon/plugins/power/power-button-action
EOF

  command -v dconf &>/dev/null && dconf update &>/dev/null && log_action "Applied screen timeout/locking policies"
}

disable_xserver_tcp() {
  log_action "=== DISABLING X SERVER TCP CONNECTIONS ==="

  local configs_created=0

  mkdir -p /etc/X11/xorg.conf.d
  cat > /etc/X11/xorg.conf.d/10-nolisten.conf <<'EOF'
Section "ServerFlags"
    Option "DisallowTCP" "true"
EndSection
EOF
  ((configs_created++))
  log_action "Created /etc/X11/xorg.conf.d/10-nolisten.conf"

  if [[ -f /etc/gdm3/custom.conf ]]; then
    backup_file /etc/gdm3/custom.conf
    if grep -q "^DisallowTCP=" /etc/gdm3/custom.conf; then
      sed -i 's/^DisallowTCP=.*/DisallowTCP=true/' /etc/gdm3/custom.conf
    elif grep -q "^\[security\]" /etc/gdm3/custom.conf; then
      sed -i '/^\[security\]/a DisallowTCP=true' /etc/gdm3/custom.conf
    else
      echo -e "\n[security]\nDisallowTCP=true" >> /etc/gdm3/custom.conf
    fi
    ((configs_created++))
    log_action "Configured GDM3 to disable TCP"
  fi

  if [[ -f /etc/lightdm/lightdm.conf ]] || [[ -d /etc/lightdm/lightdm.conf.d ]]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/50-nolisten.conf <<'EOF'
[Seat:*]
xserver-allow-tcp=false
EOF
    ((configs_created++))
    log_action "Configured LightDM to disable TCP"
  fi

  log_action "X Server TCP disabled in $configs_created config(s)"
}

validate_gdm3_config() {
  log_action "=== VALIDATING GDM3 USER CONFIGURATION ==="

  local gdm_custom="/etc/gdm3/custom.conf"
  local gdm_dropin="/etc/systemd/system/gdm.service.d"
  local sanitized=false

  if [[ -f "$gdm_custom" ]]; then
    backup_file "$gdm_custom"
    if grep -q "^User=" "$gdm_custom"; then
      sed -i '/^User=/d' "$gdm_custom"
      sanitized=true
    fi
    if grep -q "^Group=" "$gdm_custom"; then
      sed -i '/^Group=/d' "$gdm_custom"
      sanitized=true
    fi
  fi

  if [[ -d "$gdm_dropin" ]]; then
    for file in "$gdm_dropin"/*.conf; do
      [[ -f "$file" ]] || continue
      backup_file "$file"
      if grep -q "^User=" "$file"; then
        sed -i '/^User=/d' "$file"
        sanitized=true
      fi
      if grep -q "^Group=" "$file"; then
        sed -i '/^Group=/d' "$file"
        sanitized=true
      fi
    done
  fi

  if [[ "$sanitized" == true ]]; then
    command -v systemctl &>/dev/null && systemctl daemon-reload &>/dev/null
    log_action "Removed custom user/group overrides for GDM3"
  else
    log_action "No problematic GDM3 configuration found"
  fi
}

configure_firewall() {
  log_action "=== CONFIGURING ENHANCED UFW FIREWALL ==="

  if ! command -v ufw &>/dev/null; then
    log_action "UFW not found, installing..."
    apt-get install -y ufw &>/dev/null
    log_action "UFW installed"
  else
    log_action "UFW already installed"
  fi

  log_action "Setting UFW default policies..."
  ufw default deny incoming >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  ufw default deny routed >/dev/null 2>&1
  log_action "Default policies: deny incoming, allow outgoing, deny routed"

  log_action "Configuring loopback rules (CIS Benchmark)..."
  ufw allow in on lo >/dev/null 2>&1
  ufw allow out on lo >/dev/null 2>&1
  ufw deny in from 127.0.0.0/8 >/dev/null 2>&1
  ufw deny in from ::1 >/dev/null 2>&1
  log_action "Loopback protection configured"

  log_action "Configuring SSH rate limiting..."
  ufw --force delete allow 22/tcp >/dev/null 2>&1
  ufw --force delete allow ssh >/dev/null 2>&1
  ufw limit 22/tcp >/dev/null 2>&1
  log_action "SSH rate limiting enabled (blocks brute-force attacks)"

  log_action "Setting UFW logging to high..."
  ufw logging high >/dev/null 2>&1

  if [[ -f /etc/default/ufw ]]; then
    if ! grep -q "^IPV6=yes" /etc/default/ufw; then
      sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw 2>/dev/null || echo "IPV6=yes" >> /etc/default/ufw
      log_action "Enabled IPv6 support in UFW"
    fi
  fi

  log_action "Denying unnecessary ports..."
  local unnecessary_ports=("21/tcp" "23/tcp" "25/tcp" "80/tcp" "110/tcp" "143/tcp" "445/tcp" "3389/tcp" "1900/udp")
  
  for port_proto in "${unnecessary_ports[@]}"; do
    local port="${port_proto%/*}"
    local proto="${port_proto#*/}"
    
    local in_use=false
    if command -v ss &>/dev/null; then
      if ss -lntu | awk -v p="$port" -v proto="$proto" '$1 == proto && $5 ~ (":" p "$")' | grep -q .; then
        in_use=true
      fi
    fi

    if [[ "$in_use" == true ]]; then
      log_action "Port $port_proto is in use, skipping deny rule"
    else
      if ! ufw status | grep -q "DENY[[:space:]]\+$port_proto"; then
        ufw deny "$port_proto" >/dev/null 2>&1
        log_action "Denied unused port $port_proto"
      fi
    fi
  done

  log_action "Enabling UFW..."
  echo "y" | ufw enable >/dev/null 2>&1
  
  if command -v systemctl &>/dev/null; then
    systemctl enable ufw >/dev/null 2>&1
  fi

  log_action "Verifying UFW configuration..."
  local status_output=$(ufw status verbose 2>/dev/null)
  
  if echo "$status_output" | grep -q "Status: active"; then
    log_action "UFW is active"
  else
    log_action "WARNING: UFW may not be active"
  fi

  if echo "$status_output" | grep -q "deny (incoming)"; then
    log_action "Default incoming: deny"
  fi

  if echo "$status_output" | grep -q "allow (outgoing)"; then
    log_action "Default outgoing: allow"
  fi

  log_action "Firewall configuration complete"
}
# Main runner
run_os_settings() {
    log_section "Starting OS Settings Module"

    fix_hosts_file
    harden_ssh
    configure_firewall

    log_success "OS Settings completed"
}

export -f run_os_settings
