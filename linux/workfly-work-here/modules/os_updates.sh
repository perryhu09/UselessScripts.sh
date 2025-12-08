#!/bin/bash
# os_updates.sh - Operating System Updates

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Operating System Updates
# Category: System Updates
# Description: Operating System Updates

    log_action "=== ENSURING SECURITY UPDATE REPOSITORIES ARE ENABLED ==="

    sed -i 's/^#\(.*-security.*\)/\1/' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null

    CODENAME="$(lsb_release -sc)"
    if ! grep -Rq "${CODENAME}-security" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        echo "deb http://archive.ubuntu.com/ubuntu ${CODENAME}-security main restricted universe multiverse" | tee -a /etc/apt/sources.list >/dev/null
        log_action "Added missing security repo for ${CODENAME}"
    fi
    
    log_action "Security update repos ensured"
}

configure_automatic_updates() {
  log_action "=== CONFIGURING AUTOMATIC UPDATES ==="

  DEBIAN_FRONTEND=noninteractive apt-get update -y -qq &>/dev/null

  # Install unattended updates
  if ! dpkg -l | grep -q unattended-upgrades; then
    apt install -y unattended-upgrades apt-listchanges &>/dev/null
    log_action "Installed unattended-upgrades"
  fi

  # Enable automatic updates
  echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections &>/dev/null
  dpkg-reconfigure -f noninteractive unattended-upgrades &>/dev/null
  log_action "Enabled unattended-upgrades"

  backup_file /etc/apt/apt.conf.d/20auto-upgrades

  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
  log_action "Configured daily automatic updates"

  local unattended_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
  touch "$unattended_conf"
  grep -q "Remove-Unused-Kernel-Packages" "$unattended_conf" || echo 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";' >> "$unattended_conf"
  grep -q "Remove-Unused-Dependencies" "$unattended_conf" || echo 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' >> "$unattended_conf"
  log_action "Configured automatic cleanup policy"

  systemctl enable apt-daily.timer &>/dev/null
  systemctl start apt-daily.timer &>/dev/null
  systemctl enable apt-daily-upgrade.timer &>/dev/null
  systemctl start apt-daily-upgrade.timer &>/dev/null

  if systemctl is-active --quiet apt-daily.timer && systemctl is-active --quiet apt-daily-upgrade.timer; then
      log_action "APT update timers active"
  else
      log_action "WARNING: APT timers may not be active"
  fi
}

update_system() {
  log_action "=== UPDATING SYSTEM PACKAGES ==="

  enable_security_updates

  # Kill any apt processes
  pkill -9 apt &>/dev/null || true
  pkill -9 apt-get &>/dev/null || true
  pkill -9 dpkg &>/dev/null || true
  sleep 1

  # Remove lock files 
  rm -f /var/lib/dpkg/lock-frontend &>/dev/null || true
  rm -f /var/lib/dpkg/lock &>/dev/null || true
  rm -f /var/cache/apt/archives/lock &>/dev/null || true

  DEBIAN_FRONTEND=noninteractive apt update -y -qq &>/dev/null
  log_action "Updated package lists"

  DEBIAN_FRONTEND=noninteractive apt full-upgrade -y -qq \
    -o Dpkg::Options::="--force-confold" \
    -o Dpkg::Options::="--force-confdef" \
    &>/dev/null
  log_action "Performed full system upgrade"

  apt autoremove -y -qq &>/dev/null
  log_action "Removed unnecessary packages"

  apt autoclean -y -qq &>/dev/null
  log_action "Cleaned package cache"

  if [[ -f /var/run/reboot-required ]]; then
      log_action "*** REBOOT REQUIRED to complete updates ***"
  fi

  local remaining=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || echo "0")
  log_action "Remaining upgradeable packages: $remaining"
}

install_security_dependencies() {
  log_action "=== INSTALLING REQUIRED SECURITY TOOLS ==="

  local packages=(curl jq debsums) # TODO: ADD MORE
  local missing=()

  for pkg in "${packages[@]}"; do
    if ! command -v "$pkg" &>/dev/null; then
      missing+=("$pkg")
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    log_action "All required security tools already installed"
    return 0
  fi

  log_action "Installing missing packages: ${missing[*]}"
  
  if ! apt-get update -qq 2>/dev/null; then
    log_action "WARNING: apt-get update failed, attempting installation anyway"
  fi

  for pkg in "${missing[@]}"; do
    if apt-get install -y "$pkg" >/dev/null 2>&1; then
      log_action "✓ Installed $pkg"
    else
      log_action "⚠ WARNING: Failed to install $pkg"
    fi
  done
}

# Main runner
run_os_updates() {
    log_section "Starting OS Updates and Security Patches"
    configure_automatic_updates
    update_system
    install_security_dependencies
    log_success "OS Updates and Security Patches completed"
}

export -f run_os_updates