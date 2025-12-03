#!/usr/bin/env bash

# Written by: Dominic Hu, Naren Pai, Victor Zhou

#===============================================
# Configuration && Setup
#===============================================
# MANUALLY enter based on README for each image

# Authorized Users
AUTHORIZED_USERS=()

# Users with admin/sudo privileges
ADMIN_USERS=()

#===============================================
# Utility Functions
#===============================================
# Set up log directory and file
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
#===============================================
# Pre-Flight Checklist
#===============================================
preflight_check() {
  echo "==============================================="
  echo " HARDENING SCRIPT PRE-FLIGHT CHECK"
  echo "==============================================="
  echo ""
  echo "WARNING: If not configured properly, this script will cause DESTRUCTIVE changes to your system!!!"
  echo ""
  echo "PRE-FLIGHT CHECKLIST - Have you completed ALL of these?"
  echo "[] 1. Read the README and take notes"
  echo "[] 2. Identified and added all AUTHORIZED_USERS from the README"
  echo "[] 3. Identified and added all ADMIN_USERS (sudo) from the README"
  echo "[] 4. Check the spelling for two lists above. (MUST DO THIS!!!! DUMBAHH CANT SPELL)"
  echo "[] 5. Remove any required services from the README in service_blacklist.txt"
  echo "[] 6. Remove any required packages from the README in packages_blacklist.txt"
  echo ""
  echo "This script is mint_hardening.sh, it is supposed to be run on LINUX MINT"
  echo ""
  read -p "Have you completed ALL items on the checklist above? (print initials)" confirm1
  if [[ ! "$confirm1" == "DH" ]]; then
    echo ""
    echo "Preflight check failed, complete the checklist before running this script"
    echo "Edit the script and configure the AUTHORIZED_USERS and ADMIN_USERS arrays."
    exit 1
  fi
  echo ""
  echo "FINAL WARNING: Are you sure that you have completed everything in the checklist?"
  echo ""
  read -p "Type 'I UNDERSTAND' to proceed: " confirm2
  if [[ "$confirm2" != "I UNDERSTAND" ]]; then
      echo ""
      echo "Confirmation failed. Exiting for safety"
      exit 1
  fi
}

#===============================================
# System Updates
#===============================================

enable_security_updates() {
    log_action "=== ENSURING SECURITY UPDATE REPOSITORIES ARE ENABLED ==="
    sed -i 's/^#\(.*-security.*\)/\1/' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null

    CODENAME="$(lsb_release -sc)"
    if ! grep -Rq "${CODENAME}-security" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        echo "deb http://archive.ubuntu.com/ubuntu ${CODENAME}-security main restricted universe multiverse" | tee -a /etc/apt/sources.list >/dev/null
        log_action "Added missing security repo for ${CODENAME}"
    fi
    
    log_action "Security update repos ensured"
}

enable_auto_update_refresh() {
    log_action "=== ENABLING AUTOMATIC UPDATE REFRESH ==="

    USERNAME=$(ls /home | head -n 1)
    USERPATH="/com/linuxmint/${USERNAME}" #is this right for all linux mint images?

    apt-get update -y
    apt-get install -y dconf-cli

    sudo -u "$USERNAME" dconf write "${USERPATH}/refresh-schedule-enabled" true
    sudo -u "$USERNAME" dconf write "${USERPATH}/refresh-schedule-id" "'DAILY_MNT'"

    gsettings set org.cinnamon.updates refresh-package-lists true
    gsettings set org.cinnamon.updates refresh-frequency 1  # 1 = Daily

    systemctl enable --now apt-daily.timer &>/dev/null
    systemctl enable --now apt-daily-upgrade.timer &>/dev/null

    log_action "Automatic update refresh enabled"
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
}

configure_automatic_updates() {
  log_action "=== CONFIGURING AUTOMATIC UPDATES ==="

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
}

#===============================================
# Users && Groups
#===============================================

remove_unauthorized_users() {
  log_action "=== CHECKING FOR UNAUTHORIZED USERS ==="

  CURRENT_USERS=$(awk -F: '($3 >=1000 || $3 == 0) && $1 != "nobody" {print $1}' /etc/passwd)
  for user in $CURRENT_USERS; do
    if [ "$user" = "root" ]; then
      continue
    fi

    if [[ " ${ADMIN_USERS[@]} " =~ "${user}" ]]; then
      log_action "Skipping admin user: $user"
      continue
    fi

    if [[ " ${AUTHORIZED_USERS[@]} " =~ "${user}" ]]; then
      continue
    fi

    log_action "FOUND UNAUTHORIZED USER: $user - Removing ..."
    userdel -r "$user" 2>/dev/null
    if [ $? -eq 0 ]; then
      log_action "Successfully removed user: $user"
    else
      log_action "Failed to remove user: $user (CHECK MANUALLY)"
    fi
  done
}

fix_admin_group() {
  log_action "=== FIXING SUDO GROUP MEMBERSHIP ==="

  # ADMIN - older ubuntu versions used admin group, included for compatibility

  SUDO_MEMBERS=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
  ADMIN_MEMBERS=$(getent group admin 2>/dev/null | cut -d: -f4 | tr ',' ' ')

  # Remove unauthorized users from sudo group
  for user in $SUDO_MEMBERS; do
    if [[ ! "${ADMIN_USERS[@]}" =~ "${user}" ]]; then
      log_action "Removing $user from sudo group"
      deluser "$user" sudo &>/dev/null
    fi
  done

  # Check if admin group exists (then remove)
  if getent group admin >/dev/null 2>&1; then
    for user in $ADMIN_MEMBERS; do
      if [[ ! "${ADMIN_USERS[@]}" =~ "${user}" ]]; then
        log_action "Removing $user from admin group"
        deluser "$user" admin &>/dev/null
      fi
    done
  fi

  # Add authorized admin users to sudo group
  for user in "${ADMIN_USERS[@]}"; do
    if id "$user" &>/dev/null; then
      usermod -aG sudo "$user" &>/dev/null
      log_action "Added $user to sudo group"
    fi
  done
}

check_uid_zero() {
  log_action "=== CHECKING FOR UNAUTHORIZED UID 0 ACCOUNTS ==="

  UID_ZERO=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

  if [ -n "$UID_ZERO" ]; then
    for user in $UID_ZERO; do
      log_action "WARNING: Found UID 0 account: $user - Removing..."
      userdel -r "$user" 2>/dev/null
    done
  else
    log_action "No unauthorized UID 0 accounts found"
  fi
}

disable_guest() {
  log_action "=== DISABLING GUEST ACCOUNT ==="

  # LightDM 
  if [ -f /etc/lightdm/lightdm.conf ]; then
    backup_file /etc/lightdm/lightdm.conf

    if grep -q "^\[Seat:\*\]" /etc/lightdm/lightdm.conf; then
      sed -i '/^[#[:space:]]*allow-guest=/d' /etc/lightdm/lightdm.conf
      sed -i '/^\[Seat:\*\]/a allow-guest=false' /etc/lightdm/lightdm.conf
    else
      echo -e "\n[Seat:*]\nallow-guest=false" >> /etc/lightdm/lightdm.conf
    fi
    log_action "Disabled guest account in lightdm.conf"
  fi

  # Alternative LightDM config location
  if [ -d /etc/lightdm/lightdm.conf.d ]; then
    echo "[Seat:*]" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf
    echo "allow-guest=false" >> /etc/lightdm/lightdm.conf.d/50-no-guest.conf
    log_action "Created /etc/lightdm/lightdm.conf.d/50-no-guest.conf"
  fi

  # Update dconf database
  if command -v dconf &>/dev/null; then
    dconf update 2>/dev/null
    log_action "Updated dconf configuration database"
  fi

  # GDM3 Display Manager (if used in some Mint configurations)
  for gdm_conf in /etc/gdm3/custom.conf /etc/gdm/custom.conf; do
    if [ -f "$gdm_conf" ]; then
      backup_file "$gdm_conf"

      local dm_name="GDM3"
      [[ "$gdm_conf" == *"/gdm/"* ]] && dm_name="GDM"

      # Disable timed login
      if [[ "$gdm_conf" == *"/gdm3/"* ]]; then
        if grep -q "^TimedLoginEnable.*=.*true" "$gdm_conf"; then
          sed -i 's/^\(TimedLoginEnable.*=.*\)true/\1false/' "$gdm_conf"
          log_action "Disabled timed login in ${dm_name} (replaced true w/ false)"
        elif ! grep -q "^TimedLoginEnable.*=.*false" "$gdm_conf"; then
          if grep -q "^\[security\]" "$gdm_conf"; then
            sed -i '/^\[security\]/a TimedLoginEnable=false' "$gdm_conf"
          else
            echo -e "\n[security]\nTimedLoginEnable=false" >>"$gdm_conf"
          fi
          log_action "Disabled timed login in ${dm_name} (added new setting)"
        fi
      fi

      # Disable automatic login
      if grep -q "^AutomaticLoginEnable.*=.*true" "$gdm_conf"; then
        sed -i 's/^\(AutomaticLoginEnable.*=.*\)true/\1false/' "$gdm_conf"
        log_action "Disabled automatic login in ${dm_name} (replaced true with false)"
      elif ! grep -q "^AutomaticLoginEnable.*=.*false" "$gdm_conf"; then
        if grep -q "^\[daemon\]" "$gdm_conf"; then
          sed -i '/^\[daemon\]/a AutomaticLoginEnable=false' "$gdm_conf"
        else
          echo -e "\n[daemon]\nAutomaticLoginEnable=false" >>"$gdm_conf"
        fi
        log_action "Disabled automatic login in ${dm_name} (added new setting)"
      fi
    fi
  done

  log_action "Guest account disabling complete (reboot required to take effect)"
}

set_all_user_passwords() {
  log_action "=== SETTING ALL USER PASSWORDS ==="

  set +H # disable history expansion
  REGULAR_USERS=$(awk -F: '($3 >= 1000) && ($1 != "nobody") {print $1}' /etc/passwd)

  for user in $REGULAR_USERS; do
    printf '%s:%s\n' "$user" 'Cyb3rPatr!0t' | chpasswd --crypt-method SHA512
    log_action "Set password for user: $user"
  done

  log_action "All user passwords set to: Cyb3rPatr!0t"
}

lock_root_account() {
  log_action "=== LOCKING ROOT ACCOUNT ==="
  if id root &>/dev/null; then
    if passwd -l root &>/dev/null; then
      usermod -s /usr/sbin/nologin root
      log_action "Root password locked successfully."
    else
      log_action "ERROR: Failed to lock root password."
      return 1
    fi
  else
    log_action "Root account not found."
    return 1
  fi
}

#===============================================
# Password Policies
#===============================================

# remove nullok in /etc/pam.d/common-auth to disallow empty pwds
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
  if grep -q "^PASS_WARN_AGE" /etc/login.defs; then
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs &>/dev/null
  else
    echo "PASS_WARN_AGE   7" >>/etc/login.defs
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

#===============================================
# File Permissions
#===============================================

secure_file_permissions() {
  log_action "=== SECURING FILE PERMISSIONS ==="

  # Password & Authentication Files
  [ -f /etc/passwd ] && chmod 644 /etc/passwd && chown root:root /etc/passwd &>/dev/null
  [ -f /etc/shadow ] && chmod 640 /etc/shadow && chown root:shadow /etc/shadow &>/dev/null
  [ -f /etc/group ] && chmod 644 /etc/group && chown root:root /etc/group &>/dev/null
  [ -f /etc/gshadow ] && chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow &>/dev/null
  [ -f /etc/security/opasswd ] && chmod 600 /etc/security/opasswd && chown root:root /etc/security/opasswd &>/dev/null

  log_action "Secured password/auth files"

  # Boot files (GRUB)
  for grub_cfg in /boot/grub/grub.cfg /boot/grub/grub.conf /boot/grub2/grub.cfg; do
    if [ -f "$grub_cfg" ]; then
      chmod 600 "$grub_cfg" &>/dev/null
      chown root:root "$grub_cfg" &>/dev/null
      log_action "Secured $grub_cfg"
    fi
  done

  # SSH Configuration
  [ -f /etc/ssh/sshd_config ] && chmod 600 /etc/ssh/sshd_config &>/dev/null && chown root:root /etc/ssh/sshd_config
  [ -d /etc/ssh ] && chmod 755 /etc/ssh && chown root:root /etc/ssh
  log_action "Secured SSH configuration"

  # Sudoers
  [ -f /etc/sudoers ] && chmod 440 /etc/sudoers && chown root:root /etc/sudoers
  if [ -d /etc/sudoers.d ]; then
    chmod 755 /etc/sudoers.d
    find /etc/sudoers.d -type f -exec chmod 440 {} \; &>/dev/null
    find /etc/sudoers.d -type f -exec chown root:root {} \; &>/dev/null
    log_action "Secured /etc/sudoers and /etc/sudoers.d/*"
  fi

  # Cron files
  [ -f /etc/crontab ] && chmod 600 /etc/crontab && chown root:root /etc/crontab
  [ -d /etc/cron.d ] && find /etc/cron.d -type f -exec chmod 600 {} \;
  [ -d /var/spool/cron/crontabs ] && chmod 700 /var/spool/cron/crontabs
  log_action "Secured cron configurations"

  [ -d /root ] && chmod 700 /root && chown root:root /root
  log_action "Secured /root directory"

  # SSL private keys
  [ -d /etc/ssl/private ] && chmod 710 /etc/ssl/private && chown root:ssl-cert /etc/ssl/private
  log_action "Secured SSL private key directory"

  # FTP Root directory (vsftp)
  for ftp_root in /srv/ftp /var/ftp; do 
    if [ -d "$ftp_root"]; then
      chmod 755 "$ftp_root"
      chown root:ftp "$ftp_root"
      log_action "Secured FTP root directory: $ftp_root"
    fi 
  done

  log_action "File perms hardening complete"
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

#===============================================
# Network Security
#===============================================

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

  cat >>/etc/sysctl.conf <<'EOF'
fs.file-max = 65535
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.exec-shield = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.pid_max = 65536
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_wmem = 10240 87380 12582912
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 0

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# In case IPv6 is necessary
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
EOF

  log_action "Applied hardening settings to /etc/sysctl.conf..."
  log_action "Applying settings"
  sysctl -p &>/dev/null

  if [ $? -eq 0 ]; then
    log_action "Sysctl hardening applied successfully"
  else
    log_action "WARNING: Some settings may have failed"
    sysctl -p >>"$LOG_FILE" 2>&1
  fi

  log_action "Kernel hardening complete"
}

#===============================================
# Firewall
#===============================================

configure_firewall() {
  log_action "=== CONFIGURING UFW FIREWALL ==="

  # Remove iptables-persistent
  if dpkg -l | grep -q iptables-persistent; then
    apt purge -y iptables-persistent
    log_action "Removed iptables-persistent"
  fi

  ufw --force reset
  log_action "Reset UFW to defaults"

  # Loopback rules
  ufw allow in on lo
  ufw allow out on lo
  ufw deny in from 127.0.0.0/8
  ufw deny in from ::1
  log_action "Configured loopback rules"

  # Default policies
  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny routed
  log_action "Set default policies"

  ufw --force enable
  log_action "UFW enabled"

  log_action "Firewall configuration complete"
}

#===============================================
# Packages, Services, & Files
#===============================================

disable_unnecessary_services() {
  log_action "=== DISABLING UNNECESSARY SERVICES ==="

  local BLACKLIST_FILE="${1:-}"

  # If no file provided, skip this function
  if [[ -z "$BLACKLIST_FILE" ]]; then
    log_action "WARNING: No service blacklist file provided"
    log_action "Usage: disable_unnecessary_services <blacklist_file>"
    log_action "Skipping service disabling..."
    return 0
  fi

  # Check if file exists
  if [[ ! -f "$BLACKLIST_FILE" ]]; then
    log_action "ERROR: Service blacklist file not found: $BLACKLIST_FILE"
    return 1
  fi

  log_action "Reading prohibited services from: $BLACKLIST_FILE"

  # Read services from file (one per line, ignore comments and empty lines)
  local service_count=0
  local disabled_count=0

  while IFS= read -r service || [[ -n "$service" ]]; do
    # Skip empty lines and comments
    [[ -z "$service" || "$service" =~ ^[[:space:]]*# ]] && continue

    # Clean up whitespace
    service=$(echo "$service" | xargs)
    [[ -z "$service" ]] && continue

    ((service_count++))

    # Check if service exists
    if systemctl list-unit-files | grep -q "^${service}.service"; then
      if systemctl is-active --quiet "$service"; then
        log_action "Stopping and disabling: $service"
        systemctl stop "$service" &>/dev/null
        systemctl disable "$service" &>/dev/null
        ((disabled_count++))
        log_action "Stopped and disabled: $service"
      elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
        log_action "Disabling: $service"
        systemctl disable "$service" &>/dev/null
        ((disabled_count++))
        log_action "Disabled: $service"
      else
        log_action "Service $service is already disabled"
      fi
    else
      log_action "Service $service not found on system (skipping)"
    fi
  done <"$BLACKLIST_FILE"

  log_action "Processed $service_count services, disabled $disabled_count"
}

audit_running_services() {
  log_action "=== AUDITING RUNNING SERVICES ==="

  systemctl list-units --type=service --state=running --no-pager | grep "loaded active running" | awk '{print $1}' | while read service; do
    log_action "RUNNING: $service"
  done

  log_action "Perform manual review of log for services that shouldn't be running"
}

remove_unauthorized_software() {
  log_action "=== REMOVING UNAUTHORIZED SOFTWARE ==="

  local BLACKLIST_FILE="${1:-}"

  # If no file provided, skip this function
  if [[ -z "$BLACKLIST_FILE" ]]; then
    log_action "WARNING: No package blacklist file provided"
    log_action "Usage: remove_unauthorized_software <blacklist_file>"
    log_action "Skipping software removal..."
    return 0
  fi

  # Check if file exists
  if [[ ! -f "$BLACKLIST_FILE" ]]; then
    log_action "ERROR: Package blacklist file not found: $BLACKLIST_FILE"
    return 1
  fi

  log_action "Reading prohibited packages from: $BLACKLIST_FILE"

  # Read packages from file (one per line, ignore comments and empty lines)
  local package_count=0
  local removed_count=0

  while IFS= read -r package || [[ -n "$package" ]]; do
    # Skip empty lines and comments
    [[ -z "$package" || "$package" =~ ^[[:space:]]*# ]] && continue

    # Clean up whitespace
    package=$(echo "$package" | xargs)
    [[ -z "$package" ]] && continue

    ((package_count++))

    # Check if package is installed
    if dpkg -l 2>/dev/null | grep -q "^ii  $package "; then
      log_action "Removing package: $package"
      if apt purge -y "$package" &>/dev/null; then
        ((removed_count++))
        log_action "Successfully removed: $package"
      else
        log_action "Failed to remove: $package"
      fi
    else
      log_action "Package $package not installed (skipping)"
    fi
  done <"$BLACKLIST_FILE"

  # Clean up dependencies
  log_action "Cleaning up orphaned dependencies..."
  apt autoremove -y &>/dev/null

  log_action "Processed $package_count packages, removed $removed_count"
}

# Implement another function for auditing installed packages?

remove_prohibited_media() {
  log_action "=== SCANNING FOR PROHIBITED MEDIA FILES ==="

  MEDIA_EXTENSIONS=(
      # Audio formats
      "*.mp3"
      "*.ogg"
      "*.wav"
      "*.m4a"
      "*.aac"
      "*.wma"
      "*.flac"
      
      # Video formats
      "*.mp4"
      "*.avi"
      "*.mkv"
      "*.mov"
      "*.flv"
      "*.wmv"
      "*.webm"
      "*.mpeg"
      "*.mpg"
      "*.3gp"
      
      # Archive formats (for prohibited software)
      "*.zip"
      "*.tar"
      "*.tar.gz"
      "*.tgz"
      "*.rar"
      "*.7z"
      "*.bz2"
      "*.xz"
      
      # Image formats (sometimes prohibited)
      "*.jpg"
      "*.jpeg"
      "*.png"
      "*.gif"
      "*.bmp"
      "*.tiff"
      "*.webp"
      
      # Other suspicious files
      "*.flag"
      "*.torrent"
  )

  log_action "NOTE: MAKE SURE TO MANUALLY REVIEW THIS SECTION"
  log_action ""
  for ext in "${MEDIA_EXTENSIONS[@]}"; do
    find /home -type f -name "$ext" 2>/dev/null | while read file; do
      log_action "PROHIBITED MEDIA FOUND: $file"
      # rm -f "$file"
    done
  done

  log_action "Possible prohibited media found (NOT REMOVED)"
}

#===============================================
# Service Hardening
#===============================================

harden_vsftp() {
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

harden_apache() {
  log_action "=== HARDENING APACHE ==="

  if ! command -v apache2 >/dev/null 2>&1 && [ ! -d /etc/apache2 ]; then
      log_action "Apache2 not found. Skipping Apache hardening."
      return 0
  fi

  SECURITY_CONF="/etc/apache2/conf-available/security.conf"

  if [ ! -f "$SECURITY_CONF" ]; then
      log_action "apache2 security.conf not found, creating it."
      touch "$SECURITY_CONF"
  fi

  sed -i 's/^ServerTokens .*/ServerTokens Prod/' "$SECURITY_CONF" || echo "ServerTokens Prod" >> "$SECURITY_CONF"
  sed -i 's/^ServerSignature .*/ServerSignature Off/' "$SECURITY_CONF" || echo "ServerSignature Off" >> "$SECURITY_CONF"
  sed -i 's/^TraceEnable .*/TraceEnable Off/' "$SECURITY_CONF" || echo "TraceEnable Off" >> "$SECURITY_CONF"

  a2enconf security.conf >/dev/null 2>&1

  systemctl restart apache2

  log_action "Apache hardening complete."
}

harden_nginx() {
  log_action "=== HARDENING NGINX CONFIGURATION ==="

  if ! command -v nginx &>/dev/null; then
    log_action "NGINX not installed, skipping"
    return 0
  fi

  local NGINX_USER="www-data"
  if id -u nginx &>/dev/null; then
    NGINX_USER="nginx"
  fi

  set_nginx() {
    local key="$1"
    local val="$2"
    sed -i "/^\s*${key}/d" /etc/nginx/nginx.conf
    sed -i "/http {/a\\    ${key} ${val};" /etc/nginx/nginx.conf
    log_action "Set ${key} ${val}"
  }

  backup_file /etc/nginx/nginx.conf

  log_action "Disabling server version disclosure"
  set_nginx "server_tokens" "off"

  log_action "Configuring buffer limits (DoS protection)"
  set_nginx "client_body_buffer_size" "1k"
  set_nginx "client_header_buffer_size" "1k"
  set_nginx "client_max_body_size" "1m"
  set_nginx "large_client_header_buffers" "2 1k"

  log_action "Configuring connection timeouts"
  set_nginx "client_body_timeout" "10s"
  set_nginx "client_header_timeout" "10s"
  set_nginx "keepalive_timeout" "5s"
  set_nginx "send_timeout" "10s"

  log_action "Creating security headers snippet"
  mkdir -p /etc/nginx/snippets
  cat > /etc/nginx/snippets/security-headers.conf <<'EOF'
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self';" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
proxy_hide_header X-Powered-By;
fastcgi_hide_header X-Powered-By;
EOF
  chmod 644 /etc/nginx/snippets/security-headers.conf

  log_action "Creating SSL/TLS hardening snippet"
  cat > /etc/nginx/snippets/ssl-params.conf <<'EOF'
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
EOF
  chmod 644 /etc/nginx/snippets/ssl-params.conf

  log_action "Creating HSTS snippet"
  cat > /etc/nginx/snippets/hsts.conf <<'EOF'
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
EOF
  chmod 644 /etc/nginx/snippets/hsts.conf

  log_action "Creating general hardening config"
  mkdir -p /etc/nginx/conf.d
  cat > /etc/nginx/conf.d/99-security-hardening.conf <<'EOF'
autoindex off;
server_tokens off;
map $request_method $allowed_method {
    default 0;
    GET 1;
    POST 1;
    HEAD 1;
}
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_status 429;
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn_status 429;
EOF
  chmod 644 /etc/nginx/conf.d/99-security-hardening.conf

  if [ -f /etc/nginx/sites-available/default ]; then
    log_action "Updating default site config"
    backup_file /etc/nginx/sites-available/default
    if ! grep -q "include snippets/security-headers.conf" /etc/nginx/sites-available/default; then
      sed -i '/server {/a\    include snippets/security-headers.conf;' /etc/nginx/sites-available/default
    fi
    if ! grep -q 'location ~ /\.' /etc/nginx/sites-available/default; then
      sed -i '/server {/a\    location ~ /\\. { deny all; }' /etc/nginx/sites-available/default
    fi
  fi

  log_action "Securing NGINX config permissions"
  chown -R root:root /etc/nginx
  chmod 644 /etc/nginx/nginx.conf
  find /etc/nginx/sites-available -type f -exec chmod 644 {} \; 2>/dev/null
  find /etc/nginx/conf.d -type f -exec chmod 644 {} \; 2>/dev/null
  find /etc/nginx/snippets -type f -exec chmod 644 {} \; 2>/dev/null

  log_action "Securing SSL private keys"
  for keydir in /etc/ssl/private /etc/nginx/ssl /etc/letsencrypt; do
    if [ -d "$keydir" ]; then
      find "$keydir" -type f \( -name "*.key" -o -name "*-key.pem" \) -exec chmod 600 {} \; -exec chown root:root {} \; 2>/dev/null
    fi
  done

  log_action "Securing web root"
  for webroot in /var/www/html /var/www /usr/share/nginx/html; do
    if [ -d "$webroot" ]; then
      chown -R root:root "$webroot"
      find "$webroot" -type d -exec chmod 755 {} \;
      find "$webroot" -type f -exec chmod 644 {} \;
      log_action "Secured web root: $webroot"
      break
    fi
  done

  log_action "Validating NGINX configuration"
  if nginx -t &>/dev/null; then
    log_action "Configuration valid, reloading NGINX"
    systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null
  else
    log_action "WARNING: NGINX config has errors, not reloading"
    nginx -t
  fi

  log_action "NGINX hardening complete"
}

harden_php() {
  log_action "=== HARDENING PHP CONFIGURATION ==="

  if [ ! -d "/etc/php" ]; then
    log_action "PHP not installed (/etc/php not found), skipping"
    return 0
  fi

  local PHP_WEB_ROOT="/var/www/html" # default apache web dir
  local hardened_count=0

  local PHP_DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,highlight_file,phpinfo,pcntl_exec,pcntl_fork,pcntl_signal,pcntl_waitpid,pcntl_wexitstatus,pcntl_wifexited,pcntl_wifsignaled,pcntl_wifstopped,pcntl_wstopsig,pcntl_wtermsig,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,dl"
  local PHP_OPEN_BASEDIR="/var/www:/tmp:/usr/share/php:/dev/urandom"

  for version_dir in /etc/php/*/; do
    local version=$(basename "$version_dir")

    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+$ ]]; then
      continue
    fi

    log_action "Found PHP version: $version"

    for sapi in apache2 fpm cli cgi; do
      local conf_dir="/etc/php/${version}/${sapi}/conf.d"

      if [ -d "$conf_dir" ]; then
        local security_file="${conf_dir}/99-cyberpatriot-security.ini"
        log_action "Hardening PHP ${version} ${sapi}"

        cat > "$security_file" <<EOF
; CyberPatriot PHP Security Hardening
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
html_errors = Off
allow_url_fopen = Off
allow_url_include = Off
enable_dl = Off
disable_functions = ${PHP_DISABLE_FUNCTIONS}
session.cookie_secure = 1
session.cookie_httponly = 1
session.use_strict_mode = 1
session.use_only_cookies = 1
session.cookie_samesite = Strict
session.use_trans_sid = 0
file_uploads = Off
upload_max_filesize = 2M
max_file_uploads = 2
max_execution_time = 30
max_input_time = 60
memory_limit = 128M
post_max_size = 8M
max_input_vars = 1000
open_basedir = ${PHP_OPEN_BASEDIR}
cgi.force_redirect = 1
cgi.fix_pathinfo = 0
sql.safe_mode = On
mail.add_x_header = Off
zend.assertions = -1
assert.active = 0
EOF

        chmod 644 "$security_file"
        chown root:root "$security_file"
        ((hardened_count++))
        log_action "Created security config: $security_file"
      fi
    done
  done

  log_action "Hardended $hardened_count PHP configuration(s)"

  log_action "Searching for phpinfo files..."
  local phpinfo_patterns=("phpinfo.php" "info.php" "test.php" "pi.php" "php_info.php")
  local removed_count=0

  if [ -d "$PHP_WEB_ROOT" ]; then
    for pattern in "${phpinfo_patterns[@]}"; do
      while IFS= read -r file; do
        if [ -f "$file" ] && grep -qi "phpinfo\s*(" "$file" 2>/dev/null; then
          backup_file "$file"
          rm -f "$file"
          ((removed_count++))
          log_action "Removed phpinfo file: $file"
        fi
      done < <(find "$PHP_WEB_ROOT" -type f -name "$pattern" 2>/dev/null)
    done
  fi

  log_action "Removed $removed_count phpinfo file(s)"

  log_action "Hardening PHP file permissions..."
  find /etc/php -type f \( -name "php.ini" -o -name "*.ini" \) -exec chown root:root {} \; -exec chmod 644 {} \; 2>/dev/null
  find /etc/php -type d -exec chown root:root {} \; -exec chmod 755 {} \; 2>/dev/null
  log_action "PHP config files set to 644 root:root"

  if [ -d "$PHP_WEB_ROOT" ]; then
    log_action "Hardening web directory permissions..."
    local web_user="www-data"
    chown -R "${web_user}:${web_user}" "$PHP_WEB_ROOT" 2>/dev/null
    find "$PHP_WEB_ROOT" -type d -exec chmod 755 {} \; 2>/dev/null
    find "$PHP_WEB_ROOT" -type f -exec chmod 644 {} \; 2>/dev/null
    log_action "Web directory permissions set (dirs=755, files=644)"

    for upload_dir in "${PHP_WEB_ROOT}/uploads" "${PHP_WEB_ROOT}/upload" "${PHP_WEB_ROOT}/files" "${PHP_WEB_ROOT}/media"; do
      if [ -d "$upload_dir" ]; then
        chmod 750 "$upload_dir" 2>/dev/null
        local htaccess="${upload_dir}/.htaccess"
        if [ ! -f "$htaccess" ]; then
          cat > "$htaccess" <<'HTACCESS'
<FilesMatch "\.(?i:php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
HTACCESS
          chmod 644 "$htaccess"
          chown "${web_user}:${web_user}" "$htaccess"
          log_action "Created .htaccess in $upload_dir to block script execution"
        fi
      fi
    done
  fi

  log_action "Reloading PHP services..."
  for service in $(systemctl list-unit-files 2>/dev/null | grep -o 'php[0-9.]*-fpm\.service'); do
    if systemctl is-active "$service" &>/dev/null; then
      systemctl reload "$service" &>/dev/null && log_action "Reloaded $service"
    fi
  done

  systemctl is-active apache2 &>/dev/null && systemctl reload apache2 &>/dev/null && log_action "Reloaded apache2"
  systemctl is-active nginx &>/dev/null && systemctl reload nginx &>/dev/null && log_action "Reloaded nginx"

  log_action "PHP hardening complete"
}

harden_mysql() {
  log_action "=== HARDENING MYSQL/MARIADB CONFIGURATION ==="

  if ! command -v mysql &>/dev/null && ! command -v mariadb &>/dev/null; then
    log_action "MySQL/MariaDB not installed, skipping"
    return 0
  fi

  if ! command -v mysqld &>/dev/null && ! systemctl list-unit-files 2>/dev/null | grep -qE 'mysql|mariadb'; then
    log_action "MySQL/MariaDB server not installed, skipping"
    return 0
  fi

  local SERVICE_NAME=""
  if systemctl list-unit-files 2>/dev/null | grep -qE '^mysql\.service'; then
    SERVICE_NAME="mysql"
  elif systemctl list-unit-files 2>/dev/null | grep -qE '^mariadb\.service'; then
    SERVICE_NAME="mariadb"
  fi

  run_mysql() {
    local query="$1"
    mysql -e "$query" 2>/dev/null || mysql -u root -e "$query" 2>/dev/null
  }

  log_action "Detecting MySQL configuration paths"
  local CONFIG_FILE=""
  for cfg in /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.conf.d/50-server.cnf; do
    if [ -f "$cfg" ]; then
      CONFIG_FILE="$cfg"
      break
    fi
  done

  local DATA_DIR="/var/lib/mysql"
  if [ -d "/var/lib/mariadb" ]; then
    DATA_DIR="/var/lib/mariadb"
  fi

  local CONFIG_DIR=""
  if [ -d "/etc/mysql/mysql.conf.d" ]; then
    CONFIG_DIR="/etc/mysql/mysql.conf.d"
  elif [ -d "/etc/mysql/conf.d" ]; then
    CONFIG_DIR="/etc/mysql/conf.d"
  else
    mkdir -p /etc/mysql/conf.d
    CONFIG_DIR="/etc/mysql/conf.d"
  fi

  log_action "Creating hardened MySQL configuration"
  cat > "$CONFIG_DIR/99-security-hardening.cnf" <<'EOF'
[mysqld]
# Network Security
bind-address = 127.0.0.1
skip-name-resolve = 1

# Run as non-root user
user = mysql

# Require SSL/TLS for connections
require_secure_transport = ON

# Disable dangerous features
local-infile = 0
symbolic-links = 0
skip-symbolic-links

# Disable file operations (most secure)
secure-file-priv = NULL

# Logging
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_error = /var/log/mysql/error.log

# Connection limits
max_connections = 100
max_connect_errors = 10
connect_timeout = 10
wait_timeout = 600
interactive_timeout = 600
max_allowed_packet = 64M

# Performance
table_open_cache = 2000
thread_cache_size = 8
EOF
  chmod 644 "$CONFIG_DIR/99-security-hardening.cnf"
  chown root:root "$CONFIG_DIR/99-security-hardening.cnf"
  log_action "Created $CONFIG_DIR/99-security-hardening.cnf"

  log_action "Securing MySQL configuration file permissions"
  if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
    backup_file "$CONFIG_FILE"
    chmod 644 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    log_action "Secured $CONFIG_FILE (644, root:root)"
  fi

  log_action "Securing MySQL data directory"
  if [ -d "$DATA_DIR" ]; then
    chown -R mysql:mysql "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    log_action "Secured $DATA_DIR (750, mysql:mysql)"
  fi

  if [ -n "$SERVICE_NAME" ] && systemctl is-active "$SERVICE_NAME" &>/dev/null; then
    log_action "MySQL is running, performing database-level hardening"

    log_action "Removing anonymous users"
    if run_mysql "DELETE FROM mysql.user WHERE User = ''; FLUSH PRIVILEGES;" 2>/dev/null; then
      log_action "Removed anonymous users"
    else
      log_action "WARNING: Could not remove anonymous users (may need auth)"
    fi

    log_action "Disabling remote root login"
    if run_mysql "DELETE FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); FLUSH PRIVILEGES;" 2>/dev/null; then
      log_action "Disabled remote root login"
    else
      log_action "WARNING: Could not disable remote root (may need auth)"
    fi

    log_action "Removing test database"
    if run_mysql "DROP DATABASE IF EXISTS test;" 2>/dev/null; then
      log_action "Removed test database"
    else
      log_action "WARNING: Could not remove test database (may need auth)"
    fi

    log_action "Installing password validation plugin"
    if run_mysql "INSTALL COMPONENT 'file://component_validate_password';" 2>/dev/null; then
      log_action "Installed password validation component (MySQL 8+)"
      run_mysql "SET GLOBAL validate_password.policy = 'STRONG';" 2>/dev/null
      run_mysql "SET GLOBAL validate_password.length = 12;" 2>/dev/null
    elif run_mysql "INSTALL PLUGIN validate_password SONAME 'validate_password.so';" 2>/dev/null; then
      log_action "Installed password validation plugin (legacy)"
      run_mysql "SET GLOBAL validate_password_policy = 'STRONG';" 2>/dev/null
    elif run_mysql "INSTALL SONAME 'simple_password_check';" 2>/dev/null; then
      log_action "Installed simple_password_check (MariaDB)"
    else
      log_action "Password validation plugin already installed or unavailable"
    fi

    log_action "Restarting MySQL to apply configuration"
    systemctl restart "$SERVICE_NAME" 2>/dev/null || service "$SERVICE_NAME" restart 2>/dev/null
    if [ $? -eq 0 ]; then
      log_action "MySQL restarted successfully"
    else
      log_action "WARNING: MySQL restart failed, changes apply on next start"
    fi
  else
    log_action "WARNING: MySQL not running, skipping database-level hardening"
    log_action "Start MySQL and re-run to apply: remove anon users, disable remote root, remove test db, install password validator"
  fi

  log_action "MySQL hardening complete"
}

harden_postgresql() {
  log_action "=== HARDENING POSTGRESQL CONFIGURATION ==="

  if ! command -v psql &>/dev/null; then
    log_action "PostgreSQL not installed, skipping"
    return 0
  fi

  if ! systemctl list-unit-files 2>/dev/null | grep -qE 'postgresql' && ! service --status-all 2>&1 | grep -qE 'postgresql'; then
    log_action "PostgreSQL service not found, skipping"
    return 0
  fi

  log_action "Detecting PostgreSQL version and paths"
  local PG_VERSION=""
  for ver in 16 15 14 13 12 11 10; do
    if [ -d "/etc/postgresql/$ver/main" ]; then
      PG_VERSION="$ver"
      break
    fi
  done

  if [ -z "$PG_VERSION" ]; then
    log_action "WARNING: Could not detect PostgreSQL version"
    return 0
  fi
  log_action "Detected PostgreSQL version: $PG_VERSION"

  local PG_CONF=""
  local PG_HBA=""
  local PG_DATA=""

  for cfg in "/etc/postgresql/$PG_VERSION/main/postgresql.conf" "/var/lib/postgresql/$PG_VERSION/main/postgresql.conf"; do
    if [ -f "$cfg" ]; then
      PG_CONF="$cfg"
      break
    fi
  done

  for hba in "/etc/postgresql/$PG_VERSION/main/pg_hba.conf" "/var/lib/postgresql/$PG_VERSION/main/pg_hba.conf"; do
    if [ -f "$hba" ]; then
      PG_HBA="$hba"
      break
    fi
  done

  for data in "/var/lib/postgresql/$PG_VERSION/main" "/var/lib/postgresql"; do
    if [ -d "$data" ]; then
      PG_DATA="$data"
      break
    fi
  done

  if [ -z "$PG_CONF" ]; then
    log_action "WARNING: postgresql.conf not found"
    return 0
  fi
  log_action "Found postgresql.conf: $PG_CONF"

  if [ -z "$PG_HBA" ]; then
    log_action "WARNING: pg_hba.conf not found"
    return 0
  fi
  log_action "Found pg_hba.conf: $PG_HBA"

  log_action "Hardening postgresql.conf"
  backup_file "$PG_CONF"

  cat > "$PG_CONF" <<'EOF'
# === CyberPatriot PostgreSQL Hardening ===

# Connection Security
listen_addresses = 'localhost'
port = 5432
max_connections = 100

# Logging and Auditing
log_connections = on
log_disconnections = on
log_duration = off
log_line_prefix = '%m [%p] %q%u@%d '
log_statement = 'ddl'
log_lock_waits = on
log_timezone = 'UTC'

# SSL/TLS Configuration
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
ssl_prefer_server_ciphers = on
ssl_min_protocol_version = 'TLSv1.2'

# Authentication
password_encryption = 'scram-sha-256'

# Security Parameters
shared_preload_libraries = ''
fsync = on
full_page_writes = on
EOF
  chmod 644 "$PG_CONF"
  chown postgres:postgres "$PG_CONF" 2>/dev/null
  log_action "Created hardened postgresql.conf"

  log_action "Hardening pg_hba.conf"
  backup_file "$PG_HBA"

  cat > "$PG_HBA" <<'EOF'
# === CyberPatriot PostgreSQL pg_hba.conf Hardening ===
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local connections (require password, no trust/peer)
local   all             postgres                                scram-sha-256
local   all             all                                     scram-sha-256

# IPv4 local connections
host    all             all             127.0.0.1/32            scram-sha-256

# IPv6 local connections
host    all             all             ::1/128                 scram-sha-256

# Remote connections - reject non-SSL, allow SSL with auth
hostnossl   all         all             0.0.0.0/0               reject
hostssl     all         all             0.0.0.0/0               scram-sha-256
EOF
  chmod 640 "$PG_HBA"
  chown postgres:postgres "$PG_HBA" 2>/dev/null
  log_action "Created hardened pg_hba.conf (no trust/peer, SSL required for remote)"

  if [ -n "$PG_DATA" ] && [ -d "$PG_DATA" ]; then
    log_action "Securing PostgreSQL data directory: $PG_DATA"
    chown -R postgres:postgres "$PG_DATA"
    chmod 700 "$PG_DATA"
    find "$PG_DATA" -type d -exec chmod 700 {} \; 2>/dev/null
    find "$PG_DATA" -type f -exec chmod 600 {} \; 2>/dev/null
    log_action "Secured data directory (700/600, postgres:postgres)"
  fi

  log_action "Securing SSL private key"
  local SSL_KEY="/etc/ssl/private/ssl-cert-snakeoil.key"
  if [ -f "$SSL_KEY" ]; then
    chown postgres:postgres "$SSL_KEY" 2>/dev/null || chown root:ssl-cert "$SSL_KEY" 2>/dev/null
    chmod 600 "$SSL_KEY"
    log_action "Secured SSL key: $SSL_KEY (600)"
  fi

  log_action "Verifying PostgreSQL is not running as root"
  if pgrep -x postgres &>/dev/null; then
    local PG_USER=$(ps aux | grep -E '[p]ostgres.*main' | awk '{print $1}' | head -n1)
    if [ "$PG_USER" = "root" ]; then
      log_action "CRITICAL: PostgreSQL running as root!"
    elif [ "$PG_USER" = "postgres" ]; then
      log_action "PostgreSQL running as unprivileged user 'postgres'"
    else
      log_action "PostgreSQL running as: $PG_USER"
    fi
  fi

  log_action "Reloading PostgreSQL service"
  local SERVICE_NAME=""
  if systemctl list-unit-files 2>/dev/null | grep -q '^postgresql\.service'; then
    SERVICE_NAME="postgresql"
  elif systemctl list-unit-files 2>/dev/null | grep -qE '^postgresql@'; then
    SERVICE_NAME=$(systemctl list-unit-files | grep -E '^postgresql@' | head -n1 | awk '{print $1}')
  fi

  if [ -n "$SERVICE_NAME" ] && systemctl is-active "$SERVICE_NAME" &>/dev/null; then
    if systemctl reload "$SERVICE_NAME" 2>/dev/null; then
      log_action "PostgreSQL reloaded successfully"
    elif systemctl restart "$SERVICE_NAME" 2>/dev/null; then
      log_action "PostgreSQL restarted successfully"
    else
      log_action "WARNING: Could not reload PostgreSQL"
    fi
  else
    log_action "PostgreSQL not running, changes apply on next start"
  fi

  log_action "Validating PostgreSQL connectivity"
  if command -v pg_isready &>/dev/null; then
    if pg_isready -h localhost -p 5432 &>/dev/null; then
      log_action "PostgreSQL accepting connections on port 5432"
    else
      log_action "PostgreSQL not responding (may not be running)"
    fi
  fi

  log_action "PostgreSQL hardening complete"
  log_action "NOTE: Set postgres password with: sudo -u postgres psql -c \"ALTER USER postgres PASSWORD 'STRONG_PASSWORD';\""
}

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

#===============================================
# Antivirus
#===============================================

run_rootkit_scans() {
  log_action "=== RUNNING ROOTKIT SCANS ==="

  local RK_LOG="/var/log/rkhunter.log"
  local CRK_LOG="/var/log/chkrootkit.log"

  # Update package lists
  log_action "Updating package lists for rootkit scanner installation..."
  apt update -y -qq &>/dev/null

  # Install or reinstall rkhunter
  if ! dpkg -s rkhunter &>/dev/null; then
    log_action "Installing rkhunter..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rkhunter &>/dev/null
    log_action "rkhunter installed successfully"
  else
    log_action "Reinstalling rkhunter for clean baseline..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall rkhunter &>/dev/null
    log_action "rkhunter reinstalled successfully"
  fi

  # Install or reinstall chkrootkit
  if ! dpkg -s chkrootkit &>/dev/null; then
    log_action "Installing chkrootkit..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chkrootkit &>/dev/null
    log_action "chkrootkit installed successfully"
  else
    log_action "Reinstalling chkrootkit for clean baseline..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall chkrootkit &>/dev/null
    log_action "chkrootkit reinstalled successfully"
  fi

  # Configure rkhunter
  if [ -f /etc/rkhunter.conf ]; then
    backup_file /etc/rkhunter.conf
    log_action "Configuring rkhunter..."
    # Prefer mirror updates and quiet web fetches
    sed -i 's/^[#[:space:]]*UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null || true
    sed -i 's/^[#[:space:]]*MIRRORS_MODE=.*/MIRRORS_MODE=1/' /etc/rkhunter.conf 2>/dev/null || true
    sed -i 's|^[#[:space:]]*WEB_CMD=.*|WEB_CMD="wget -q"|' /etc/rkhunter.conf 2>/dev/null || true
    log_action "rkhunter configuration updated"
  fi

  # Update rkhunter database
  log_action "Updating rkhunter signatures database..."
  rkhunter --update &>>"$RK_LOG" || true

  # Build baseline file property database
  log_action "Building rkhunter file property baseline..."
  rkhunter --propupd &>>"$RK_LOG" || true

  # Run rkhunter scan
  log_action "Starting rkhunter system scan (this may take several minutes)..."
  rkhunter --check --sk --nocolors --noappend-log &>>"$RK_LOG" || true
  log_action "rkhunter scan completed. Full log: $RK_LOG"

  # Run chkrootkit scan
  log_action "Starting chkrootkit system scan..."
  chkrootkit -q >"$CRK_LOG" 2>&1 || true
  log_action "chkrootkit scan completed. Full log: $CRK_LOG"

  # Append scan results to main log
  {
    echo "========== rkhunter Results (last 50 lines) =========="
    tail -n 50 "$RK_LOG" 2>/dev/null || echo "No rkhunter log found"
  } >>"$LOG_FILE" 2>/dev/null

  {
    echo "========== chkrootkit Results (last 50 lines) =========="
    tail -n 50 "$CRK_LOG" 2>/dev/null || echo "No chkrootkit log found"
  } >>"$LOG_FILE" 2>/dev/null

  # Basic alerting based on common warning patterns
  log_action "Analyzing scan results for suspicious findings..."
  local RK_ALERTS CRK_ALERTS
  RK_ALERTS=$(grep -Ei "Warning|suspect|infected|rootkit" "$RK_LOG" 2>/dev/null | wc -l)
  CRK_ALERTS=$(grep -Ei "INFECTED|Vulnerable|Warning" "$CRK_LOG" 2>/dev/null | wc -l)

  if [ "${RK_ALERTS:-0}" -gt 0 ] || [ "${CRK_ALERTS:-0}" -gt 0 ]; then
    log_action "ALERT: Potential security issues detected by rootkit scanners"
    log_action "ALERT: rkhunter warnings: ${RK_ALERTS}, chkrootkit warnings: ${CRK_ALERTS}"
    log_action "ALERT: Review full logs at $RK_LOG and $CRK_LOG"
  else
    log_action "No obvious rootkit indicators found in scans"
  fi

  log_action "Rootkit scanning complete"
}

#==============================================
# System Auditing
#==============================================
harden_auditd() {
  log_action "=== HARDENING AUDITD ==="

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

#===============================================
# MAIN EXECUTION
#===============================================
main() {
  if [ "$EUID" -ne 0 ]; then
    echo "ERR: Script must be run as root"
    exit 1
  fi

  preflight_check

  log_action "======================================"
  log_action "STARTING LINUX MINT HARDENING SCRIPT"
  log_action "======================================"
  log_action "Timestamp: $(date)"
  log_action ""

  log_action "[ PHASE 1: SYSTEM UPDATES ]"
  update_system
  configure_automatic_updates
  enable_auto_update_refresh
  log_action ""

  log_action "[ PHASE 2: USER & GROUP MANAGEMENT ]"
  remove_unauthorized_users
  fix_admin_group
  check_uid_zero
  disable_guest
  set_all_user_passwords
  lock_root_account
  log_action ""

  log_action "[ PHASE 3: PASSWORD POLICIES ]"
  disallow_empty_passwords
  configure_pam
  set_password_aging
  log_action ""

  log_action "[ PHASE 4: FILE PERMISSIONS & SECURITY ]"
  secure_file_permissions
  fix_sudoers_nopasswd
  find_world_writable_files
  check_suid_sgid
  find_orphaned_files
  log_action ""

  log_action "[ PHASE 5: NETWORK SECURITY ]"
  fix_hosts_file
  harden_ssh
  harden_kernel_sysctl
  log_action ""

  log_action "[ PHASE 6: FIREWALL ]"
  configure_firewall
  log_action ""

  log_action "[ PHASE 7: SERVICE MANAGEMENT ]"
  disable_unnecessary_services "./service_blacklist.txt"
  audit_running_services
  log_action ""

  log_action "[ PHASE 8: SOFTWARE AUDITING ]"
  remove_unauthorized_software "./package_blacklist.txt"
  remove_prohibited_media
  log_action ""

  log_action "[ PHASE 9: SERVICE HARDENING ]"
  harden_vsftp
  harden_apache
  harden_nginx
  harden_php
  harden_mysql
  harden_postgresql
  log_action ""

  log_action "[ PHASE 10: CRON SECURITY ]"
  secure_cron_system
  log_action ""

  log_action "[ PHASE 11: MALWARE DETECTION ]"
  run_rootkit_scans
  log_action ""

  log_action "[ PHASE 12: SYSTEM AUDITING ]"
  harden_auditd
  enable_app_armor
  log_action ""

  # 12. COMPREHENSIVE SECURITY AUDIT
  log_action "[ PHASE 13: LYNIS AUDIT ]"
  audit_with_lynis
  log_action ""

  log_action "======================================"
  log_action "HARDENING COMPLETE"
  log_action "======================================"
  log_action "IMPORTANT: Review the log at $LOG_FILE"
  log_action "IMPORTANT: Reboot system to apply all changes"
  log_action "Run: sudo reboot"
  log_action ""
  log_action "Completion time: $(date)"
}

main
