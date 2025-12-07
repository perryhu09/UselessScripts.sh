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

  SUDO_MEMBERS=$(getent group sudo | cut -d: -f4 | tr ',' ' ')

  # Remove unauthorized users from sudo group
  for user in $SUDO_MEMBERS; do
    if [[ ! "${ADMIN_USERS[@]}" =~ "${user}" ]]; then
      log_action "Removing $user from sudo group"
      deluser "$user" sudo &>/dev/null
    fi
  done

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

check_group_sudo_privileges() {
  log_action "=== CHECKING GROUP SUDO PRIVILEGES ==="

  log_action "Checking for groups with sudo privileges..."

  local issues_found=0

  if getent group sudo >/dev/null 2>&1; then
    local sudo_members
    sudo_members=$(getent group sudo | cut -d: -f4)
    if [[ -n "$sudo_members" ]]; then
      log_action "Sudo group members: $sudo_members"
      log_action "This is expected - individual users should be in sudo group, not other groups"
    fi
  fi

  if [[ -f /etc/sudoers ]]; then
    while IFS= read -r line; do
      if [[ -n "$line" ]]; then
        local groupname
        groupname=$(echo "$line" | sed 's/^%\([^ ]*\).*/\1/')
        
        if [[ "$groupname" != "sudo" && "$groupname" != "admin" ]]; then
          log_action "WARNING: Group $groupname has sudo privileges in /etc/sudoers"
          log_action "Disabling sudo privileges for group: $groupname"
          sed -i "s/^\(%$groupname.*\)$/# DISABLED BY SECURITY POLICY: \1/" /etc/sudoers
          issues_found=$((issues_found + 1))
        fi
      fi
    done < <(grep -E "^%[^#]" /etc/sudoers 2>/dev/null | grep -v "^%sudo" | grep -v "^%admin")
  fi

  if [[ -d /etc/sudoers.d ]]; then
    while IFS= read -r file; do
      while IFS= read -r line; do
        if [[ -n "$line" ]]; then
          local groupname
          groupname=$(echo "$line" | sed 's/^%\([^ ]*\).*/\1/')
          if [[ "$groupname" != "sudo" && "$groupname" != "admin" ]]; then
            log_action "WARNING: Group $groupname has sudo privileges in $file"
            log_action "Disabling sudo privileges for group: $groupname in $file"
            sed -i "s/^\(%$groupname.*\)$/# DISABLED BY SECURITY POLICY: \1/" "$file"
            issues_found=$((issues_found + 1))
          fi
        fi
      done < <(grep -E "^%[^#]" "$file" 2>/dev/null | grep -v "^%sudo" | grep -v "^%admin")
    done < <(find /etc/sudoers.d -type f)
  fi

  if [[ $issues_found -eq 0 ]]; then
    log_action "No unauthorized groups have sudo privileges"
  else
    log_action "Removed sudo privileges from $issues_found unauthorized group(s)"
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
  if [ -d /etc/lightdm/lightdm.conf.d/ ]; then
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
