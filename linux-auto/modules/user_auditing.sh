#!/bin/bash
# user_auditing.sh - User Auditing and Management with AI Integration
# Manages users based on README parsing and security best practices

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Try to load readme_parser for AI-based user information
if [[ -f "$SCRIPT_DIR/readme_parser.sh" ]]; then
    source "$SCRIPT_DIR/readme_parser.sh"
fi

# Module: User Auditing and Management
# Category: User Security
# Description: Audits and manages user accounts based on README requirements

# Get authorized users from README or fallback to global arrays
get_all_authorized_users_list() {
    if [[ "${README_PARSED:-0}" -eq 1 ]] && type -t get_authorized_users >/dev/null 2>&1; then
        get_authorized_users
    elif [[ -n "${AUTHORIZED_USERS[*]:-}" ]]; then
        printf '%s\n' "${AUTHORIZED_USERS[@]}"
    else
        echo ""
    fi
}

# Get admin users from README or fallback to global arrays
get_all_admin_users_list() {
    if [[ "${README_PARSED:-0}" -eq 1 ]] && type -t get_authorized_admins >/dev/null 2>&1; then
        get_authorized_admins
    elif [[ -n "${ADMIN_USERS[*]:-}" ]]; then
        printf '%s\n' "${ADMIN_USERS[@]}"
    else
        echo ""
    fi
}

# Get terminated users from README
get_all_terminated_users_list() {
    if [[ "${README_PARSED:-0}" -eq 1 ]] && type -t get_terminated_users >/dev/null 2>&1; then
        get_terminated_users
    else
        echo ""
    fi
}

remove_unauthorized_users() {
    log_action "=== CHECKING FOR UNAUTHORIZED USERS ==="

    # Get authorized users list
    local -a authorized_users_arr=()
    while IFS= read -r user; do
        [[ -n "$user" ]] && authorized_users_arr+=("$user")
    done < <(get_all_authorized_users_list)

    # Get admin users list
    local -a admin_users_arr=()
    while IFS= read -r user; do
        [[ -n "$user" ]] && admin_users_arr+=("$user")
    done < <(get_all_admin_users_list)

    # Get terminated users list
    local -a terminated_users_arr=()
    while IFS= read -r user; do
        [[ -n "$user" ]] && terminated_users_arr+=("$user")
    done < <(get_all_terminated_users_list)

    log_info "Authorized users: ${authorized_users_arr[*]:-none}"
    log_info "Admin users: ${admin_users_arr[*]:-none}"
    log_info "Terminated users: ${terminated_users_arr[*]:-none}"

    # First, remove explicitly terminated users
    for user in "${terminated_users_arr[@]}"; do
        if id "$user" &>/dev/null; then
            log_action "Removing terminated user: $user"
            userdel -r "$user" 2>/dev/null
            if [ $? -eq 0 ]; then
                log_success "Successfully removed terminated user: $user"
            else
                log_warn "Failed to remove terminated user: $user (CHECK MANUALLY)"
            fi
        fi
    done

    # Now check for unauthorized users
    CURRENT_USERS=$(awk -F: '($3 >=1000 || $3 == 0) && $1 != "nobody" {print $1}' /etc/passwd)

    for user in $CURRENT_USERS; do
        if [ "$user" = "root" ]; then
            continue
        fi

        # Check if user is in admin list
        local is_admin=0
        for admin in "${admin_users_arr[@]}"; do
            if [[ "$admin" == "$user" ]]; then
                is_admin=1
                break
            fi
        done

        if [[ $is_admin -eq 1 ]]; then
            log_debug "Skipping admin user: $user"
            continue
        fi

        # Check if user is in authorized list
        local is_authorized=0
        for auth_user in "${authorized_users_arr[@]}"; do
            if [[ "$auth_user" == "$user" ]]; then
                is_authorized=1
                break
            fi
        done

        if [[ $is_authorized -eq 1 ]]; then
            log_debug "Skipping authorized user: $user"
            continue
        fi

        # If we have no authorized users list, don't remove anyone (safety)
        if [[ ${#authorized_users_arr[@]} -eq 0 && ${#admin_users_arr[@]} -eq 0 ]]; then
            log_warn "No authorized users list available - skipping user removal for safety"
            log_warn "User $user would be removed if authorized list was available"
            continue
        fi

        log_action "FOUND UNAUTHORIZED USER: $user - Removing ..."
        userdel -r "$user" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_success "Successfully removed user: $user"
        else
            log_warn "Failed to remove user: $user (CHECK MANUALLY)"
        fi
    done
}

fix_admin_group() {
    log_action "=== FIXING SUDO GROUP MEMBERSHIP ==="

    # Get admin users list
    local -a admin_users_arr=()
    while IFS= read -r user; do
        [[ -n "$user" ]] && admin_users_arr+=("$user")
    done < <(get_all_admin_users_list)

    if [[ ${#admin_users_arr[@]} -eq 0 ]]; then
        log_warn "No admin users list available - skipping sudo group fix"
        return 0
    fi

    log_info "Expected admins: ${admin_users_arr[*]}"

    SUDO_MEMBERS=$(getent group sudo | cut -d: -f4 | tr ',' ' ')

    # Remove unauthorized users from sudo group
    for user in $SUDO_MEMBERS; do
        local is_admin=0
        for admin in "${admin_users_arr[@]}"; do
            if [[ "$admin" == "$user" ]]; then
                is_admin=1
                break
            fi
        done

        if [[ $is_admin -eq 0 ]]; then
            log_action "Removing $user from sudo group (not in admin list)"
            deluser "$user" sudo &>/dev/null
        fi
    done

    # Add authorized admin users to sudo group
    for user in "${admin_users_arr[@]}"; do
        if id "$user" &>/dev/null; then
            usermod -aG sudo "$user" &>/dev/null
            log_action "Ensured $user is in sudo group"
        else
            log_warn "Admin user $user does not exist on system"
        fi
    done
}

create_missing_users() {
    log_action "=== CREATING MISSING USERS ==="

    if [[ "${README_PARSED:-0}" -ne 1 ]]; then
        log_warn "README not parsed - cannot create missing users"
        return 0
    fi

    if ! type -t get_users_to_create >/dev/null 2>&1; then
        log_warn "get_users_to_create function not available"
        return 0
    fi

    local users_created=0

    while IFS= read -r user_json; do
        [[ -z "$user_json" ]] && continue

        local username=$(echo "$user_json" | jq -r '.name // empty')
        local account_type=$(echo "$user_json" | jq -r '.account_type // "standard"')

        if [[ -z "$username" ]]; then
            continue
        fi

        # Check if user already exists
        if id "$username" &>/dev/null; then
            log_debug "User $username already exists"
            continue
        fi

        log_action "Creating user: $username (type: $account_type)"

        # Create user
        useradd -m -s /bin/bash "$username" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "Created user: $username"
            users_created=$((users_created + 1))

            # Set password
            printf '%s:%s\n' "$username" 'Cyb3rPatr!0t' | chpasswd --crypt-method SHA512
            log_action "Set password for user: $username"

            # Add to sudo if admin
            if [[ "$account_type" == "admin" ]]; then
                usermod -aG sudo "$username" &>/dev/null
                log_action "Added $username to sudo group (admin)"
            fi

            # Handle groups
            local groups=$(echo "$user_json" | jq -r '.groups[]? // empty')
            for group in $groups; do
                if getent group "$group" >/dev/null 2>&1; then
                    usermod -aG "$group" "$username" &>/dev/null
                    log_action "Added $username to group $group"
                else
                    log_warn "Group $group does not exist for user $username"
                fi
            done
        else
            log_warn "Failed to create user: $username"
        fi
    done < <(get_users_to_create)

    log_info "Created $users_created new user(s)"
}

create_groups_from_readme() {
    log_action "=== CREATING GROUPS FROM README ==="

    if [[ "${README_PARSED:-0}" -ne 1 ]]; then
        log_warn "README not parsed - cannot create groups"
        return 0
    fi

    if ! type -t get_groups_to_create >/dev/null 2>&1; then
        log_warn "get_groups_to_create function not available"
        return 0
    fi

    local groups_created=0

    while IFS= read -r group_json; do
        [[ -z "$group_json" ]] && continue

        local groupname=$(echo "$group_json" | jq -r '.name // empty')

        if [[ -z "$groupname" ]]; then
            continue
        fi

        # Check if group exists
        if ! getent group "$groupname" >/dev/null 2>&1; then
            log_action "Creating group: $groupname"
            groupadd "$groupname" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                log_success "Created group: $groupname"
                groups_created=$((groups_created + 1))
            else
                log_warn "Failed to create group: $groupname"
            fi
        else
            log_debug "Group $groupname already exists"
        fi

        # Add members
        local members=$(echo "$group_json" | jq -r '.members[]? // empty')
        for member in $members; do
            if id "$member" &>/dev/null; then
                usermod -aG "$groupname" "$member" &>/dev/null
                log_action "Added $member to group $groupname"
            else
                log_warn "User $member does not exist (cannot add to $groupname)"
            fi
        done
    done < <(get_groups_to_create)

    log_info "Created $groups_created new group(s)"
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

# Main runner
run_user_auditing() {
    log_section "Starting User Auditing"

    # Try to parse README if not already done
    if [[ "${README_PARSED:-0}" -eq 0 ]]; then
        log_info "README not parsed yet, attempting to parse..."
        if type -t parse_readme >/dev/null 2>&1 && parse_readme; then
            log_success "README parsed successfully for user auditing"
        else
            log_warn "Could not parse README - using fallback global arrays"
        fi
    fi

    # Create groups first (needed for user creation)
    create_groups_from_readme

    # Create missing users from README
    create_missing_users

    # Now remove unauthorized users
    remove_unauthorized_users

    # Fix admin group membership
    fix_admin_group

    # Check for UID 0 violations
    check_uid_zero

    # Check group sudo privileges
    check_group_sudo_privileges

    # Disable guest account
    disable_guest

    # Set all passwords
    set_all_user_passwords

    # Lock root account
    lock_root_account

    log_success "User Auditing completed"
}

export -f run_user_auditing
