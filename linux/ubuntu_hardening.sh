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
# Load Modules
#===============================================

source "./ubuntu/00_utils.sh"
source "./ubuntu/01_updates.sh"
source "./ubuntu/02_users.sh"
source "./ubuntu/03_passwords.sh"
source "./ubuntu/04_files.sh"
source "./ubuntu/05_network.sh"
source "./ubuntu/06_firewall.sh"
source "./ubuntu/07_remove_services.sh"
source "./ubuntu/08_remove_software.sh"
source "./ubuntu/09_service_hardening.sh"
source "./ubuntu/10_cron.sh"
source "./ubuntu/11_malware.sh"
source "./ubuntu/12_auditing.sh"


#===============================================
# Run Functions
#===============================================

main() {
  if [ "$EUID" -ne 0 ]; then
    echo "ERR: Script must be run as root"
    exit 1
  fi

  preflight_check

  log_action "======================================"
  log_action "STARTING UBUNTU HARDENING SCRIPT"
  log_action "======================================"
  log_action "Timestamp: $(date)"
  log_action ""

  log_action "[ PHASE 1: SYSTEM UPDATES & INSTALLATIONS]"
  configure_automatic_updates
  update_system
  install_security_dependencies
  log_action ""

  log_action "[ PHASE 2: USER & GROUP MANAGEMENT ]"
  remove_unauthorized_users
  fix_admin_group
  check_uid_zero
  check_group_sudo_privileges
  disable_guest
  set_all_user_passwords
  lock_root_account
  log_action ""

  log_action "[ PHASE 3: PASSWORD POLICIES ]"
  configure_account_lockout
  configure_pam
  disallow_empty_passwords
  set_password_aging
  log_action ""

  log_action "[ PHASE 4: FILE PERMISSIONS & SECURITY ]"
  secure_file_permissions
  verify_file_permissions
  fix_sudoers_nopasswd
  find_world_writable_files
  check_suid_sgid
  find_orphaned_files
  log_action ""

  log_action "[ PHASE 5: NETWORK SECURITY ]"
  fix_hosts_file
  harden_ssh
  harden_kernel_sysctl
  verify_sysctl_settings
  harden_grub # need to refactor code this is getting kinda long
  remove_rbash
  enforce_umask
  secure_home_directories
  secure_tmp_mount
  secure_dev_shm
  setup_proc_hidepid
  configure_host_conf
  configure_screen_security
  disable_xserver_tcp
  validate_gdm3_config #helper
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
  harden_samba
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