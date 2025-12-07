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
  echo "This script is ubuntu_hardening.sh, it is supposed to be run on UBUNTU LINUX"
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
