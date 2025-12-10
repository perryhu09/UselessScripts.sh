#!/bin/bash
# mysql_hardening.sh - Mysql Hardening Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Mysql Hardening
# Category: Service Hardening
# Description: Hardens Mysql configuration

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
# Main runner
run_mysql_hardening() {
    log_section "Starting Mysql Hardening"
    harden_mysql
    log_success "Mysql Hardening completed"
}

export -f run_mysql_hardening
