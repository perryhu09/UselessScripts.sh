#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

harden_postgresql(){
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

run_postgresql_hardening() {
    log_section "Starting Postgresql Hardening"
    harden_postgresql
    log_success "Postgresql Hardening completed"
}

export -f run_postgresql_hardening
