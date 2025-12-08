#!/bin/bash
# apache_hardening.sh - Apache Hardening Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Apache Hardening
# Category: Service Hardening
# Description: Hardens Apache configuration
harden_apache() {
  log_action "=== HARDENING APACHE CONFIGURATION ==="

  if ! command -v apache2 &>/dev/null && ! command -v apachectl &>/dev/null; then
    log_action "Apache not installed, skipping"
    return 0
  fi

  if [ ! -d /etc/apache2 ]; then
    log_action "WARNING: /etc/apache2 not found"
    return 0
  fi

  local CONF_AVAILABLE="/etc/apache2/conf-available"
  local CONF_ENABLED="/etc/apache2/conf-enabled"
  local MODS_ENABLED="/etc/apache2/mods-enabled"
  local SECURITY_CONF="$CONF_AVAILABLE/99-security-hardening.conf"
  local HEADERS_CONF="$CONF_AVAILABLE/security-headers.conf"

  mkdir -p "$CONF_AVAILABLE"

  log_action "Creating hardened Apache security configuration"
  cat > "$SECURITY_CONF" <<'EOF'
# === CyberPatriot Apache Security Hardening ===

# Hide Apache version and OS information
ServerTokens Prod
ServerSignature Off

# Disable HTTP TRACE method (prevents XST attacks)
TraceEnable Off

# Disable ETag (prevents inode disclosure)
FileETag None

# Timeout settings (DoS protection)
Timeout 60
KeepAliveTimeout 5

# Request size limits
LimitRequestBody 10485760
LimitRequestFields 100
LimitRequestFieldSize 8190
LimitRequestLine 8190

# Root directory - deny all by default
<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

# Web root hardening
<Directory /var/www/>
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# Block access to .ht files
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# Block access to version control directories
<DirectoryMatch "/\.(git|svn|hg|bzr)">
    Require all denied
</DirectoryMatch>

# Block access to backup files
<FilesMatch "(~|\.bak|\.swp|\.tmp|\.old|\.orig)$">
    Require all denied
</FilesMatch>
EOF
  chmod 644 "$SECURITY_CONF"
  log_action "Created $SECURITY_CONF"

  log_action "Creating security headers configuration"
  cat > "$HEADERS_CONF" <<'EOF'
# === Apache Security Headers ===

<IfModule mod_headers.c>
    # Prevent clickjacking
    Header always set X-Frame-Options "SAMEORIGIN"

    # Prevent MIME-sniffing
    Header always set X-Content-Type-Options "nosniff"

    # Enable XSS filter
    Header always set X-XSS-Protection "1; mode=block"

    # Control referrer information
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Remove server information headers
    Header unset Server
    Header always unset X-Powered-By

    # Permissions Policy
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

    # HSTS (uncomment for HTTPS sites only)
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
EOF
  chmod 644 "$HEADERS_CONF"
  log_action "Created $HEADERS_CONF"

  log_action "Enabling required Apache modules"
  if command -v a2enmod &>/dev/null; then
    if [ ! -e "$MODS_ENABLED/headers.load" ]; then
      a2enmod headers &>/dev/null && log_action "Enabled mod_headers"
    fi
  fi

  log_action "Disabling unnecessary Apache modules"
  if command -v a2dismod &>/dev/null; then
    for mod in autoindex status info userdir cgi cgid; do
      if [ -e "$MODS_ENABLED/${mod}.load" ]; then
        a2dismod "$mod" &>/dev/null && log_action "Disabled mod_$mod"
      fi
    done
  fi

  log_action "Enabling security configurations"
  if command -v a2enconf &>/dev/null; then
    a2enconf 99-security-hardening &>/dev/null && log_action "Enabled 99-security-hardening"
    a2enconf security-headers &>/dev/null && log_action "Enabled security-headers"
  else
    ln -sf "$SECURITY_CONF" "$CONF_ENABLED/99-security-hardening.conf" 2>/dev/null
    ln -sf "$HEADERS_CONF" "$CONF_ENABLED/security-headers.conf" 2>/dev/null
  fi

  log_action "Securing Apache configuration permissions"
  chown -R root:root /etc/apache2
  chmod 755 /etc/apache2
  find /etc/apache2 -type f -exec chmod 644 {} \;
  find /etc/apache2 -type d -exec chmod 755 {} \;
  log_action "Secured /etc/apache2 permissions"

  log_action "Securing web root permissions"
  local WEB_ROOT="/var/www/html"
  if [ -d "$WEB_ROOT" ]; then
    chown -R root:root "$WEB_ROOT"
    find "$WEB_ROOT" -type d -exec chmod 755 {} \;
    find "$WEB_ROOT" -type f -exec chmod 644 {} \;
    log_action "Secured $WEB_ROOT (755/644, root:root)"
  fi

  if [ -d /var/log/apache2 ]; then
    chown -R root:adm /var/log/apache2
    chmod 750 /var/log/apache2
    find /var/log/apache2 -type f -exec chmod 640 {} \;
    log_action "Secured /var/log/apache2 permissions"
  fi

  log_action "Validating Apache configuration"
  local VALID=0
  if command -v apache2ctl &>/dev/null; then
    if apache2ctl configtest 2>&1 | grep -qi "syntax ok"; then
      VALID=1
      log_action "Apache configuration is valid"
    fi
  elif command -v apachectl &>/dev/null; then
    if apachectl configtest 2>&1 | grep -qi "syntax ok"; then
      VALID=1
      log_action "Apache configuration is valid"
    fi
  fi

  if [ "$VALID" -eq 0 ]; then
    log_action "WARNING: Apache configuration validation failed"
    apache2ctl configtest 2>&1 | head -10
  fi

  log_action "Reloading Apache service"
  if systemctl is-active apache2 &>/dev/null; then
    if [ "$VALID" -eq 1 ]; then
      systemctl reload apache2 2>/dev/null && log_action "Apache reloaded successfully"
    else
      log_action "WARNING: Skipping reload due to config errors"
    fi
  else
    log_action "Apache not running, changes apply on next start"
  fi

  log_action "Apache hardening complete"
  log_action "Security applied: version hidden, TRACE disabled, directory listing off, security headers enabled"
}

# Main runner
run_apache_hardening() {
    log_section "Starting Apache Hardening"
    harden_apache
    log_success "Apache Hardening completed"
}

export -f run_apache_hardening
