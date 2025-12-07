
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

harden_samba() {
  log_action "=== HARDENING SAMBA CONFIGURATION ==="

  if ! command -v smbd &>/dev/null; then
    log_action "Samba not installed, skipping"
    return 0
  fi

  local SMB_CONF=""
  for cfg in /etc/samba/smb.conf /etc/smb.conf /usr/local/samba/lib/smb.conf; do
    if [ -f "$cfg" ]; then
      SMB_CONF="$cfg"
      break
    fi
  done

  if [ -z "$SMB_CONF" ]; then
    log_action "WARNING: smb.conf not found"
    return 0
  fi
  log_action "Found smb.conf: $SMB_CONF"

  log_action "Backing up Samba configuration"
  backup_file "$SMB_CONF"

  log_action "Extracting existing share definitions"
  local EXISTING_SHARES=""
  if [ -f "$SMB_CONF" ]; then
    EXISTING_SHARES=$(awk '/^\[.+\]$/ && !/^\[global\]$/ {p=1} p' "$SMB_CONF")
  fi

  log_action "Creating hardened smb.conf"
  cat > "$SMB_CONF" <<'EOF'
# === CyberPatriot Samba Security Hardening ===

[global]
# Basic Settings
workgroup = WORKGROUP
server string = Samba Server %v
netbios name = FILESERVER

# CRITICAL: Protocol Security - Disable SMBv1 (WannaCry protection)
server min protocol = SMB2
client min protocol = SMB2
server max protocol = SMB3

# CRITICAL: Encryption - Require for all connections
smb encrypt = required

# CRITICAL: Authentication
security = user
map to guest = never
guest account = nobody
ntlm auth = disabled
lanman auth = no
encrypt passwords = yes
passdb backend = tdbsam

# CRITICAL: SMB Signing - Prevent packet tampering
server signing = mandatory
client signing = mandatory

# CRITICAL: Anonymous Access Prevention
restrict anonymous = 2
null passwords = no

# Network Access Control
hosts allow = 127.0.0.1 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12
hosts deny = 0.0.0.0/0

# Logging
log level = 2
log file = /var/log/samba/log.%m
max log size = 1000

# Auditing
vfs objects = acl_xattr full_audit
full_audit:prefix = %u|%I|%m|%S
full_audit:failure = connect
full_audit:success = connect disconnect opendir mkdir rmdir open close read write rename unlink chmod chown

# Connection Limits
max connections = 100
deadtime = 15
socket options = TCP_NODELAY IPTOS_LOWDELAY

# Disable Printer Sharing
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes

# Disable Master Browser
domain master = no
local master = no
preferred master = no
wins support = no
dns proxy = no

# File System
use sendfile = yes
map acl inherit = yes
store dos attributes = yes

EOF

  if [ -n "$EXISTING_SHARES" ]; then
    log_action "Restoring existing share definitions"
    echo "" >> "$SMB_CONF"
    echo "# === Existing Shares ===" >> "$SMB_CONF"
    echo "$EXISTING_SHARES" >> "$SMB_CONF"
  fi

  cat >> "$SMB_CONF" <<'EOF'

# === Secure Share Template (Example) ===
# [secure_share]
# comment = Secure File Share
# path = /srv/samba/secure_share
# browseable = no
# guest ok = no
# read only = yes
# write list = @samba_admins
# valid users = @samba_users
# create mask = 0660
# directory mask = 2770
# force group = samba_users
EOF

  log_action "Securing Samba file permissions"
  chown root:root "$SMB_CONF"
  chmod 644 "$SMB_CONF"

  if [ -d /etc/samba ]; then
    chown -R root:root /etc/samba
    chmod 755 /etc/samba
  fi

  if [ -d /var/lib/samba/private ]; then
    chmod 700 /var/lib/samba/private
    chown root:root /var/lib/samba/private
    log_action "Secured /var/lib/samba/private (700)"
  fi

  log_action "Creating samba_users group"
  if ! getent group samba_users &>/dev/null; then
    groupadd samba_users
    log_action "Created 'samba_users' group"
  else
    log_action "Group 'samba_users' already exists"
  fi

  log_action "Validating Samba configuration"
  if command -v testparm &>/dev/null; then
    if testparm -s "$SMB_CONF" &>/dev/null; then
      log_action "Samba configuration is valid"
    else
      log_action "WARNING: Samba configuration has errors"
      testparm -s "$SMB_CONF" 2>&1 | head -20
    fi
  fi

  log_action "Restarting Samba services"
  local RESTARTED=0
  if systemctl is-active smbd &>/dev/null || systemctl is-enabled smbd &>/dev/null; then
    systemctl restart smbd 2>/dev/null && RESTARTED=1 && log_action "Restarted smbd"
  fi
  if systemctl is-active nmbd &>/dev/null || systemctl is-enabled nmbd &>/dev/null; then
    systemctl restart nmbd 2>/dev/null && log_action "Restarted nmbd"
  fi
  if systemctl is-active samba &>/dev/null || systemctl is-enabled samba &>/dev/null; then
    systemctl restart samba 2>/dev/null && RESTARTED=1 && log_action "Restarted samba"
  fi

  if [ "$RESTARTED" -eq 0 ]; then
    log_action "Samba services not running, changes apply on next start"
  fi

  log_action "Samba hardening complete"
  log_action "Security applied: SMBv1 disabled, encryption required, guest disabled, NTLMv1 disabled, signing mandatory"
  log_action "Next steps: Add users with 'smbpasswd -a <user>' and 'usermod -aG samba_users <user>'"
}