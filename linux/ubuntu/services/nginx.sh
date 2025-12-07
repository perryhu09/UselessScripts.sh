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