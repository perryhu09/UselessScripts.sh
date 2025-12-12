#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

harden_php(){
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

  log_action "Hardened $hardened_count PHP configuration(s)"

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

run_php_hardening() {
    log_section "Starting Php Hardening"
    harden_php
    log_success "Php Hardening completed"
}

export -f run_php_hardening
