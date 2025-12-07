
#===============================================
# Firewall
#===============================================

configure_firewall() {
  log_action "=== CONFIGURING ENHANCED UFW FIREWALL ==="

  if ! command -v ufw &>/dev/null; then
    log_action "UFW not found, installing..."
    apt-get install -y ufw &>/dev/null
    log_action "UFW installed"
  else
    log_action "UFW already installed"
  fi

  log_action "Setting UFW default policies..."
  ufw default deny incoming >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  ufw default deny routed >/dev/null 2>&1
  log_action "Default policies: deny incoming, allow outgoing, deny routed"

  log_action "Configuring loopback rules (CIS Benchmark)..."
  ufw allow in on lo >/dev/null 2>&1
  ufw allow out on lo >/dev/null 2>&1
  ufw deny in from 127.0.0.0/8 >/dev/null 2>&1
  ufw deny in from ::1 >/dev/null 2>&1
  log_action "Loopback protection configured"

  log_action "Configuring SSH rate limiting..."
  ufw --force delete allow 22/tcp >/dev/null 2>&1
  ufw --force delete allow ssh >/dev/null 2>&1
  ufw limit 22/tcp >/dev/null 2>&1
  log_action "SSH rate limiting enabled (blocks brute-force attacks)"

  log_action "Setting UFW logging to high..."
  ufw logging high >/dev/null 2>&1

  if [[ -f /etc/default/ufw ]]; then
    if ! grep -q "^IPV6=yes" /etc/default/ufw; then
      sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw 2>/dev/null || echo "IPV6=yes" >> /etc/default/ufw
      log_action "Enabled IPv6 support in UFW"
    fi
  fi

  log_action "Denying unnecessary ports..."
  local unnecessary_ports=("21/tcp" "23/tcp" "25/tcp" "80/tcp" "110/tcp" "143/tcp" "445/tcp" "3389/tcp" "1900/udp")
  
  for port_proto in "${unnecessary_ports[@]}"; do
    local port="${port_proto%/*}"
    local proto="${port_proto#*/}"
    
    local in_use=false
    if command -v ss &>/dev/null; then
      if ss -lntu | awk -v p="$port" -v proto="$proto" '$1 == proto && $5 ~ (":" p "$")' | grep -q .; then
        in_use=true
      fi
    fi

    if [[ "$in_use" == true ]]; then
      log_action "Port $port_proto is in use, skipping deny rule"
    else
      if ! ufw status | grep -q "DENY[[:space:]]\+$port_proto"; then
        ufw deny "$port_proto" >/dev/null 2>&1
        log_action "Denied unused port $port_proto"
      fi
    fi
  done

  log_action "Enabling UFW..."
  echo "y" | ufw enable >/dev/null 2>&1
  
  if command -v systemctl &>/dev/null; then
    systemctl enable ufw >/dev/null 2>&1
  fi

  log_action "Verifying UFW configuration..."
  local status_output=$(ufw status verbose 2>/dev/null)
  
  if echo "$status_output" | grep -q "Status: active"; then
    log_action "UFW is active"
  else
    log_action "WARNING: UFW may not be active"
  fi

  if echo "$status_output" | grep -q "deny (incoming)"; then
    log_action "Default incoming: deny"
  fi

  if echo "$status_output" | grep -q "allow (outgoing)"; then
    log_action "Default outgoing: allow"
  fi

  log_action "Firewall configuration complete"
}