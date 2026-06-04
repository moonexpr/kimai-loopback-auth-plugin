#!/usr/bin/env bash
#
# LoopbackAuth security audit
# ===========================
# Checks whether your Kimai host exposes the loopback-auth surface beyond what
# you intend. It does NOT change anything — it inspects and reports.
#
# What it checks:
#   1. What address the HTTP port is bound to (loopback vs all interfaces).
#   2. Which of this host's non-loopback addresses can actually reach the port,
#      classified as tailnet / LAN / other, with a warning for each.
#   3. The plugin's effective REMOTE_ADDR allowlist (LOOPBACK_AUTH_TRUSTED_IPS).
#   4. nginx config smells: REMOTE_USER set without a geo/map default, and
#      trusted-proxy directives that can move $remote_addr.
#
# Usage:
#   scripts/security-audit.sh [--port 80] [--host 127.0.0.1] [--nginx-conf PATH]
#
# Exit code: 0 = clean, 1 = warnings, 2 = failures.

set -u

PORT=80
HOST=127.0.0.1
NGINX_CONF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --nginx-conf) NGINX_CONF="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

WARN=0; FAIL=0
note() { printf '  %s\n' "$*"; }
ok()   { printf '\033[32m  PASS\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  WARN\033[0m %s\n' "$*"; WARN=$((WARN+1)); }
fail() { printf '\033[31m  FAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
hr()   { printf '\n== %s ==\n' "$*"; }

# Classify an IPv4/IPv6 address into loopback | tailnet | lan | other.
ip_class() {
  case "$1" in
    127.*|::1|::ffff:127.*) echo loopback ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) echo tailnet ;; # 100.64.0.0/10
    fd7a:115c:a1e0:*) echo tailnet ;;                                              # tailscale ULA
    10.*|192.168.*) echo lan ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) echo lan ;;
    *) echo other ;;
  esac
}

# ---------------------------------------------------------------------------
hr "1. HTTP listener binding (port $PORT)"
LISTENERS=""
if command -v ss >/dev/null 2>&1; then
  LISTENERS=$(ss -tlnH 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$" {print $4}')
elif command -v lsof >/dev/null 2>&1; then
  LISTENERS=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $9}')
elif command -v sockstat >/dev/null 2>&1; then
  LISTENERS=$(sockstat -4 -6 -l 2>/dev/null | awk -v p=":$PORT" '$6 ~ p"$" {print $6}')
else
  warn "no ss/lsof/sockstat found — cannot enumerate listeners"
fi

if [ -n "$LISTENERS" ]; then
  printf '%s\n' "$LISTENERS" | sort -u | while read -r L; do note "listening: $L"; done
  if printf '%s\n' "$LISTENERS" | grep -qE '(\*|0\.0\.0\.0|\[::\]):'"$PORT"'$'; then
    warn "port $PORT is bound to ALL interfaces (wildcard). It is reachable from every network this host is on, not just loopback. Bind to 127.0.0.1 if only local access is intended."
  elif printf '%s\n' "$LISTENERS" | grep -qE '(127\.0\.0\.1|\[::1\]):'"$PORT"'$'; then
    ok "port $PORT is bound to loopback only"
  else
    warn "port $PORT is bound to a specific non-loopback address — confirm that network is trusted"
  fi
else
  note "(nothing found listening on $PORT — Kimai may run elsewhere or on a different port; pass --port)"
fi

# ---------------------------------------------------------------------------
hr "2. Reachability from this host's non-loopback addresses"
MYIPS=$(
  { ifconfig 2>/dev/null | awk '/inet /{print $2} /inet6 /{print $2}'; \
    ip -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1; } \
  | grep -vE '^(127\.|::1|fe80)' | sort -u
)
if [ -z "$MYIPS" ]; then
  note "(no non-loopback addresses detected)"
else
  for ip in $MYIPS; do
    cls=$(ip_class "$ip")
    case "$ip" in *:*) url="http://[$ip]:$PORT/";; *) url="http://$ip:$PORT/";; esac
    code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$url" 2>/dev/null)
    [ -z "$code" ] && code="000"
    if [ "$code" = "000" ]; then
      ok "$ip ($cls) — not reachable on $PORT"
    else
      case "$cls" in
        tailnet) warn "$ip (tailnet) — reachable on $PORT (HTTP $code). OK only if you trust every device on this tailnet." ;;
        lan)     fail "$ip (LAN) — reachable on $PORT (HTTP $code). LAN is typically untrusted; Kimai's login surface is exposed to the local network." ;;
        other)   fail "$ip (PUBLIC/other) — reachable on $PORT (HTTP $code). This looks internet-routable — verify a firewall is in front." ;;
        *)       warn "$ip ($cls) — reachable on $PORT (HTTP $code)" ;;
      esac
    fi
  done
fi

# ---------------------------------------------------------------------------
hr "3. Plugin REMOTE_ADDR allowlist"
EFF="${LOOPBACK_AUTH_TRUSTED_IPS:-}"
if [ -z "$EFF" ]; then
  ok "LOOPBACK_AUTH_TRUSTED_IPS unset — plugin defaults to loopback only (127.0.0.1, ::1)"
else
  note "LOOPBACK_AUTH_TRUSTED_IPS = $EFF"
  OLDIFS=$IFS; IFS=','
  for c in $EFF; do
    c=$(echo "$c" | tr -d ' '); [ -z "$c" ] && continue
    base=${c%%/*}
    case "$(ip_class "$base")" in
      loopback) note "  $c -> loopback (safe)" ;;
      tailnet)  warn "  $c -> tailnet: every tailnet device may auto-login passwordless" ;;
      lan)      fail "  $c -> LAN: untrusted network in the auto-login allowlist" ;;
      *)        warn "  $c -> non-loopback range in the auto-login allowlist — confirm it is trusted" ;;
    esac
  done
  IFS=$OLDIFS
fi

# ---------------------------------------------------------------------------
hr "4. nginx config smells"
DUMP=""
if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
  DUMP=$(cat "$NGINX_CONF")
elif command -v nginx >/dev/null 2>&1; then
  DUMP=$(nginx -T 2>/dev/null)
fi
if [ -z "$DUMP" ]; then
  note "(no nginx config available — pass --nginx-conf PATH, or run as a user that can 'nginx -T')"
else
  if printf '%s' "$DUMP" | grep -qE 'fastcgi_param[[:space:]]+REMOTE_USER'; then
    if printf '%s' "$DUMP" | grep -qE '(geo|map)[[:space:]]+\$remote_addr[[:space:]]+\$[A-Za-z0-9_]*' \
       && printf '%s' "$DUMP" | grep -qE '\$kimai_loopback_user|\$loopback'; then
      ok "REMOTE_USER is driven by a geo/map keyed on \$remote_addr"
    else
      fail "REMOTE_USER is set, but not via a geo/map on \$remote_addr — confirm it cannot be set for non-loopback clients"
    fi
  else
    note "no fastcgi_param REMOTE_USER found in the inspected config (Kimai vhost may be elsewhere)"
  fi
  if printf '%s' "$DUMP" | grep -qE 'set_real_ip_from|real_ip_header'; then
    warn "real_ip / set_real_ip_from present — these rewrite \$remote_addr from forwarded headers; make sure they do not let a client spoof a trusted peer address"
  fi
fi

# ---------------------------------------------------------------------------
hr "Summary"
if [ "$FAIL" -gt 0 ]; then
  printf '\033[31m%d failure(s), %d warning(s)\033[0m\n' "$FAIL" "$WARN"; exit 2
elif [ "$WARN" -gt 0 ]; then
  printf '\033[33m%d warning(s)\033[0m\n' "$WARN"; exit 1
else
  printf '\033[32mclean\033[0m\n'; exit 0
fi
