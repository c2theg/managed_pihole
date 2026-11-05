#!/bin/bash
#  By: Christpher Gray | Version 6.4.0 | Updated: 11/5/2026
#  Updated by: Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#  Install:  wget https://raw.githubusercontent.com/c2theg/srvBuilds/refs/heads/master/install_pihole.sh && chmod u+x install_pihole.sh
#
#  ChangeLog:
#    6.4.0  11/5/2026  (Claude Code) NEW: MCP server for AI agents (ENABLE_MCP, default true).
#                      Installs mcp_server.py to ${PIHOLE_BASE}/mcp, creates a locked system
#                      user "dnsmcp" that can only run it (SSH forced command), a Pi-hole app
#                      password for it, and a sudo rule for exactly two read-only
#                      unbound-control commands. Agents connect with: ssh dnsmcp@<host>
#                      New maintenance commands: mcp, mcp-add-key KEY|FILE.
#    6.3.0  11/5/2026  (Claude Code) Unbound: extended-statistics and unbound-control on
#                      127.0.0.1 inside the container (not published), so mcp_server.py can
#                      read stats with `docker exec unbound unbound-control stats_noreset`.
#    6.2.0  11/5/2026  (Claude Code) Import and configure ALL managed lists automatically:
#      - Lists are imported by default with no prompt (IMPORT_LISTS=false to skip).
#      - Pi-hole: pihole_exclude_list.txt -> webserver.api.excludeDomains (regex form).
#      - Pi-hole: social "unbreak" regexes are now ENABLED and assigned only to the
#        group "Allow_Social" (created automatically) instead of being added disabled.
#      - NEW SOCIAL_CLIENTS="ip|name ...": devices allowed to use social media.
#        Pi-hole: added as clients in Default + Allow_Social. AdGuard Home:
#        passed to upsert_adguardhome.py --social-clients.
#      - cgray_blocklists.txt now also subscribes url_general_blocklist.txt,
#        cgray_religion_school.txt and toolz_adblock_test.txt.
#    6.1.0  11/5/2026  (Claude Code)
#      - NEW: DNS_FILTER=pihole|adguardhome. AdGuard Home can run in place of Pi-hole,
#        in front of the same Unbound (+ dnscrypt-proxy). Its first-run wizard is
#        completed automatically (user "admin", same generated password), upstream is
#        set to Unbound, and the managed lists are synced with upsert_adguardhome.py
#        (from c2theg/managed_pihole) - daily, like Pi-hole.
#      - FIX: exact allowlist sync read only "pihole -w"/"pihole allow" lines. The v6
#        pihole_allowlist.sh uses an "allow" helper, so those lines are now read too.
#    6.0.0  11/5/2026  Pi-hole v6 + Unbound + dnscrypt-proxy + WireGuard (Docker).
#
# Pi-hole v6 (or AdGuard Home) + Unbound + dnscrypt-proxy (DoH / ODoH) + optional WireGuard
# Docker installer for Ubuntu 22.04 / 24.04 / 26.04. Safe to re-run: keeps the
# admin password, WireGuard keys and peers, and the Pi-hole database.
#
# ---------------------------------------------------------------------------
# Resolution path
# ---------------------------------------------------------------------------
#
#   LAN / VPN clients
#        │  :53 (UDP/TCP)
#        ▼
#   Pi-hole or AdGuard Home (DNS_FILTER) ─ blocklists, regex, allowlists, DoH-bypass blocking, rate limit
#        │  172.31.53.53:53   (Docker network only, not published)
#        ▼
#   Unbound  ─ DNSSEC validation, cache, prefetch, serve-stale, rebind
#        │     protection, hardening
#        │  172.31.53.54:5053 (Docker network only, not published)
#        ▼
#   dnscrypt-proxy ─ DNS-over-HTTPS (doh) or Oblivious DoH (odoh)
#        │  HTTPS :443
#        ▼
#   Upstream resolvers (default: 1.1.1.2, 208.67.222.123, 2606:4700:4700::1002)
#
#   UPSTREAM_MODE=dot   → Unbound speaks DNS-over-TLS directly (no dnscrypt-proxy)
#   UPSTREAM_MODE=plain → Unbound forwards over plain UDP/TCP 53
#
# ---------------------------------------------------------------------------
# Scheduled maintenance (systemd timers, installed by this script)
# ---------------------------------------------------------------------------
#   daily   ~03:30  sync c2theg/managed_pihole lists + gravity update
#   weekly  Sun     refresh CA certificates (drop expired), renew Pi-hole TLS
#                   cert, pull and redeploy updated container images
#   Manual: sudo ${PIHOLE_BASE}/pihole-maint.sh {daily|weekly|lists|certs|images|add-peer NAME|status}
#
# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
#   sudo bash install_pihole.sh
#
#   Non-interactive (every prompt has an env override):
#     sudo UPSTREAM_MODE=doh IMPORT_LISTS=true ENABLE_WIREGUARD=true \
#          WG_ENDPOINT=vpn.example.com WG_PEERS="phone laptop" bash install_pihole.sh
#
#   Render the config files without touching the system (for review):
#     RENDER_ONLY=true PIHOLE_BASE=/tmp/ph bash install_pihole.sh
#
# Options (env vars)
#   PIHOLE_BASE            install dir                       (default: /opt/pihole)
#   DNS_FILTER             pihole | adguardhome              (default: prompt, else pihole)
#   UPSTREAM_MODE          doh | odoh | dot | plain          (default: doh)
#   DNS_V4                 space-separated IPv4 resolvers    (default: "1.1.1.2 208.67.222.123")
#   DNS_V6                 space-separated IPv6 resolvers    (default: "2606:4700:4700::1002")
#   NEXTDNS_ID             use NextDNS over DoH instead of DNS_V4/DNS_V6
#   ODOH_SERVERS           ODoH targets (dnscrypt names)     (default: "odoh-cloudflare odoh-snowstorm odoh-crypto-sx")
#   ENABLE_IPV6            auto | true | false               (default: auto)
#   IMPORT_LISTS           true | false                      (default: true - no prompt)
#   SOCIAL_CLIENTS         IPs / hostnames / MACs allowed to use social media, space separated
#                          (default: none - social sites stay blocked for everyone)
#   BLOCK_DOH_BYPASS       block public DoH endpoints so clients cannot skip Pi-hole (default: true)
#   LOG_RETENTION_DAYS     query DB + log retention          (default: 10)
#   AUTO_UPDATE_IMAGES     weekly image pull + redeploy      (default: true)
#   CONDITIONAL_FORWARDING resolve LAN hostnames via router  (default: false; uses LAN_CIDR/ROUTER_IP/LOCAL_DOMAIN or auto-detect)
#   ENABLE_WIREGUARD       true | false                      (default: prompt, else false)
#   WG_ENDPOINT            public hostname/IP for clients    (default: auto-detect public IPv4)
#   WG_PORT                (default: 47111)   WG_PEERS (default: "client1")
#   WG_TUNNEL              full | dns  (all traffic through VPN, or DNS only) (default: full)
#   PIHOLE_HTTP_PORT / PIHOLE_HTTPS_PORT (default: 80 / 443)
#   ENABLE_MCP             read-only MCP server for AI agents, over SSH (default: true)
#   MCP_USER               system user the agent logs in as  (default: dnsmcp)
#   MCP_SSH_KEYS           public key(s) allowed to start it  (default: the sudo user's
#                          authorized_keys; later: pihole-maint.sh mcp-add-key KEY|FILE)
#   TZ                     (default: America/New_York)
#
# References
#   https://docs.pi-hole.net/docker/
#   https://docs.pi-hole.net/guides/dns/unbound/
#   https://docs.pi-hole.net/guides/vpn/wireguard/
#   https://github.com/DNSCrypt/dnscrypt-proxy/wiki
#   https://github.com/c2theg/managed_pihole

set -euo pipefail

# =============================================================
# Configuration
# =============================================================

RENDER_ONLY="${RENDER_ONLY:-false}"
# Older versions installed into the current directory; keep using it if found.
if [[ -z "${PIHOLE_BASE:-}" && -d "$(pwd)/etc-pihole" ]]; then PIHOLE_BASE="$(pwd)"; fi
PIHOLE_BASE="${PIHOLE_BASE:-/opt/pihole}"
TZ="${TZ:-America/New_York}"
PIHOLE_HTTP_PORT="${PIHOLE_HTTP_PORT:-80}"
PIHOLE_HTTPS_PORT="${PIHOLE_HTTPS_PORT:-443}"

DNS_FILTER="${DNS_FILTER:-}"
UPSTREAM_MODE="${UPSTREAM_MODE:-}"
DNS_V4="${DNS_V4:-1.1.1.2 208.67.222.123}"
DNS_V6="${DNS_V6:-2606:4700:4700::1002}"
ODOH_SERVERS="${ODOH_SERVERS:-odoh-cloudflare odoh-snowstorm odoh-crypto-sx}"
ENABLE_IPV6="${ENABLE_IPV6:-auto}"

IMPORT_LISTS="${IMPORT_LISTS:-true}"   # all managed lists are imported unless set to false
SOCIAL_CLIENTS="${SOCIAL_CLIENTS:-}"
BLOCK_DOH_BYPASS="${BLOCK_DOH_BYPASS:-true}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-10}"
AUTO_UPDATE_IMAGES="${AUTO_UPDATE_IMAGES:-true}"
MANAGED_REPO_RAW="${MANAGED_REPO_RAW:-https://raw.githubusercontent.com/c2theg/managed_pihole/refs/heads/main}"
ENABLE_MCP="${ENABLE_MCP:-true}"
MCP_USER="${MCP_USER:-dnsmcp}"
MCP_SSH_KEYS="${MCP_SSH_KEYS:-}"
[[ "${MCP_USER}" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || { echo "MCP_USER must be a valid user name." >&2; exit 1; }

CONDITIONAL_FORWARDING="${CONDITIONAL_FORWARDING:-false}"
LAN_CIDR="${LAN_CIDR:-}"
ROUTER_IP="${ROUTER_IP:-}"
LOCAL_DOMAIN="${LOCAL_DOMAIN:-lan}"

ENABLE_WIREGUARD="${ENABLE_WIREGUARD:-}"
WG_ENDPOINT="${WG_ENDPOINT:-}"
WG_PORT="${WG_PORT:-47111}"
WG_PEERS="${WG_PEERS:-client1}"
WG_TUNNEL="${WG_TUNNEL:-full}"
WG_NET4="10.100.0"          # Pi-hole WireGuard guide defaults
WG_NET6="fd08:4711:"

# Internal Docker network. Static IPs are required because Pi-hole (dnsmasq)
# upstreams must be IP addresses, not container names.
DNS_NET_PREFIX="${DNS_NET_PREFIX:-172.31.53}"
DNS_NET6="fd53:53:53::/64"
IP_PIHOLE="${DNS_NET_PREFIX}.10"
IP_UNBOUND="${DNS_NET_PREFIX}.53"
IP_DNSCRYPT="${DNS_NET_PREFIX}.54"

COMPOSE_FILE="${PIHOLE_BASE}/docker-compose.yml"
MAINT="${PIHOLE_BASE}/pihole-maint.sh"
ENV_FILE="${PIHOLE_BASE}/pihole.env"
SECRETS_FILE="${PIHOLE_BASE}/secrets/pihole_password.txt"

# =============================================================
# Helpers
# =============================================================

info() { printf '  \033[1;34m[i]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
is_true() { [[ "$(lower "${1:-}")" =~ ^(1|y|yes|true|on)$ ]]; }
interactive() { [[ -t 0 && "${RENDER_ONLY}" != "true" ]]; }

# ask_yn VAR "Question" default(y|n)
ask_yn() {
  local __var=$1 __q=$2 __def=$3 __ans
  if [[ -n "${!__var}" ]]; then return; fi
  if interactive; then
    read -rp "  ${__q} [$([[ ${__def} == y ]] && echo Y/n || echo y/N)]: " __ans
    __ans="$(lower "${__ans:-${__def}}")"
  else
    __ans="${__def}"
  fi
  if [[ "${__ans}" =~ ^y ]]; then printf -v "${__var}" true; else printf -v "${__var}" false; fi
}

# DoH / DoT hostname for well-known resolver IPs (used to build TLS SNI and
# DNS stamps). Unknown IPs can still be used in plain mode.
doh_host_for() {
  case "$1" in
    1.1.1.1|1.0.0.1|2606:4700:4700::1111|2606:4700:4700::1001) echo "cloudflare-dns.com" ;;
    1.1.1.2|1.0.0.2|2606:4700:4700::1112|2606:4700:4700::1002) echo "security.cloudflare-dns.com" ;;
    1.1.1.3|1.0.0.3|2606:4700:4700::1113|2606:4700:4700::1003) echo "family.cloudflare-dns.com" ;;
    208.67.222.123|208.67.220.123|2620:119:35::123|2620:119:53::123) echo "doh.familyshield.opendns.com" ;;
    208.67.222.222|208.67.220.220|2620:119:35::35|2620:119:53::53)   echo "doh.opendns.com" ;;
    9.9.9.9|149.112.112.112|2620:fe::fe|2620:fe::9)               echo "dns.quad9.net" ;;
    8.8.8.8|8.8.4.4|2001:4860:4860::8888|2001:4860:4860::8844)    echo "dns.google" ;;
    *) return 1 ;;
  esac
}

# OpenDNS does not offer DNS-over-TLS.
dot_capable() { [[ "$1" != *opendns.com ]]; }

# Build a DoH DNS stamp (https://dnscrypt.info/stamps-specifications).
# props bitmask: 1 = DNSSEC, 2 = no logs, 4 = no filter
doh_stamp() {
  python3 -I - "$@" <<'PY'
import sys, base64, struct
props, addr, host, path = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
lp = lambda s: bytes([len(s.encode())]) + s.encode()
data = bytes([0x02]) + struct.pack('<Q', props) + lp(addr) + b'\x00' + lp(host) + lp(path)
print('sdns://' + base64.urlsafe_b64encode(data).decode().rstrip('='))
PY
}

host_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  fi
  [[ -z "${ip}" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "${ip:-127.0.0.1}"
}

wan_if() { ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }

# =============================================================
# Pre-flight
# =============================================================

if [[ "${RENDER_ONLY}" != "true" ]]; then
  [[ $EUID -eq 0 ]] || die "Run this script with sudo or as root."
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || warn "Tested on Ubuntu only (detected: ${PRETTY_NAME:-unknown}). Continuing."
  fi
fi
command -v python3 >/dev/null 2>&1 || die "python3 is required (used to build DNS stamps)."

# =============================================================
# Interactive choices (before any system change)
# =============================================================

section "Configuration"

if [[ -z "${DNS_FILTER}" ]]; then
  DNS_FILTER="pihole"
  if interactive; then
    cat <<'EOF'

  DNS filter (both use Unbound + the managed lists)
    1) pihole       - Pi-hole v6 (recommended)
    2) adguardhome  - AdGuard Home

EOF
    read -rp "  Choose [1-2] (default 1): " _f
    case "${_f}" in 2|adguard*) DNS_FILTER=adguardhome ;; *) DNS_FILTER=pihole ;; esac
  fi
fi
DNS_FILTER="$(lower "${DNS_FILTER}")"
[[ "${DNS_FILTER}" =~ ^(pihole|adguardhome)$ ]] || die "DNS_FILTER must be pihole or adguardhome."

if [[ -z "${UPSTREAM_MODE}" ]]; then
  UPSTREAM_MODE="doh"
  if interactive; then
    cat <<'EOF'

  Upstream encryption
    1) doh   - DNS-over-HTTPS to 1.1.1.2 / 208.67.222.123 / 2606:4700:4700::1002  (recommended)
               Upstream malware/adult filtering stays active.
    2) odoh  - Oblivious DoH via relays: the resolver never sees your IP.
               ODoH targets do NOT filter; protection comes from Pi-hole lists only.
    3) dot   - DNS-over-TLS straight from Unbound (Cloudflare only; OpenDNS has no DoT).
    4) plain - Unencrypted DNS (not recommended).

EOF
    read -rp "  Choose [1-4] (default 1): " _m
    case "${_m}" in 2|odoh) UPSTREAM_MODE=odoh ;; 3|dot) UPSTREAM_MODE="dot" ;; 4|plain) UPSTREAM_MODE=plain ;; *) UPSTREAM_MODE=doh ;; esac
  fi
fi
UPSTREAM_MODE="$(lower "${UPSTREAM_MODE}")"
[[ "${UPSTREAM_MODE}" =~ ^(doh|odoh|dot|plain)$ ]] || die "UPSTREAM_MODE must be doh, odoh, dot or plain."

if [[ "${UPSTREAM_MODE}" == "doh" && -z "${NEXTDNS_ID+x}" ]] && interactive; then
  read -rp "  NextDNS config ID to use instead of the defaults (Enter to skip): " NEXTDNS_ID
fi
NEXTDNS_ID="${NEXTDNS_ID:-}"
[[ -z "${NEXTDNS_ID}" || "${NEXTDNS_ID}" =~ ^[A-Za-z0-9]+$ ]] || die "NEXTDNS_ID must be alphanumeric."

is_true "${IMPORT_LISTS}" && IMPORT_LISTS=true || IMPORT_LISTS=false
if [[ "${IMPORT_LISTS}" == "true" ]]; then
  info "Managed lists from github.com/c2theg/managed_pihole will be imported and synced daily:"
  info "  block lists, regex deny/allow, exact allowlist, excluded domains, social group,"
  info "  DoH-bypass blocking. First gravity/filter build takes ~5-10 min. (IMPORT_LISTS=false to skip)"
  if [[ -z "${SOCIAL_CLIENTS}" ]] && interactive; then
    read -rp "  Devices allowed to use social media (IPs/hostnames, space separated, Enter = none): " SOCIAL_CLIENTS
  fi
fi
[[ -z "${SOCIAL_CLIENTS}" || "${SOCIAL_CLIENTS}" =~ ^[A-Za-z0-9.:_/\ -]+$ ]] || die "SOCIAL_CLIENTS may only contain IPs, subnets, MACs or hostnames."

if [[ -z "${ENABLE_WIREGUARD}" ]] && interactive; then
  echo ""
  echo "  WireGuard VPN lets phones/laptops use this Pi-hole while away from home."
  echo "  Requires forwarding UDP ${WG_PORT} on your router to this host."
fi
ask_yn ENABLE_WIREGUARD "Set up WireGuard VPN access?" n

if is_true "${ENABLE_WIREGUARD}" && [[ -z "${WG_ENDPOINT}" ]] && interactive; then
  read -rp "  Public hostname or IP clients will connect to (Enter = auto-detect): " WG_ENDPOINT
fi

# IPv6 egress: needs a global IPv6 route and Docker >= 27 (ip6tables NAT on by default).
if [[ "${ENABLE_IPV6}" == "auto" ]]; then
  ENABLE_IPV6=false
  if [[ "${RENDER_ONLY}" != "true" ]] && command -v ip >/dev/null 2>&1 \
     && ip -6 route get 2606:4700:4700::1002 >/dev/null 2>&1; then
    ENABLE_IPV6=true
    # An existing Docker older than 27 has no IPv6 NAT by default.
    if command -v docker >/dev/null 2>&1; then
      _dv=$(docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1)
      if [[ "${_dv:-0}" =~ ^[0-9]+$ && "${_dv:-0}" -lt 27 ]]; then
        warn "Docker < 27 detected; IPv6 upstreams disabled (set ENABLE_IPV6=true after upgrading Docker)."
        ENABLE_IPV6=false
      fi
    fi
  fi
fi
is_true "${ENABLE_IPV6}" && ENABLE_IPV6=true || ENABLE_IPV6=false

info "DNS filter    : ${DNS_FILTER}"
info "Upstream mode : ${UPSTREAM_MODE}"
info "IPv6 upstream : ${ENABLE_IPV6}"
info "Managed lists : ${IMPORT_LISTS}"
info "Social clients: ${SOCIAL_CLIENTS:-none}"
info "WireGuard     : ${ENABLE_WIREGUARD}"

# =============================================================
# Directories and secrets
# =============================================================

mkdir -p "${PIHOLE_BASE}"/{etc-pihole,secrets,unbound,dnscrypt,logrotate}
[[ "${DNS_FILTER}" == "adguardhome" ]] && mkdir -p "${PIHOLE_BASE}"/adguardhome/{work,conf}
chmod 700 "${PIHOLE_BASE}/secrets"

if [[ -s "${SECRETS_FILE}" ]]; then
  PIHOLE_PASSWORD=$(cat "${SECRETS_FILE}")
  info "Reusing admin password from ${SECRETS_FILE}"
elif [[ -n "${PIHOLE_PASSWORD:-}" ]]; then
  printf '%s' "${PIHOLE_PASSWORD}" > "${SECRETS_FILE}"
else
  # set +o pipefail: head closes the pipe early, sending SIGPIPE to tr.
  PIHOLE_PASSWORD=$(set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9!#%*+,.:;=?@^_~' </dev/urandom | head -c 24)
  printf '%s' "${PIHOLE_PASSWORD}" > "${SECRETS_FILE}"
  NEW_PASSWORD=true
fi
chmod 600 "${SECRETS_FILE}"

# =============================================================
# Unbound configuration
# =============================================================
# Loaded after the image's base unbound.conf (later values win).

UNBOUND_IP6=no
FORWARD_BLOCK=""
case "${UPSTREAM_MODE}" in
  doh|odoh)
    FORWARD_BLOCK="    forward-addr: ${IP_DNSCRYPT}@5053"
    ;;
  dot)
    FORWARD_BLOCK="    forward-tls-upstream: yes"
    for ip in ${DNS_V4} $( [[ ${ENABLE_IPV6} == true ]] && echo "${DNS_V6}" ); do
      if h=$(doh_host_for "${ip}") && dot_capable "${h}"; then
        FORWARD_BLOCK+=$'\n'"    forward-addr: ${ip}@853#${h}"
      else
        warn "Skipping ${ip} in DoT mode (no known DNS-over-TLS endpoint)."
      fi
    done
    [[ ${ENABLE_IPV6} == true ]] && UNBOUND_IP6=yes
    ;;
  plain)
    for ip in ${DNS_V4} $( [[ ${ENABLE_IPV6} == true ]] && echo "${DNS_V6}" ); do
      FORWARD_BLOCK+="${FORWARD_BLOCK:+$'\n'}    forward-addr: ${ip}@53"
    done
    [[ ${ENABLE_IPV6} == true ]] && UNBOUND_IP6=yes
    ;;
esac
grep -q 'forward-addr' <<<"${FORWARD_BLOCK}" || die "No usable upstream resolvers for mode ${UPSTREAM_MODE}."

cat > "${PIHOLE_BASE}/unbound/pihole.conf" <<UNBOUND_CONF
# Generated by install_pihole.sh. Re-running the installer overwrites this file.
server:
    verbosity: 0
    log-queries: no
    log-replies: no
    log-servfail: no
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: ${UNBOUND_IP6}
    do-udp: yes
    do-tcp: yes

    # Only the internal Docker network may query Unbound
    access-control: 0.0.0.0/0 refuse
    access-control: ::0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ${DNS_NET_PREFIX}.0/24 allow

    # Privacy / information leakage
    hide-identity: yes
    hide-version: yes
    hide-trustanchor: yes
    qname-minimisation: yes
    minimal-responses: yes

    # DNSSEC and hardening (validation happens here, not in Pi-hole)
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-algo-downgrade: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    harden-unknown-additional: yes
    aggressive-nsec: yes
    val-clean-additional: yes
    deny-any: yes
    unwanted-reply-threshold: 10000000
    use-caps-for-id: no
    edns-buffer-size: 1232

    # DNS-rebinding protection: public names may not resolve to private IPs
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: ::ffff:0:0/96
    private-domain: "${LOCAL_DOMAIN}"

    # Cache and performance
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-client-timeout: 1800
    cache-min-ttl: 0
    cache-max-ttl: 86400
    cache-max-negative-ttl: 3600
    msg-cache-size: 64m
    rrset-cache-size: 128m
    rrset-roundrobin: yes
    so-reuseport: yes
    infra-keep-probing: yes

    # rcode / query-type / DNSSEC counters for unbound-control stats (mcp_server.py)
    extended-statistics: yes

# unbound-control for stats. Loopback inside the container only (no port is published),
# so certificates are not needed: docker exec unbound unbound-control stats_noreset
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-use-cert: no

forward-zone:
    name: "."
    forward-first: no
${FORWARD_BLOCK}
UNBOUND_CONF
chmod 755 "${PIHOLE_BASE}/unbound"
chmod 644 "${PIHOLE_BASE}/unbound/pihole.conf"

# =============================================================
# dnscrypt-proxy configuration (doh / odoh)
# =============================================================

UPSTREAM_DESC=""
if [[ "${UPSTREAM_MODE}" == "doh" || "${UPSTREAM_MODE}" == "odoh" ]]; then
  STATIC_BLOCK=""
  SERVER_NAMES=()
  BOOTSTRAP=()
  for ip in ${DNS_V4}; do BOOTSTRAP+=("'${ip}:53'"); done

  if [[ "${UPSTREAM_MODE}" == "doh" ]]; then
    if [[ -n "${NEXTDNS_ID}" ]]; then
      # Empty address: resolved once via bootstrap_resolvers, then cached.
      stamp=$(doh_stamp 3 "" "dns.nextdns.io" "/${NEXTDNS_ID}")
      STATIC_BLOCK+=$'\n'"  [static.'nextdns']"$'\n'"  stamp = '${stamp}'"
      SERVER_NAMES+=("'nextdns'")
      UPSTREAM_DESC="NextDNS ${NEXTDNS_ID} (DoH)"
    else
      for ip in ${DNS_V4} $( [[ ${ENABLE_IPV6} == true ]] && echo "${DNS_V6}" ); do
        if ! h=$(doh_host_for "${ip}"); then
          warn "Skipping ${ip} in DoH mode (no known DoH endpoint; use UPSTREAM_MODE=plain for it)."
          continue
        fi
        addr="${ip}"; [[ "${ip}" == *:* ]] && addr="[${ip}]"
        name="doh-$(tr -c 'A-Za-z0-9' '-' <<<"${ip}" | sed 's/-*$//')"
        stamp=$(doh_stamp 1 "${addr}" "${h}" "/dns-query")
        STATIC_BLOCK+=$'\n'"  [static.'${name}']"$'\n'"  stamp = '${stamp}'"
        SERVER_NAMES+=("'${name}'")
        UPSTREAM_DESC+="${UPSTREAM_DESC:+, }${ip} (${h})"
      done
    fi
    [[ ${#SERVER_NAMES[@]} -gt 0 ]] || die "No DoH-capable upstreams in DNS_V4/DNS_V6."
  else
    for s in ${ODOH_SERVERS}; do SERVER_NAMES+=("'${s}'"); done
    UPSTREAM_DESC="ODoH: ${ODOH_SERVERS} (via relays)"
  fi

  join() { local IFS=,; echo "$*"; }

  cat > "${PIHOLE_BASE}/dnscrypt/dnscrypt-proxy.toml" <<DNSCRYPT_CONF
# Generated by install_pihole.sh (mode: ${UPSTREAM_MODE}). Re-running the installer overwrites this file.
server_names = [$(join "${SERVER_NAMES[@]}")]
listen_addresses = ['0.0.0.0:5053']
max_clients = 512

ipv4_servers = true
ipv6_servers = ${ENABLE_IPV6}
dnscrypt_servers = false
doh_servers = $([[ ${UPSTREAM_MODE} == doh ]] && echo true || echo false)
odoh_servers = $([[ ${UPSTREAM_MODE} == odoh ]] && echo true || echo false)

# Unbound validates DNSSEC; filtering upstreams are intentional.
require_dnssec = false
require_nolog = false
require_nofilter = false

force_tcp = false
http3 = false
timeout = 3000
keepalive = 30
lb_strategy = 'p2'
lb_estimator = true
cert_refresh_delay = 240

# Plain DNS is only used to fetch resolver lists / resolve ODoH hostnames.
bootstrap_resolvers = [$(join "${BOOTSTRAP[@]}")]
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '$(awk '{print $1}' <<<"${DNS_V4}"):53'

block_ipv6 = false
block_unqualified = true
block_undelegated = true
reject_ttl = 10

# Unbound does the caching.
cache = false
log_level = 2

DNSCRYPT_CONF

  if [[ "${UPSTREAM_MODE}" == "odoh" ]]; then
    cat >> "${PIHOLE_BASE}/dnscrypt/dnscrypt-proxy.toml" <<'ODOH_CONF'
[sources]
  [sources.odoh-servers]
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md']
  cache_file = 'odoh-servers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 73
  [sources.odoh-relays]
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md']
  cache_file = 'odoh-relays.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 73

[anonymized_dns]
# '*' picks a relay on a different network from the target server.
routes = [ { server_name='*', via=['*'] } ]
skip_incompatible = true
ODOH_CONF
  else
    printf '[static]%s\n' "${STATIC_BLOCK}" >> "${PIHOLE_BASE}/dnscrypt/dnscrypt-proxy.toml"
  fi
  chmod 644 "${PIHOLE_BASE}/dnscrypt/dnscrypt-proxy.toml"
  # dnscrypt-proxy runs as nonroot (65532) and writes list caches here.
  chown -R 65532:65532 "${PIHOLE_BASE}/dnscrypt" 2>/dev/null || chmod 777 "${PIHOLE_BASE}/dnscrypt"
else
  for ip in ${DNS_V4} $( [[ ${ENABLE_IPV6} == true ]] && echo "${DNS_V6}" ); do
    UPSTREAM_DESC+="${UPSTREAM_DESC:+, }${ip}"
  done
fi

# =============================================================
# Pi-hole log rotation (bind-mounted over the image default)
# =============================================================
# The query database is trimmed by FTL (database.maxDBdays). Text logs are
# rotated daily by the container's 00:00 "pihole flush" job.

cat > "${PIHOLE_BASE}/logrotate/pihole" <<LOGROTATE
/var/log/pihole/pihole.log
/var/log/pihole/FTL.log
/var/log/pihole/webserver.log {
    # su #
    daily
    create 640 pihole pihole
    rotate ${LOG_RETENTION_DAYS}
    maxage ${LOG_RETENTION_DAYS}
    compress
    delaycompress
    notifempty
    missingok
    nomail
    nodateext
    sharedscripts
    postrotate
        . /opt/pihole/utils.sh; pid="\$(getFTLPID)"; [ "\${pid}" -gt 0 ] && kill -USR2 "\${pid}" 2>/dev/null || true
    endscript
}
LOGROTATE
chmod 644 "${PIHOLE_BASE}/logrotate/pihole"

# =============================================================
# docker-compose.yml
# =============================================================

REV_SERVER_LINE=""
if is_true "${CONDITIONAL_FORWARDING}"; then
  if [[ -z "${ROUTER_IP}" ]]; then ROUTER_IP=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}'); fi
  if [[ -z "${LAN_CIDR}" ]]; then
    LAN_CIDR=$(ip -4 route show dev "$(wan_if)" scope link 2>/dev/null | awk '$1 ~ /\// {print $1; exit}')
  fi
  if [[ -n "${ROUTER_IP}" && -n "${LAN_CIDR}" ]]; then
    REV_SERVER_LINE="      FTLCONF_dns_revServers: \"true,${LAN_CIDR},${ROUTER_IP},${LOCAL_DOMAIN}\""
  else
    warn "Could not detect LAN_CIDR/ROUTER_IP; conditional forwarding not enabled."
  fi
fi

LOGGING='    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"'

if [[ "${DNS_FILTER}" == "adguardhome" ]]; then
  FILTER_SVC=$(cat <<AGH_SVC
  adguardhome:
    image: adguard/adguardhome:latest
    container_name: adguardhome
    restart: unless-stopped
    depends_on:
      unbound:
        condition: service_healthy
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "${PIHOLE_HTTP_PORT}:80/tcp"
      - "${PIHOLE_HTTPS_PORT}:443/tcp"
      # First-run wizard (:3000) is finished by the installer over the Docker network.
    networks:
      dnsnet:
        ipv4_address: ${IP_PIHOLE}
    environment:
      TZ: "${TZ}"
    volumes:
      - "${PIHOLE_BASE}/adguardhome/work:/opt/adguardhome/work"
      - "${PIHOLE_BASE}/adguardhome/conf:/opt/adguardhome/conf"
    cap_add:
      - NET_ADMIN      # only needed for DHCP; harmless otherwise
    security_opt:
      - no-new-privileges:true
    healthcheck:
      # :80 after setup, :3000 while the first-run wizard is waiting
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:80/login.html || wget -q -O /dev/null http://127.0.0.1:3000/install.html"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
${LOGGING}
AGH_SVC
)
else
  FILTER_SVC=$(cat <<PIHOLE_SVC
  pihole:
    image: pihole/pihole:latest
    container_name: pihole
    hostname: pi.hole
    restart: unless-stopped
    depends_on:
      unbound:
        condition: service_healthy
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "${PIHOLE_HTTP_PORT}:80/tcp"
      - "${PIHOLE_HTTPS_PORT}:443/tcp"
      # Uncomment to use Pi-hole as the DHCP server (also see docs.pi-hole.net/docker/DHCP):
      # - "67:67/udp"
    networks:
      dnsnet:
        ipv4_address: ${IP_PIHOLE}
    environment:
      TZ: "${TZ}"
      WEBPASSWORD_FILE: pihole_password          # name of the Docker secret below
      FTLCONF_dns_listeningMode: "ALL"           # required on a bridge network

      # Upstream: Unbound only (Unbound forwards via ${UPSTREAM_MODE})
      FTLCONF_dns_upstreams: "${IP_UNBOUND}#53"
      FTLCONF_dns_dnssec: "false"                # Unbound validates; avoid double validation

      # Hygiene
      FTLCONF_dns_domainNeeded: "true"           # never forward single-label names
      FTLCONF_dns_bogusPriv: "true"              # never forward private reverse lookups
      FTLCONF_dns_blockESNI: "true"
      FTLCONF_dns_specialDomains_mozillaCanary: "true"       # keep Firefox from auto-enabling DoH
      FTLCONF_dns_specialDomains_iCloudPrivateRelay: "true"  # keep iCloud Private Relay from bypassing Pi-hole
      FTLCONF_dns_specialDomains_designatedResolver: "true"  # block DDR auto-upgrade to other resolvers
      FTLCONF_dns_blocking_mode: "NULL"
      FTLCONF_dns_rateLimit_count: "1000"
      FTLCONF_dns_rateLimit_interval: "60"
      FTLCONF_dns_cache_size: "10000"
${REV_SERVER_LINE}

      # Retention: ${LOG_RETENTION_DAYS} days of query history
      FTLCONF_database_maxDBdays: "${LOG_RETENTION_DAYS}"
      FTLCONF_database_network_expire: "${LOG_RETENTION_DAYS}"

      # Host keeps time (systemd-timesyncd); container cannot set the clock
      FTLCONF_ntp_sync_active: "false"

      FTLCONF_webserver_tls_validity: "47"
    volumes:
      - "${PIHOLE_BASE}/etc-pihole:/etc/pihole"
      - "${PIHOLE_BASE}/logrotate/pihole:/etc/logrotate.d/pihole:ro"
    secrets:
      - pihole_password
    cap_add:
      - NET_ADMIN      # only needed for DHCP; harmless otherwise
      - SYS_NICE
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "dig", "+norecurse", "+retry=0", "@127.0.0.1", "pi.hole"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
${LOGGING}
PIHOLE_SVC
)
fi

{
  echo "# Generated by install_pihole.sh. Re-running the installer overwrites this file."
  echo "name: pihole"
  echo "services:"

  if [[ "${UPSTREAM_MODE}" == "doh" || "${UPSTREAM_MODE}" == "odoh" ]]; then
    cat <<DNSCRYPT_SVC

  dnscrypt-proxy:
    image: klutchell/dnscrypt-proxy:latest
    container_name: dnscrypt-proxy
    restart: unless-stopped
    volumes:
      - "${PIHOLE_BASE}/dnscrypt:/config"
    networks:
      dnsnet:
        ipv4_address: ${IP_DNSCRYPT}
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "/usr/local/bin/dnsprobe", "cloudflare.com", "127.0.0.1:5053"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
${LOGGING}
DNSCRYPT_SVC
    UNBOUND_DEPENDS='    depends_on:
      dnscrypt-proxy:
        condition: service_healthy'
  else
    UNBOUND_DEPENDS=""
  fi

  cat <<UNBOUND_SVC

  unbound:
    image: klutchell/unbound:latest
    container_name: unbound
    restart: unless-stopped
${UNBOUND_DEPENDS}
    volumes:
      - "${PIHOLE_BASE}/unbound:/etc/unbound/custom.conf.d:ro"
    networks:
      dnsnet:
        ipv4_address: ${IP_UNBOUND}
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "drill-hc", "cloudflare.com", "@127.0.0.1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
${LOGGING}

${FILTER_SVC}

networks:
  dnsnet:
    name: pihole_dnsnet
    driver: bridge
UNBOUND_SVC

  if [[ "${ENABLE_IPV6}" == "true" ]]; then
    echo "    enable_ipv6: true"
  fi
  echo "    ipam:"
  echo "      config:"
  echo "        - subnet: ${DNS_NET_PREFIX}.0/24"
  if [[ "${ENABLE_IPV6}" == "true" ]]; then
    echo "        - subnet: ${DNS_NET6}"
  fi
  cat <<SECRETS

secrets:
  pihole_password:
    file: ${SECRETS_FILE}
SECRETS
} > "${COMPOSE_FILE}"
# Drop blank lines left by empty optional blocks
sed -i.bak '/^[[:space:]]*$/N;/^\n[[:space:]]*$/D' "${COMPOSE_FILE}" && rm -f "${COMPOSE_FILE}.bak"

# =============================================================
# Settings file read by the maintenance script
# =============================================================

cat > "${ENV_FILE}" <<ENVFILE
# Generated by install_pihole.sh, read by pihole-maint.sh
PIHOLE_BASE="${PIHOLE_BASE}"
DNS_FILTER="${DNS_FILTER}"
FILTER_IP="${IP_PIHOLE}"
UNBOUND_IP="${IP_UNBOUND}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS}"
MANAGED_LISTS="${IMPORT_LISTS}"
MANAGED_REPO_RAW="${MANAGED_REPO_RAW}"
ENABLE_MCP="${ENABLE_MCP}"
MCP_USER="${MCP_USER}"
BLOCK_DOH_BYPASS="${BLOCK_DOH_BYPASS}"
SOCIAL_CLIENTS="${SOCIAL_CLIENTS}"
AUTO_UPDATE_IMAGES="${AUTO_UPDATE_IMAGES}"
ENABLE_WIREGUARD="${ENABLE_WIREGUARD}"
WG_PORT="${WG_PORT}"
WG_TUNNEL="${WG_TUNNEL}"
WG_NET4="${WG_NET4}"
WG_NET6="${WG_NET6}"
WG_IPV6="${ENABLE_IPV6}"
ENVFILE
chmod 600 "${ENV_FILE}"

# =============================================================
# Maintenance script (lists, certificates, images, WireGuard peers)
# =============================================================

cat > "${MAINT}" <<'MAINT_SCRIPT'
#!/bin/bash
# pihole-maint.sh: generated by install_pihole.sh
#   daily     sync managed lists (if enabled) + gravity update
#   weekly    certs + images
#   lists     sync c2theg/managed_pihole into gravity.db and run gravity
#   certs     refresh host CA store (drop expired CAs), renew Pi-hole TLS cert
#   images    pull new images, redeploy, prune
#   add-peer  NAME   create a WireGuard client config (+ QR code)
#   status    container health and DNS self-test
#   setup-agh finish AdGuard Home first-run setup + upstream (DNS_FILTER=adguardhome)
#   mcp       install/refresh the read-only MCP server for AI agents (ENABLE_MCP)
#   mcp-add-key KEY|FILE  allow an SSH public key to start the MCP server (and nothing else)
set -euo pipefail
BASE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck disable=SC1091
. "${BASE}/pihole.env"
TAG="managed:c2theg"

log()  { echo "[$(date '+%F %T')] $*"; }
warn() { echo "[$(date '+%F %T')] WARNING: $*" >&2; }
is_true() { [[ "${1,,}" =~ ^(1|y|yes|true|on)$ ]]; }
sqlq() { printf '%s' "${1//\'/\'\'}"; }

wait_healthy() {
  local c=$1 tries=${2:-60} s
  for ((i = 0; i < tries; i++)); do
    s=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$c" 2>/dev/null || echo missing)
    [[ "$s" == "healthy" ]] && return 0
    sleep 3
  done
  warn "$c is not healthy (status: $s). Check: docker logs $c"
  return 1
}

fetch() { curl -fsSL --retry 3 --retry-delay 5 --max-time 120 "${MANAGED_REPO_RAW}/$1"; }

# Comment-free, trimmed, CR-free lines
clean() { tr -d '\r' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | grep -vE '^(#|$)' || true; }
domains_only() { tr '[:upper:]' '[:lower:]' | grep -E '^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$' || true; }

sync_lists() {
  is_true "${MANAGED_LISTS}" || { log "Managed lists disabled; skipping sync."; return 0; }
  local sql ok=true raw
  sql=$(mktemp)

  {
    echo "BEGIN TRANSACTION;"
    echo "UPDATE adlist SET comment='${TAG}' WHERE comment='cgray managed blocklist';"
    echo "CREATE TEMP TABLE want_ad(address TEXT PRIMARY KEY);"
    echo "CREATE TEMP TABLE want_dom(type INTEGER, domain TEXT, enabled INTEGER, PRIMARY KEY(type, domain));"
    echo "CREATE TEMP TABLE want_social(domain TEXT PRIMARY KEY);"
  } > "${sql}"

  # adlists (type 0 = blocklist)
  if raw=$(fetch cgray_blocklists.txt); then
    while IFS= read -r url; do
      echo "INSERT OR IGNORE INTO want_ad VALUES ('$(sqlq "$url")');" >> "${sql}"
    done < <(clean <<<"$raw" | sed -E 's/[[:space:]]+#.*$//' | grep -E '^https?://[^[:space:]]+$' | sort -u)
  else ok=false; warn "Could not fetch cgray_blocklists.txt"; fi

  # domainlist types: 0 exact allow, 1 exact deny, 2 regex allow, 3 regex deny
  add_dom() { # type enabled < lines
    while IFS= read -r d; do
      [[ -n "$d" ]] && echo "INSERT OR IGNORE INTO want_dom VALUES ($1, '$(sqlq "$d")', $2);" >> "${sql}"
    done
  }
  regex_lines() { clean | sed -E 's/[[:space:]]+#.*$//'; }

  if raw=$(fetch blocklist_regexs_cg.txt); then regex_lines <<<"$raw" | add_dom 3 1
  else ok=false; warn "Could not fetch blocklist_regexs_cg.txt"; fi

  if raw=$(fetch allowlist_regexs_cg.txt); then regex_lines <<<"$raw" | add_dom 2 1
  else ok=false; warn "Could not fetch allowlist_regexs_cg.txt"; fi

  # Social "unbreak" regexes are meant for selected clients only: enabled, but
  # assigned to the "Allow_Social" group instead of the Default group (see below).
  if raw=$(fetch allow_regex_social_cg.txt); then
    regex_lines <<<"$raw" | add_dom 2 1
    while IFS= read -r d; do
      [[ -n "$d" ]] && echo "INSERT OR IGNORE INTO want_social VALUES ('$(sqlq "$d")');" >> "${sql}"
    done < <(regex_lines <<<"$raw")
  else ok=false; warn "Could not fetch allow_regex_social_cg.txt"; fi

  # Exact allowlist: "pihole -w a b c" lines plus bare domain lines
  if raw=$(fetch pihole_allowlist.sh); then
    { tr -d '\r' <<<"$raw" | grep -E '^[[:space:]]*(pihole[[:space:]]+)?(-w|allow)[[:space:]]' \
        | sed -E 's/^[[:space:]]*(pihole[[:space:]]+)?(-w|allow)[[:space:]]+//; s/#.*$//' | tr -s ' \t' '\n\n'
      clean <<<"$raw"; } | domains_only | sort -u | add_dom 0 1
  else ok=false; warn "Could not fetch pihole_allowlist.sh"; fi

  # Public DoH endpoints: blocking them stops browsers/apps from bypassing Pi-hole.
  if is_true "${BLOCK_DOH_BYPASS}"; then
    if raw=$(fetch doh_servers.txt); then clean <<<"$raw" | sed -E 's/[[:space:]]+#.*$//' | domains_only | sort -u | add_dom 1 1
    else ok=false; warn "Could not fetch doh_servers.txt"; fi
  fi
  # Firefox canary domain: always NXDOMAIN (also handled by FTL special domains)
  echo "INSERT OR IGNORE INTO want_dom VALUES (1, 'use-application-dns.net', 1);" >> "${sql}"

  cat >> "${sql}" <<SQL
INSERT OR IGNORE INTO adlist (address, enabled, comment) SELECT address, 1, '${TAG}' FROM want_ad;
INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) SELECT type, domain, enabled, '${TAG}' FROM want_dom;
UPDATE domainlist SET enabled = 1 WHERE comment = '${TAG}' AND type = 2 AND domain IN (SELECT domain FROM want_social);

-- Social group: social regexes apply only to clients in "Allow_Social"
INSERT OR IGNORE INTO "group" (enabled, name, description) VALUES (1, 'Allow_Social', 'managed_pihole: clients allowed to use social media');
DELETE FROM domainlist_by_group WHERE group_id = 0
  AND domainlist_id IN (SELECT id FROM domainlist WHERE type = 2 AND domain IN (SELECT domain FROM want_social));
INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id)
  SELECT d.id, g.id FROM domainlist d, "group" g
  WHERE g.name = 'Allow_Social' AND d.type = 2 AND d.domain IN (SELECT domain FROM want_social);
SQL
  # Social clients: keep them in Default (so all block lists still apply) + Allow_Social
  local c
  for c in ${SOCIAL_CLIENTS:-}; do
    cat >> "${sql}" <<SQL
INSERT OR IGNORE INTO client (ip, comment) VALUES ('$(sqlq "$c")', '${TAG}');
INSERT OR IGNORE INTO client_by_group (client_id, group_id) SELECT id, 0 FROM client WHERE ip = '$(sqlq "$c")';
INSERT OR IGNORE INTO client_by_group (client_id, group_id)
  SELECT c.id, g.id FROM client c, "group" g WHERE c.ip = '$(sqlq "$c")' AND g.name = 'Allow_Social';
SQL
  done
  # Prune entries removed upstream, but only when every source downloaded.
  if $ok; then
    cat >> "${sql}" <<SQL
DELETE FROM adlist WHERE comment='${TAG}' AND address NOT IN (SELECT address FROM want_ad);
DELETE FROM domainlist WHERE comment='${TAG}'
  AND NOT EXISTS (SELECT 1 FROM want_dom w WHERE w.type = domainlist.type AND w.domain = domainlist.domain);
SQL
  else
    warn "Some sources failed; adding new entries only (no pruning this run)."
  fi
  echo "COMMIT;" >> "${sql}"

  log "Applying managed lists to gravity.db..."
  docker exec -i pihole pihole-FTL sqlite3 /etc/pihole/gravity.db < "${sql}" || { rm -f "${sql}"; return 1; }
  rm -f "${sql}"
  # Excluded domains (hidden from dashboard top lists / query log), v6 regex form:
  #   example.com -> ^example\.com$     *.example.com -> (^|\.)example\.com$
  local excl
  if raw=$(fetch pihole_exclude_list.txt); then
    excl=$(clean <<<"$raw" | python3 -I -c '
import json, sys
out = []
for e in (l.strip().lower() for l in sys.stdin):
    if not e:
        continue
    r = ("(^|\\.)" + e[2:].replace(".", "\\.") + "$") if e.startswith("*.") else ("^" + e.replace(".", "\\.") + "$")
    if r not in out:
        out.append(r)
print(json.dumps(out))')
    if docker exec pihole pihole-FTL --config webserver.api.excludeDomains "${excl}" >/dev/null; then
      log "Excluded domains: $(python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)))' <<<"${excl}") set (webserver.api.excludeDomains)."
    else
      warn "Could not set webserver.api.excludeDomains (is FTLCONF_webserver_api_excludeDomains set in the compose file?)"
    fi
  else warn "Could not fetch pihole_exclude_list.txt"; fi

  log "Managed: $(docker exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db \
    "SELECT (SELECT count(*) FROM adlist WHERE comment='${TAG}') || ' adlists, ' || \
            (SELECT count(*) FROM domainlist WHERE comment='${TAG}') || ' domain/regex entries';")"
}

# ---- AdGuard Home (DNS_FILTER=adguardhome) ----
AGH_FILES="upsert_adguardhome.py pihole_api.py cgray_blocklists.txt blocklist_regexs_cg.txt
allowlist_regexs_cg.txt allow_regex_social_cg.txt pihole_allowlist.sh doh_servers.txt pihole_exclude_list.txt"
agh_pw() { cat "${PIHOLE_BASE}/secrets/pihole_password.txt"; }

# Finish the first-run wizard (only if AdGuard Home has not been set up yet).
agh_setup() {
  local base="http://${FILTER_IP}" code
  if [[ ! -s "${PIHOLE_BASE}/adguardhome/conf/AdGuardHome.yaml" ]]; then
    log "Configuring AdGuard Home (first run)..."
    for ((i = 0; i < 40; i++)); do curl -fsS -o /dev/null "${base}:3000/control/install/get_addresses" && break; sleep 3; done
    python3 -I -c 'import json,sys; print(json.dumps({"web":{"ip":"0.0.0.0","port":80},"dns":{"ip":"0.0.0.0","port":53},"username":"admin","password":sys.stdin.read()}))' <<<"$(agh_pw)" \
      | curl -fsS -H 'Content-Type: application/json' -X POST --data-binary @- "${base}:3000/control/install/configure" >/dev/null
  fi
  # Wait for the web API on :80 WITHOUT credentials (5 bad logins = 15 min lock-out)
  for ((i = 0; i < 40; i++)); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${base}/control/status" || true)
    [[ "$code" == "401" || "$code" == "200" ]] && break; sleep 3
  done
  # Upstream = Unbound; Unbound validates DNSSEC. Retention = LOG_RETENTION_DAYS.
  agh_api POST /control/dns_config "{\"upstream_dns\":[\"${UNBOUND_IP}:53\"],\"bootstrap_dns\":[\"${UNBOUND_IP}:53\"],\"dnssec_enabled\":false}"
  local ms=$(( ${LOG_RETENTION_DAYS:-10} * 86400000 ))
  for kind in querylog stats; do
    agh_api GET "/control/${kind}/config" "" | python3 -I -c 'import json,sys; c=json.load(sys.stdin); c["interval"]=int(sys.argv[1]); print(json.dumps(c))' "$ms" \
      | agh_api PUT "/control/${kind}/config/update" @-
  done
  log "AdGuard Home ready: upstream ${UNBOUND_IP}:53, retention ${LOG_RETENTION_DAYS:-10} days."
}
agh_api() { # METHOD PATH DATA  (DATA "@-" = stdin)
  curl -fsS -u "admin:$(agh_pw)" -H 'Content-Type: application/json' -X "$1" \
    ${3:+--data-binary "$3"} "http://${FILTER_IP}$2"
}

sync_lists_agh() {
  is_true "${MANAGED_LISTS}" || { log "Managed lists disabled; skipping sync."; return 0; }
  local dir="${PIHOLE_BASE}/managed" f extra=""
  mkdir -p "$dir"
  for f in ${AGH_FILES}; do fetch "$f" > "$dir/$f.tmp" && mv "$dir/$f.tmp" "$dir/$f" || warn "Could not fetch $f (keeping old copy)"; done
  is_true "${BLOCK_DOH_BYPASS}" && extra="--block-doh"
  local social="${SOCIAL_CLIENTS:-}"; social="${social// /|}"
  log "Applying managed lists to AdGuard Home (and refreshing filters)..."
  ADGUARD_URL="http://${FILTER_IP}" ADGUARD_USER=admin ADGUARD_PASSWORD="$(agh_pw)" \
    python3 "$dir/upsert_adguardhome.py" --dir "$dir" ${extra} ${social:+--social-clients "$social"}
}

# ---- MCP server for AI agents (read-only stats, started over SSH) ----
MCP_FILES="mcp_server.py pihole_api.py upsert_adguardhome.py"
MCP_DIR="${PIHOLE_BASE}/mcp"
MCP_USER="${MCP_USER:-dnsmcp}"

mcp_fetch() { # newest files from the repo; keeps the current copy if a download fails
  local f
  mkdir -p "${MCP_DIR}"; chmod 755 "${MCP_DIR}"
  for f in ${MCP_FILES}; do
    if fetch "$f" > "${MCP_DIR}/$f.tmp" 2>/dev/null; then mv "${MCP_DIR}/$f.tmp" "${MCP_DIR}/$f"
    else rm -f "${MCP_DIR}/$f.tmp"; [[ -s "${MCP_DIR}/$f" ]] || { warn "Could not fetch $f"; return 1; }; fi
  done
  chown root:root "${MCP_DIR}"/*.py; chmod 755 "${MCP_DIR}"/*.py
}

# Prints an app password for the MCP user: the current one if it still works, else a new
# one (Pi-hole keeps ONE app password, webserver.api.app_pwhash). App-password sessions
# cannot change Pi-hole settings (webserver.api.app_sudo = false).
mcp_pihole_app_pw() {
  python3 -I - "http://${FILTER_IP}/api" "${PIHOLE_BASE}/secrets/pihole_password.txt" "${MCP_DIR}/managed_pihole.conf" <<'PY'
import json, sys, urllib.request
api, pwfile, conf = sys.argv[1:4]
def call(method, path, body=None, sid=None):
    hdr = {"Content-Type": "application/json"}
    if sid: hdr["X-FTL-SID"] = sid
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(urllib.request.Request(api + path, data, hdr, method=method), timeout=30) as r:
        raw = r.read()
    return json.loads(raw) if raw.strip() else {}
why = []
def login(pw):
    try:
        s = call("POST", "/auth", {"password": pw}).get("session", {})
    except Exception as e:
        why.append(str(e))
        return None
    why.append(s.get("message") or "")
    return s.get("sid") if s.get("valid") else None
old = None
try:
    for line in open(conf):
        if line.startswith("PIHOLE_PASSWORD="):
            old = line.split("=", 1)[1].strip().strip("'\"")
except OSError:
    pass
if old:
    sid = login(old)
    if sid:
        call("DELETE", "/auth", sid=sid)
        print(old)
        sys.exit(0)
sid = login(open(pwfile).read().strip())
if not sid:
    sys.exit("Pi-hole login failed: %s (all %s API seats in use? see webserver.api.max_sessions)"
             % (why[-1] if why else "?", "16"))
app = call("GET", "/auth/app", sid=sid)["app"]
call("PATCH", "/config", {"config": {"webserver": {"api": {"app_pwhash": app["hash"]}}}}, sid=sid)
# Changing a password ends every session (this one too), so no logout is needed.
sid = login(app["password"])
if not sid:
    sys.exit("Pi-hole did not accept the new app password")
call("DELETE", "/auth", sid=sid)
print(app["password"])
PY
}

mcp_add_key() { # KEY lines or a .pub / authorized_keys FILE
  local src="$1" home ak key n=0
  [[ -r "$src" ]] && src=$(cat "$src")
  home=$(getent passwd "${MCP_USER}" | cut -d: -f6)
  [[ -n "$home" ]] || { warn "User ${MCP_USER} does not exist; run: $0 mcp"; return 1; }
  ak="$home/.ssh/authorized_keys"
  install -d -m 700 -o "${MCP_USER}" -g "${MCP_USER}" "$home/.ssh"
  touch "$ak"
  while IFS= read -r key; do
    key=$(sed -E 's/^[[:space:]]+//' <<<"$key")
    # only plain key lines; lines that already carry options (from=, command= ...) are skipped
    [[ "$key" =~ ^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)[[:space:]]+[A-Za-z0-9+/=]+ ]] || continue
    key=$(awk '{print $1" "$2" "$3}' <<<"$key" | sed -E 's/ +$//')
    grep -qF "$(awk '{print $2}' <<<"$key")" "$ak" && continue
    # forced command + restrict: this key can only start the MCP server (no shell,
    # no port forwarding, no pty), whatever the client asks for
    echo "command=\"${MCP_DIR}/mcp_server.py\",restrict ${key}" >> "$ak"
    n=$((n + 1))
  done <<<"$src"
  chown "${MCP_USER}:${MCP_USER}" "$ak"; chmod 600 "$ak"
  log "MCP: ${n} key(s) added, $(grep -c '^command=' "$ak" || true) total (${ak})."
}

mcp_setup() {
  is_true "${ENABLE_MCP:-false}" || { log "ENABLE_MCP is off; skipping."; return 0; }
  mcp_fetch || { warn "MCP server files are missing; skipping MCP setup."; return 1; }
  if ! id -u "${MCP_USER}" >/dev/null 2>&1; then
    # no password (locked): the only way in is an SSH key with the forced command
    useradd --system --create-home --home-dir "/var/lib/${MCP_USER}" --shell /bin/bash \
            --comment "managed_pihole MCP server (read-only DNS stats)" "${MCP_USER}"
  fi
  local conf="${MCP_DIR}/managed_pihole.conf" docker_bin services creds pw
  docker_bin=$(command -v docker)
  if [[ "${DNS_FILTER:-pihole}" == "adguardhome" ]]; then
    # AdGuard Home has no read-only accounts; the admin login is used.
    services="adguardhome,unbound"
    creds="ADGUARD_URL=http://${FILTER_IP}
ADGUARD_USER=admin
ADGUARD_PASSWORD='$(agh_pw)'"
  else
    services="pihole,unbound"
    pw=$(mcp_pihole_app_pw) || { warn "Could not create a Pi-hole app password for MCP."; return 1; }
    creds="PIHOLE_API_URL=http://${FILTER_IP}/api
PIHOLE_PASSWORD='${pw}'"
  fi
  install -m 640 -o root -g "${MCP_USER}" /dev/null "${conf}.tmp"   # never world-readable
  cat > "${conf}.tmp" <<CONF
# Generated by pihole-maint.sh mcp - read by ${MCP_DIR}/mcp_server.py as user ${MCP_USER}
MCP_SERVICES=${services}
${creds}
UNBOUND_CONTROL=sudo -n ${docker_bin} exec unbound unbound-control
CONF
  mv "${conf}.tmp" "${conf}"
  # sudo for exactly these two read-only commands, nothing else
  local rule="/etc/sudoers.d/${MCP_USER}"
  printf '# managed_pihole MCP server: read-only Unbound stats\n%s ALL=(root) NOPASSWD: %s exec unbound unbound-control stats_noreset, %s exec unbound unbound-control status\n' \
    "${MCP_USER}" "${docker_bin}" "${docker_bin}" > "${rule}.tmp"
  chmod 440 "${rule}.tmp"
  if visudo -cqf "${rule}.tmp"; then mv "${rule}.tmp" "${rule}"; else rm -f "${rule}.tmp"; warn "sudo rule invalid; Unbound stats disabled."; fi
  [[ -n "${MCP_SSH_KEYS:-}" ]] && mcp_add_key "${MCP_SSH_KEYS}"
  if runuser -u "${MCP_USER}" -- "${MCP_DIR}/mcp_server.py" --test 2>&1 | grep -q 'queries"'; then
    log "MCP server OK: ${MCP_DIR}/mcp_server.py (${services}) as user ${MCP_USER}."
  else
    warn "MCP self-test did not return stats. Check: sudo runuser -u ${MCP_USER} -- ${MCP_DIR}/mcp_server.py --test"
  fi
}

gravity() {
  log "Running gravity update (downloads all adlists)..."
  docker exec pihole pihole -g 2>&1 | grep --line-buffered -E '\[(i|✓|✗)\]|Number of|Error' || true
  log "Gravity update finished."
}

refresh_cas() {
  log "Refreshing host CA certificates..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || warn "apt-get update failed"
  apt-get install -y -qq --only-upgrade ca-certificates openssl >/dev/null 2>&1 \
    || apt-get install -y -qq ca-certificates openssl >/dev/null

  local f rel removed=0 bk="/var/backups/expired-ca-certificates"
  # Distrust expired CAs that ship in the Mozilla bundle (marked with "!").
  if [[ -f /etc/ca-certificates.conf ]]; then
    while IFS= read -r -d '' f; do
      if ! openssl x509 -checkend 0 -noout -in "$f" >/dev/null 2>&1; then
        rel="${f#/usr/share/ca-certificates/}"
        if grep -qxF "$rel" /etc/ca-certificates.conf; then
          awk -v r="$rel" '$0 == r { $0 = "!" r } 1' /etc/ca-certificates.conf > /etc/ca-certificates.conf.tmp \
            && mv /etc/ca-certificates.conf.tmp /etc/ca-certificates.conf
          log "  distrusted expired CA: $rel"; removed=$((removed + 1))
        fi
      fi
    done < <(find /usr/share/ca-certificates -type f -name '*.crt' -print0)
  fi
  # Move expired locally-installed CAs out of the trust path.
  if [[ -d /usr/local/share/ca-certificates ]]; then
    while IFS= read -r -d '' f; do
      if ! openssl x509 -checkend 0 -noout -in "$f" >/dev/null 2>&1; then
        mkdir -p "$bk" && mv "$f" "$bk/" && log "  removed expired local CA: $f (backup in $bk)"
        removed=$((removed + 1))
      fi
    done < <(find /usr/local/share/ca-certificates -type f -name '*.crt' -print0)
  fi
  update-ca-certificates --fresh >/dev/null
  log "CA store rebuilt ($(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt) trusted roots, ${removed} expired removed)."
}

renew_pihole_tls() {
  local d="${PIHOLE_BASE}/etc-pihole" renew=false
  [[ -f "$d/tls.pem" ]] || return 0
  # Renew 7 days before expiry; FTL regenerates missing certs on start.
  openssl x509 -checkend $((7 * 86400)) -noout -in "$d/tls.pem" >/dev/null 2>&1 || renew=true
  if [[ -f "$d/tls_ca.crt" ]] && ! openssl x509 -checkend $((7 * 86400)) -noout -in "$d/tls_ca.crt" >/dev/null 2>&1; then
    renew=true; rm -f "$d/tls_ca.crt"
  fi
  if $renew; then
    log "Pi-hole web TLS certificate expires within 7 days: regenerating."
    rm -f "$d/tls.pem" "$d/tls.crt"
    docker restart pihole >/dev/null && wait_healthy pihole
  else
    log "Pi-hole TLS cert valid until $(openssl x509 -enddate -noout -in "$d/tls.pem" | cut -d= -f2)."
  fi
}

update_images() {
  is_true "${AUTO_UPDATE_IMAGES}" || { log "AUTO_UPDATE_IMAGES=false; skipping image updates."; return 0; }
  cd "${PIHOLE_BASE}"
  log "Pulling container images..."
  docker compose pull -q
  docker compose up -d --remove-orphans
  for c in $(docker compose ps --format '{{.Name}}'); do wait_healthy "$c" || true; done
  docker image prune -f >/dev/null
  log "Images up to date."
}

add_peer() {
  is_true "${ENABLE_WIREGUARD}" || { echo "WireGuard is not enabled. Re-run the installer with ENABLE_WIREGUARD=true." >&2; exit 1; }
  local name=$1 conf=/etc/wireguard/wg0.conf dir="${PIHOLE_BASE}/wireguard/clients" n priv pub psk endpoint allowed dns addr
  [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "Peer name must be alphanumeric (A-Z a-z 0-9 _ -)." >&2; exit 1; }
  mkdir -p "$dir"; chmod 700 "${PIHOLE_BASE}/wireguard" "$dir"
  if [[ -f "$dir/$name.conf" ]]; then echo "Peer $name already exists: $dir/$name.conf"; return 0; fi
  for ((n = 2; n < 255; n++)); do grep -q "AllowedIPs = ${WG_NET4}.${n}/32" "$conf" || break; done
  [[ $n -lt 255 ]] || { echo "No free peer addresses." >&2; exit 1; }
  priv=$(wg genkey); pub=$(wg pubkey <<<"$priv"); psk=$(wg genpsk)
  endpoint=$(cat "${PIHOLE_BASE}/wireguard/endpoint")
  addr="${WG_NET4}.${n}/32"; dns="${WG_NET4}.1"
  [[ "$WG_IPV6" == "true" ]] && { addr+=", ${WG_NET6}:${n}/128"; dns+=", ${WG_NET6}:1"; }
  if [[ "$WG_TUNNEL" == "dns" ]]; then
    allowed="${WG_NET4}.1/32"; [[ "$WG_IPV6" == "true" ]] && allowed+=", ${WG_NET6}:1/128"
  else
    allowed="0.0.0.0/0, ::/0"
  fi
  {
    echo ""
    echo "[Peer]"
    echo "# ${name}"
    echo "PublicKey = ${pub}"
    echo "PresharedKey = ${psk}"
    echo "AllowedIPs = ${WG_NET4}.${n}/32$([[ "$WG_IPV6" == "true" ]] && echo ", ${WG_NET6}:${n}/128")"
  } >> "$conf"
  (umask 077; cat > "$dir/$name.conf" <<PEER
[Interface]
PrivateKey = ${priv}
Address = ${addr}
DNS = ${dns}

[Peer]
PublicKey = $(cat /etc/wireguard/server.pub)
PresharedKey = ${psk}
Endpoint = ${endpoint}:${WG_PORT}
AllowedIPs = ${allowed}
PersistentKeepalive = 25
PEER
  )
  if systemctl is-active --quiet wg-quick@wg0; then wg syncconf wg0 <(wg-quick strip wg0); fi
  echo "Created WireGuard peer '${name}': $dir/$name.conf"
  command -v qrencode >/dev/null && qrencode -t ansiutf8 < "$dir/$name.conf"
}

status() {
  cd "${PIHOLE_BASE}" && docker compose ps
  echo ""
  echo -n "Resolve cloudflare.com        : "; dig +short +time=3 @127.0.0.1 cloudflare.com A | head -1
  echo -n "DNSSEC valid (isc.org)        : "; dig +time=3 @127.0.0.1 isc.org SOA | grep -q ' ad[ ;]' && echo "AD flag set (validated)" || echo "NOT validated"
  echo -n "DNSSEC bogus (dnssec-failed)  : "; dig +time=3 @127.0.0.1 dnssec-failed.org A | grep -q 'status: SERVFAIL' && echo "SERVFAIL (correct)" || echo "resolved (validation NOT working)"
  echo -n "Blocking (doubleclick.net)    : "; dig +short +time=3 @127.0.0.1 doubleclick.net A | head -1
}

if [[ "${DNS_FILTER:-pihole}" == "adguardhome" ]]; then
  # Same commands, AdGuard Home versions. Lists are refreshed by upsert_adguardhome.py.
  sync_lists() { sync_lists_agh; }
  gravity() { :; }
  renew_pihole_tls() { :; }
fi

case "${1:-}" in
  daily)    sync_lists; gravity; if is_true "${ENABLE_MCP:-false}"; then mcp_fetch || true; fi ;;
  weekly)   refresh_cas; renew_pihole_tls; update_images ;;
  lists)    sync_lists; gravity ;;
  setup-agh) agh_setup ;;
  mcp)      mcp_setup ;;
  mcp-add-key) mcp_add_key "${2:?usage: $0 mcp-add-key 'ssh-ed25519 AAAA... name' | FILE}" ;;
  certs)    refresh_cas; renew_pihole_tls ;;
  images)   update_images ;;
  add-peer) add_peer "${2:?usage: $0 add-peer NAME}" ;;
  status)   status ;;
  *) echo "usage: $0 {daily|weekly|lists|certs|images|add-peer NAME|status|setup-agh|mcp|mcp-add-key KEY}" >&2; exit 2 ;;
esac
MAINT_SCRIPT
chmod 700 "${MAINT}"

if [[ "${RENDER_ONLY}" == "true" ]]; then
  ok "Rendered config to ${PIHOLE_BASE} (RENDER_ONLY=true; no system changes made)."
  exit 0
fi

# =============================================================
# Host packages, time sync, CA certificates
# =============================================================

section "Host preparation"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl openssl dnsutils python3 >/dev/null
ok "Base packages installed"

# Accurate time is required for DNSSEC signature and TLS validity checks.
timedatectl set-ntp true 2>/dev/null || warn "Could not enable NTP via timedatectl"

"${MAINT}" certs || warn "CA refresh reported a problem; continuing."

# =============================================================
# Docker
# =============================================================

section "Docker"
if ! command -v docker >/dev/null 2>&1; then
  info "Installing Docker via get.docker.com..."
  curl -fsSL https://get.docker.com | sh
  if [[ -n "${SUDO_USER:-}" ]]; then usermod -aG docker "${SUDO_USER}"; fi
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y -qq docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null 2>&1 || true
ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')  |  Compose $(docker compose version --short)"

# =============================================================
# Free port 53 from systemd-resolved (keep the service running)
# =============================================================

if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/pihole.conf <<'RESOLVED_CONF'
[Resolve]
DNSStubListener=no
RESOLVED_CONF
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
  ok "systemd-resolved stub listener disabled (port 53 free)"
fi

# =============================================================
# WireGuard (https://docs.pi-hole.net/guides/vpn/wireguard/)
# =============================================================

setup_wireguard() {
  section "WireGuard"
  apt-get install -y -qq wireguard-tools qrencode iptables >/dev/null
  local wan; wan=$(wan_if)
  [[ -n "${wan}" ]] || die "Could not determine the WAN interface for WireGuard NAT."

  if [[ -z "${WG_ENDPOINT}" ]]; then
    WG_ENDPOINT=$(curl -4fsS --max-time 5 https://icanhazip.com 2>/dev/null | tr -d '[:space:]' || true)
    [[ -n "${WG_ENDPOINT}" ]] || die "Could not detect the public IP; set WG_ENDPOINT."
    warn "Using detected public IP ${WG_ENDPOINT}. Use a DynDNS hostname if your IP changes (WG_ENDPOINT=...)."
  fi
  mkdir -p "${PIHOLE_BASE}/wireguard/clients"
  chmod 700 "${PIHOLE_BASE}/wireguard" "${PIHOLE_BASE}/wireguard/clients"
  echo "${WG_ENDPOINT}" > "${PIHOLE_BASE}/wireguard/endpoint"

  # Forwarding (accept_ra=2 keeps IPv6 SLAAC working once forwarding is on)
  {
    echo "net.ipv4.ip_forward = 1"
    if [[ "${ENABLE_IPV6}" == "true" ]]; then
      echo "net.ipv6.conf.all.forwarding = 1"
      echo "net.ipv6.conf.${wan}.accept_ra = 2"
    fi
  } > /etc/sysctl.d/99-pihole-wireguard.conf
  sysctl -q --system

  # Firewall hooks. Docker's FORWARD policy is DROP, so VPN traffic must be
  # allowed in DOCKER-USER (created here if Docker has not started yet).
  cat > /etc/wireguard/pihole-wg-fw.sh <<FW
#!/bin/bash
# Generated by install_pihole.sh. Usage: pihole-wg-fw.sh up|down
A=\$([[ "\$1" == up ]] && echo -I || echo -D)
N=\$([[ "\$1" == up ]] && echo -A || echo -D)
for ipt in iptables $([[ "${ENABLE_IPV6}" == "true" ]] && echo ip6tables); do
  \$ipt -N DOCKER-USER 2>/dev/null || true
  \$ipt \$A DOCKER-USER -i wg0 -j ACCEPT 2>/dev/null || true
  \$ipt \$A DOCKER-USER -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  \$ipt \$A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
  \$ipt \$A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
done
iptables -t nat \$N POSTROUTING -s ${WG_NET4}.0/24 -o ${wan} -j MASQUERADE 2>/dev/null || true
$([[ "${ENABLE_IPV6}" == "true" ]] && echo "ip6tables -t nat \$N POSTROUTING -s ${WG_NET6}:/64 -o ${wan} -j MASQUERADE 2>/dev/null || true")
exit 0
FW
  chmod 700 /etc/wireguard/pihole-wg-fw.sh

  if [[ ! -f /etc/wireguard/wg0.conf ]]; then
    (umask 077
     wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
     cat > /etc/wireguard/wg0.conf <<WG0
# Generated by install_pihole.sh. Add peers with: sudo ${MAINT} add-peer NAME
[Interface]
Address = ${WG_NET4}.1/24$([[ "${ENABLE_IPV6}" == "true" ]] && echo ", ${WG_NET6}:1/64")
ListenPort = ${WG_PORT}
PrivateKey = $(cat /etc/wireguard/server.key)
PostUp = /etc/wireguard/pihole-wg-fw.sh up
PostDown = /etc/wireguard/pihole-wg-fw.sh down
WG0
    )
    ok "WireGuard server keys generated"
  else
    info "Keeping existing /etc/wireguard/wg0.conf and peers"
  fi

  mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
  cat > /etc/systemd/system/wg-quick@wg0.service.d/pihole.conf <<'DROPIN'
[Unit]
After=network-online.target docker.service
Wants=network-online.target
DROPIN
  systemctl daemon-reload
  systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || systemctl restart wg-quick@wg0

  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
    ufw allow "${WG_PORT}/udp" >/dev/null
    ufw allow in on wg0 >/dev/null
    ufw route allow in on wg0 out on "${wan}" >/dev/null
    ok "ufw rules added for WireGuard"
  fi

  for p in ${WG_PEERS//,/ }; do "${MAINT}" add-peer "$p"; done
}

# =============================================================
# Deploy
# =============================================================

section "Deploying containers"
cd "${PIHOLE_BASE}"
docker compose pull -q
# Recreate cleanly so network/IP changes and removed services (e.g. the old
# cloudflared sidecar) apply. Brief DNS outage while containers restart.
docker compose down --remove-orphans >/dev/null 2>&1 || true
# Containers from an older install (different compose project); data lives in
# bind mounts, so removing the containers is safe.
docker rm -f cloudflared pihole adguardhome unbound dnscrypt-proxy >/dev/null 2>&1 || true
docker compose up -d --remove-orphans

wait_all() {
  local c s
  for c in $( [[ "${UPSTREAM_MODE}" == doh || "${UPSTREAM_MODE}" == odoh ]] && echo dnscrypt-proxy ) unbound "${DNS_FILTER}"; do
    printf '  waiting for %-15s' "$c"
    for ((i = 0; i < 60; i++)); do
      s=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$c" 2>/dev/null || echo missing)
      [[ "$s" == "healthy" ]] && break
      printf '.'; sleep 3
    done
    if [[ "$s" == "healthy" ]]; then echo " healthy"; else echo " ${s}"; docker logs --tail 30 "$c" >&2 || true; die "$c did not become healthy."; fi
  done
}
wait_all
[[ "${DNS_FILTER}" == "adguardhome" ]] && "${MAINT}" setup-agh

if is_true "${IMPORT_LISTS}"; then
  section "Managed lists"
  "${MAINT}" lists
fi

if is_true "${ENABLE_MCP}"; then
  section "MCP server (read-only stats for AI agents)"
  mkdir -p "${PIHOLE_BASE}/mcp"
  # Run from a repo checkout? Seed with the local copies (the repo copy wins later if newer).
  _src="$(dirname "$(readlink -f "$0")")"
  for _f in mcp_server.py pihole_api.py upsert_adguardhome.py; do
    [[ -f "${_src}/${_f}" ]] && install -m 755 "${_src}/${_f}" "${PIHOLE_BASE}/mcp/${_f}"
  done
  # Default keys: the ones that can already log in as the sudo user (no new access).
  if [[ -z "${MCP_SSH_KEYS}" && -n "${SUDO_USER:-}" ]]; then
    _ak="$(getent passwd "${SUDO_USER}" | cut -d: -f6)/.ssh/authorized_keys"
    [[ -r "${_ak}" ]] && MCP_SSH_KEYS="${_ak}"
  fi
  MCP_SSH_KEYS="${MCP_SSH_KEYS}" "${MAINT}" mcp || warn "MCP setup reported a problem; DNS is unaffected."
fi

# =============================================================
# Scheduled maintenance (systemd timers)
# =============================================================

section "Scheduling maintenance"
for unit in daily weekly; do
  cat > "/etc/systemd/system/pihole-maint-${unit}.service" <<UNIT
[Unit]
Description=Pi-hole ${unit} maintenance (install_pihole.sh)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
ExecStart=${MAINT} ${unit}
UNIT
done
cat > /etc/systemd/system/pihole-maint-daily.timer <<'TIMER'
[Unit]
Description=Daily Pi-hole list sync and gravity update

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=45m
Persistent=true

[Install]
WantedBy=timers.target
TIMER
cat > /etc/systemd/system/pihole-maint-weekly.timer <<'TIMER'
[Unit]
Description=Weekly Pi-hole CA, TLS and image updates

[Timer]
OnCalendar=Sun *-*-* 04:30:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now pihole-maint-daily.timer pihole-maint-weekly.timer >/dev/null
ok "Timers enabled: $(systemctl list-timers 'pihole-maint-*' --no-legend | wc -l) (systemctl list-timers 'pihole-maint-*')"

if is_true "${ENABLE_WIREGUARD}"; then setup_wireguard; fi

# =============================================================
# Self-test and summary
# =============================================================

section "Self-test"
"${MAINT}" status || true

HOST_IP=$(host_ip)
section "Pi-hole setup complete"
cat <<SUMMARY
  DNS filter     : ${DNS_FILTER}
  Admin UI       : http://${HOST_IP}:${PIHOLE_HTTP_PORT}$( [[ "${DNS_FILTER}" == pihole ]] && echo /admin || echo "/  (user: admin)" )   (https on :${PIHOLE_HTTPS_PORT})
  Password       : $( [[ "${NEW_PASSWORD:-false}" == true ]] && echo "${PIHOLE_PASSWORD}" || echo "(unchanged)" )  -> ${SECRETS_FILE}

  DNS path       : ${DNS_FILTER} -> Unbound (DNSSEC, cache) -> ${UPSTREAM_MODE^^}
  Upstreams      : ${UPSTREAM_DESC}
  IPv6 upstream  : ${ENABLE_IPV6}
  Retention      : ${LOG_RETENTION_DAYS} days (query DB + rotated logs; container logs capped at 30 MB)
  Managed lists  : ${IMPORT_LISTS} (daily sync from github.com/c2theg/managed_pihole)
  Social clients : ${SOCIAL_CLIENTS:-none} (group Allow_Social; others keep social sites blocked)
  Maintenance    : ${MAINT} {daily|weekly|lists|certs|images|add-peer|status|mcp|mcp-add-key}
SUMMARY
if is_true "${ENABLE_MCP}"; then
  cat <<MCPSUM
  MCP (AI agent) : claude mcp add dns -- ssh ${MCP_USER}@${HOST_IP}
                   (the key can only start ${PIHOLE_BASE}/mcp/mcp_server.py; read-only)
                   Add a key: sudo ${MAINT} mcp-add-key ~/.ssh/id_ed25519.pub
MCPSUM
fi
if is_true "${ENABLE_WIREGUARD}"; then
  cat <<WGSUM
  WireGuard      : ${WG_ENDPOINT}:${WG_PORT}/udp  (${WG_TUNNEL} tunnel, DNS ${WG_NET4}.1)
                   Forward UDP ${WG_PORT} on your router to ${HOST_IP}.
                   Client configs: ${PIHOLE_BASE}/wireguard/clients/
                   New client: sudo ${MAINT} add-peer NAME
WGSUM
fi
cat <<NEXT

  Next step      : set your router's DHCP DNS server to ${HOST_IP} (and nothing else).
  Note           : Port 53 is published on all interfaces. Do not expose it to the
                   internet (open resolvers get abused). Docker bypasses ufw.
NEXT
