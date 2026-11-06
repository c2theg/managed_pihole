#!/bin/bash
#-------------------------------------------------------------------------------
#  deploy_multi_pi.sh  -  ONE Pi-hole serving several VLANs (from a trunk), with
#                         different block lists per VLAN and per-VLAN monitoring
#
#  Version:       1.2.1
#  Last Updated:  11/5/2026
#  Author:        Christopher Gray
#  Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Ubuntu 22.04 / 24.04 / 26.04 VM on Proxmox or VMware, VLANs arriving as a trunk:
#
#      trunk (ens18) ──┬─ untagged          LAN      10.11.1.2/24     (added, or the VM's own)
#                      ├─ vlan200 (exists) Servers  10.13.1.35/24    (management, kept as is)
#                      ├─ vlan666          IoT      172.16.12.2/23   (added by this script)
#                      ├─ vlan2            Kids     192.168.5.2/24   (added by this script)
#                      └─ vlan20           Guest    192.168.13.2/24  (added by this script)
#                                 │
#                     Docker: Pi-hole (+ Unbound + dnscrypt-proxy, install_pihole.sh)
#                             one group per VLAN, its subnet as the client:
#                             normal lists + group_<profile>_*.txt (iot / kids / guest / none)
#
#  What it does (safe to re-run; it only changes what differs):
#    1. checks the hypervisor (Proxmox/KVM or VMware) and prints what to set there
#    2. finds the trunk and the VLAN interfaces already on it (those are kept as is) and adds
#       the missing ones (netplan, static IP, no gateway, no IPv6); any subnet /8 - /30
#    3. installs the Docker stack with install_pihole.sh (Pi-hole, Unbound, dnscrypt-proxy,
#       managed lists, MCP server) unless it is already installed
#    4. one Pi-hole group per VLAN, the VLAN subnet as its client, and extra lists per
#       profile (upsert_vlan_groups.py + group_<profile>_*.txt) - re-synced daily
#    5. "dns-only" VLANs (all but the management one by default): the VM answers DNS (and
#       ping) there and nothing else - no web UI, no SSH, no routing through the VM
#    6. optional per-VLAN reverse lookups (ROUTERS) so reports show device names
#    7. per-VLAN monitoring: `sudo dns-vlan-report`, MCP tools for AI agents
#       (pihole_vlan_report, pihole_client_report) and alerts every 15 minutes when a
#       device hits threat lists, floods, tries to bypass DNS, or gets lots of NXDOMAIN
#       (journal, plus ALERT_WEBHOOK: ntfy / Slack / Discord / any URL)
#
#  Usage:
#    sudo bash deploy_multi_pi.sh          # asks: trunk NIC, each VLAN (ID, name, this VM's
#                                          # IP/prefix, access, lists, router), alert webhook
#    sudo VLANS="Servers:200:auto:full IoT:666:172.16.12.2/23:dns-only:iot Kids:2:192.168.5.2/24::kids" \
#         ROUTERS="Servers=10.13.1.1 IoT=172.16.12.1 Kids=192.168.5.1" \
#         ALERT_WEBHOOK=https://ntfy.sh/my-secret-topic bash deploy_multi_pi.sh
#    DRY_RUN=true bash deploy_multi_pi.sh                           # show what would change
#
#  Settings (env; saved to ${PIHOLE_BASE}/multi_pi.conf and reused on the next run):
#    VLANS        space separated NAME:VLAN_ID:ADDRESS[:MODE[:LISTS]]
#                   NAME     Pi-hole group name (not "Default", that is Pi-hole's own group)
#                   VLAN_ID  0 = untagged / native VLAN of the trunk, 1-4094 = tagged
#                   ADDRESS  this VM's IP/prefix in that VLAN (/8 - /30), or "auto" = the
#                            address it already has there (an existing VLAN interface /
#                            the trunk's own address)
#                   MODE     full | dns-only  (default: full on the management interface -
#                            default route / SSH - dns-only elsewhere)
#                   LISTS    extra list profile: none | iot | kids | guest | <your own>
#                            (default from the name: *iot*->iot, *kid*->kids, *guest*->guest)
#                 not set: asked interactively (re-runs offer the saved setup)
#    TRUNK_IF     interface carrying the trunk  (default: the default-route NIC, or its parent
#                 when that is a VLAN interface such as vlan200@ens18)
#    ROUTERS      "NAME=router-ip ..." per-VLAN reverse DNS (device names in reports)
#    IPV6         auto | off   (default: auto) DNS over IPv6 too: on every VLAN the VM takes
#                 <prefix>IPV6_TOKEN from the prefix(es) your router advertises (SLAAC), the
#                 VLAN's IPv6 prefixes join its Pi-hole group (refreshed hourly), and dns-only
#                 VLANs get the same firewall for IPv6. off = IPv6 switched off on dns-only VLANs.
#    IPV6_TOKEN   interface id of this VM in every IPv6 prefix   (default: ::53)
#    ALERT_WEBHOOK  URL that receives alerts (POST)     (default: none, journal only)
#    ALERT_*      thresholds, see vlan_report.py        (written to the MCP local config)
#    FORCE_STACK=true   re-run install_pihole.sh even if already installed
#    SKIP_STACK=true    never run install_pihole.sh
#    Everything install_pihole.sh understands (UPSTREAM_MODE, SOCIAL_CLIENTS, ...) is
#    passed through. DNS_FILTER is always pihole (groups are a Pi-hole feature).
#
#  ChangeLog:
#    1.2.1  11/6/2026  FIX: netplan "vlan200: missing 'link' property" when your own netplan file
#                      sorts after ours: id/link of your VLANs are repeated with the IPv6 settings.
#    1.2.0  11/6/2026  IPv6: the VM is <prefix>::53 on every VLAN (SLAAC token, also on VLAN
#                      interfaces from your own netplan files), IPv6 prefixes join the VLAN's
#                      group (hourly refresh), dns-only firewall for IPv6 (ip6tables), installer
#                      re-run with SERVE_IPV6 when Docker's network has no IPv6 (real client
#                      addresses). Summary lists each VLAN's IPv6 DNS address. (Claude Code)
#    1.1.3  11/6/2026  Summary: how to show/change the admin password; Unbound has no UI.
#    1.1.2  11/6/2026  FIX: re-running the wizard failed on VLANs this script had added
#                      ("not on this VM yet"), and would have dropped the untagged address it
#                      had added. Its own interfaces/addresses are now kept and managed. (Claude Code)
#    1.1.1  11/6/2026  Settings are saved before install_pihole.sh runs, so a failed or
#                      interrupted install keeps your answers for the re-run. (Claude Code)
#    1.1.0  11/5/2026  Many VLANs: detects VLAN interfaces that already exist on the trunk
#                      (kept as is) and the trunk behind a VLAN default route; untagged VLAN
#                      without an address can get one; any prefix /8-/30 with clear errors
#                      (network/broadcast address, overlaps); list profiles per VLAN
#                      (none/iot/kids/guest); dns-only refused only on the management
#                      interface; "Default" refused as a name. (Claude Code)
#    1.0.0  11/5/2026  New file (Claude Code).
#-------------------------------------------------------------------------------
set -euo pipefail

SCRIPT_VERSION="1.2.1"   # not VERSION: /etc/os-release (sourced below) sets that
SRC_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PIHOLE_BASE="${PIHOLE_BASE:-/opt/pihole}"
SAVED="${PIHOLE_BASE}/multi_pi.conf"
DRY_RUN="${DRY_RUN:-false}"
NETPLAN_FILE=/etc/netplan/60-managed-pihole-vlans.yaml
FW_SCRIPT=/usr/local/sbin/multi-pi-firewall.sh
VLAN_DIR="${PIHOLE_BASE}/vlan"
MCP_DIR="${PIHOLE_BASE}/mcp"
MCP_USER="${MCP_USER:-dnsmcp}"

info() { printf '  \033[1;34m[i]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
is_true() { [[ "${1,,}" =~ ^(1|y|yes|true|on)$ ]]; }
dry() { is_true "${DRY_RUN}"; }
interactive() { [[ -t 0 || "${ASK:-false}" == true ]]; }   # ASK=true: prompt even without a tty
# write FILE from stdin only if the content changed; prints "changed" / "same"
put_file() { # FILE MODE
  local tmp; tmp=$(mktemp)
  cat > "$tmp"
  if [[ -f "$1" ]] && cmp -s "$tmp" "$1"; then rm -f "$tmp"; echo same; return; fi
  if dry; then { echo "----- would write $1:"; cat "$tmp"; } >&2; rm -f "$tmp"; echo changed; return; fi
  install -m "$2" "$tmp" "$1"; rm -f "$tmp"; echo changed
}

# ---- settings: saved file, then environment wins ----
KEYS="VLANS TRUNK_IF ROUTERS ALERT_WEBHOOK MANAGED_REPO_RAW IPV6 IPV6_TOKEN"
declare -A ENV_VAL=()
for k in $KEYS; do [[ -n "${!k:-}" ]] && ENV_VAL[$k]="${!k}"; done
if [[ -r "$SAVED" ]]; then
  # shellcheck disable=SC1090
  . "$SAVED"
fi
for k in "${!ENV_VAL[@]}"; do printf -v "$k" '%s' "${ENV_VAL[$k]}"; done
MANAGED_REPO_RAW="${MANAGED_REPO_RAW:-https://raw.githubusercontent.com/c2theg/managed_pihole/refs/heads/main}"
ROUTERS="${ROUTERS:-}"
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"
IPV6="${IPV6:-auto}"; [[ "${IPV6,,}" =~ ^(off|false|no|0)$ ]] && IPV6=off || IPV6=auto
IPV6_TOKEN="${IPV6_TOKEN:-::53}"
python3 -I -c 'import ipaddress,sys; a=int(ipaddress.IPv6Address(sys.argv[1])); sys.exit(0 if 0 < a < 2**64 else 1)' "${IPV6_TOKEN}" 2>/dev/null \
  || { printf '  IPV6_TOKEN must be an IPv6 interface id such as ::53\n' >&2; exit 1; }

section "deploy_multi_pi.sh ${SCRIPT_VERSION}$(dry && echo '  (DRY RUN - nothing is changed)')"
dry || [[ $EUID -eq 0 ]] || die "Run with sudo (or DRY_RUN=true to preview)."
command -v ip >/dev/null || die "iproute2 (ip) is required."
command -v python3 >/dev/null || { dry && die "python3 is required."; apt-get install -y -qq python3 >/dev/null; }
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == ubuntu ]] || warn "Tested on Ubuntu; this is ${PRETTY_NAME:-unknown}."
fi

# =============================================================
# 1. Hypervisor
# =============================================================
section "Hypervisor"
VIRT=$(systemd-detect-virt 2>/dev/null || true)
case "${VIRT}" in
  kvm|qemu) HV=proxmox ;;
  vmware)   HV=vmware ;;
  *)        HV=other ;;
esac
hv_notes() {
  case "$HV" in
    proxmox) cat <<'EOF'
  Proxmox (KVM detected). For the trunk to reach this VM:
    - Node > System > Network > the bridge of this VM (e.g. vmbr0): tick "VLAN aware", Apply.
      (Linux bridge default bridge-vids 2-4094 already includes every tagged VLAN.)
    - VM > Hardware > Network Device: leave "VLAN Tag" EMPTY. Untagged frames = the native
      VLAN (VLAN 1 on most switches), tagged frames pass through to the VM.
    - Physical switch port to the Proxmox host: trunk, your VLANs tagged, native untagged.
    - Open vSwitch bridge instead of Linux bridge: same idea, VM port with no tag (trunk).
EOF
    ;;
    vmware) cat <<'EOF'
  VMware (detected). For the trunk to reach this VM:
    - Standard vSwitch: the VM's port group VLAN ID = 4095 (all VLANs, tagging done in the VM).
    - Distributed switch: port group VLAN type "VLAN trunking", range incl. your VLANs.
    - Physical uplink port: trunk, your VLANs tagged, native untagged.
    - No promiscuous mode / MAC changes / forged transmits needed: every VLAN uses the
      VM's own MAC (tagged sub-interface, not macvlan).
EOF
    ;;
    *) cat <<'EOF'
  Hypervisor: not Proxmox/KVM or VMware (or bare metal). The switch port / virtual NIC must
  deliver the native VLAN untagged and the other VLANs tagged (802.1Q trunk).
EOF
    ;;
  esac
}
hv_notes

# =============================================================
# 2. VLAN definitions
# =============================================================
section "VLANs"
# Every 802.1Q interface: "iface vid parent ipv4/prefix|-"
vlan_info() {
  python3 -I -c '
import json, subprocess
def j(*a):
    try: return json.loads(subprocess.run(["ip", "-j"] + list(a), capture_output=True, text=True).stdout or "[]")
    except Exception: return []
v4 = {}
for a in j("-4", "addr", "show"):
    for i in a.get("addr_info", []):
        if i.get("scope") == "global":
            v4.setdefault(a["ifname"], "%s/%s" % (i["local"], i["prefixlen"]))
for l in j("-d", "link", "show"):
    li = l.get("linkinfo") or {}
    if li.get("info_kind") == "vlan" and l.get("link"):
        print(l["ifname"], (li.get("info_data") or {}).get("id"), l["link"], v4.get(l["ifname"], "-"))
'
}
if_v4()  { ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk '{print $4}'; }   # all IPv4/prefix of IFACE
VLAN_INFO=$(vlan_info || true)
DEF_IF="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
DEF_GW="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
# The trunk is the default-route NIC - or its parent when that is itself a VLAN (e.g. vlan200@ens18)
DETECTED_IF="$(awk -v i="${DEF_IF}" '$1==i {print $3; exit}' <<<"${VLAN_INFO}")"
DETECTED_IF="${DETECTED_IF:-${DEF_IF}}"
# Interfaces you manage this VM through (default route + live SSH sessions): never dns-only
MGMT_IFS="${DEF_IF}"
for ip4 in $(ss -Htn state established '( sport = :22 )' 2>/dev/null | awk '{print $3}' | sed -E 's/:[0-9]+$//; s/^::ffff://' | sort -u); do
  i=$(ip -4 -o addr show 2>/dev/null | awk -v a="$ip4" '{split($4, p, "/"); if (p[1]==a) {print $2; exit}}')
  [[ -n "$i" && " ${MGMT_IFS} " != *" $i "* ]] && MGMT_IFS+=" $i"
done
MGMT_IFS="${MGMT_IFS# }"

# ---- interactive setup (runs when VLANS is not given; on re-runs it offers the saved setup) ----
ask() { # VAR "question" default  -> re-asks until the validator (optional 4th arg) accepts
  local __var=$1 __q=$2 __def=${3:-} __check=${4:-} __a
  while true; do
    read -rp "  ${__q}${__def:+ [${__def}]}: " __a || die "No answer (stdin closed)."
    __a="${__a:-${__def}}"
    if [[ -z "${__check}" ]] || "${__check}" "${__a}"; then printf -v "${__var}" '%s' "${__a}"; return; fi
  done
}
ask_yn() { local __a; read -rp "  $1 [$([[ ${2:-y} == y ]] && echo Y/n || echo y/N)]: " __a || __a=""; __a="${__a:-${2:-y}}"; [[ "${__a,,}" == y* ]]; }
v_iface() { ip link show "$1" >/dev/null 2>&1 || { warn "No interface '$1'. Interfaces: $(ls /sys/class/net | grep -vE '^(lo|docker|br-|veth)' | tr '\n' ' ')"; return 1; }; }
v_name()  { [[ "$1" =~ ^[A-Za-z][A-Za-z0-9_-]{0,30}$ ]] || { warn "Use letters, digits, - or _ (start with a letter)."; return 1; }
            [[ "${1,,}" != default ]] || { warn "'Default' is Pi-hole's built-in group (every device is in it). Use e.g. LAN or Main."; return 1; }
            [[ " ${_names,,} " != *" ${1,,} "* ]] || { warn "Name '$1' is already used."; return 1; }; }
v_vid()   { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 4094 )) || { warn "VLAN ID must be 1-4094."; return 1; }
            [[ " ${_vids} " != *" $1 "* ]] || { warn "VLAN $1 is already in this setup."; return 1; }
            local e; e=$(awk -v t="${TRUNK_IF}" -v v="$1" '$3==t && $2==v {print $1; exit}' <<<"${VLAN_INFO}")
            [[ -z "$e" ]] || { warn "VLAN $1 already exists here as ${e} (offered above, configured outside this script)."; return 1; }; }
v_cidr()  { local m; m=$(python3 -I -c '
import ipaddress, sys
a, others = sys.argv[1], sys.argv[2].split()
if "/" not in a:
    sys.exit("Add the prefix length, e.g. %s/24 (anything from /8 to /30 works, e.g. /23 or /22)." % a)
try:
    i = ipaddress.IPv4Interface(a)
except ValueError:
    sys.exit("%r is not an IPv4 address/prefix (e.g. 172.16.12.2/23)." % a)
n = i.network
if not 8 <= n.prefixlen <= 30:
    sys.exit("Prefix /%d: use /8 to /30." % n.prefixlen)
if i.ip == n.network_address:
    sys.exit("%s is the NETWORK address of %s, not a host. Give this VM a free address in it, e.g. %s/%d (%s is usually the router)."
             % (i.ip, n, n.network_address + 2, n.prefixlen, n.network_address + 1))
if i.ip == n.broadcast_address:
    sys.exit("%s is the BROADCAST address of %s. Give this VM a free host address, e.g. %s/%d."
             % (i.ip, n, n.network_address + 2, n.prefixlen))
for o in others:
    if n.overlaps(ipaddress.ip_network(o)):
        sys.exit("%s overlaps %s, already used by another VLAN here." % (n, o))
' "$1" "${_nets}" 2>&1) || { warn "$m"; return 1; }; }
v_ip_opt() { [[ -z "$1" || "$1" == none ]] || python3 -I -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$1" 2>/dev/null || { warn "Enter an IPv4 address, or 'none'."; return 1; }; }
v_url_opt() { [[ -z "$1" || "$1" == none || "$1" =~ ^https?://[^[:space:]]+$ ]] || { warn "Enter an http(s):// URL, or 'none'."; return 1; }; }
v_profile() { [[ "$1" =~ ^[1-4]$ || "${1,,}" =~ ^[a-z][a-z0-9_-]{0,30}$ ]] || { warn "Pick 1-4, or type a profile name."; return 1; }; }
gw_guess() { python3 -I -c 'import ipaddress,sys; print(next(ipaddress.ip_interface(sys.argv[1]).network.hosts()))' "$1" 2>/dev/null || true; }
net_info() { python3 -I -c 'import ipaddress,sys; n=ipaddress.ip_interface(sys.argv[1]).network; print("%s  (%s - %s, %d devices)" % (n, n.network_address+1, n.broadcast_address-1, n.num_addresses-2))' "$1"; }
# default list profile from the group name
profile_guess() { case "${1,,}" in *iot*|*cam*|*smart*) echo iot ;; *kid*|*child*|*famil*) echo kids ;; *guest*|*visit*) echo guest ;; *) echo none ;; esac; }

# per-VLAN questions; appends to VLANS / ROUTERS.   VID IFACE ADDRSPEC(auto|ip/pfx) ADDR DEFAULT_NAME
vlan_questions() {
  local vid=$1 iface=$2 spec=$3 addr=$4 def_name=${5:-} label name mode router p _m _p
  label=$([[ $vid == 0 ]] && echo "the untagged VLAN" || echo "VLAN ${vid}")
  echo "    Subnet: $(net_info "$addr")"
  ask name "  Name for ${label}'s group (e.g. Users, IoT, Kids)" "${def_name}" v_name
  if [[ " ${MGMT_IFS} " == *" ${iface} "* ]]; then
    echo "    Access: full (you manage this VM through ${iface}, so it stays reachable)."
    mode=full
  else
    echo "    What may devices in ${name} reach on this VM?"
    echo "      1) dns-only - DNS (and ping) only; no web UI, no SSH   (IoT, guests, kids)"
    echo "      2) full     - everything, like your management network"
    ask _m "  Choose" "1"
    mode=$([[ "$_m" == 2 || "${_m,,}" == full ]] && echo full || echo dns-only)
  fi
  p=$(profile_guess "$name")
  echo "    Extra block lists for ${name} (every VLAN already gets the normal managed lists):"
  echo "      1) none  - normal lists only                                   (people, servers)"
  echo "      2) iot   - + threat intel, vendor telemetry, DoH/VPN bypass, dyndns, ... (strict)"
  echo "      3) kids  - + adult, gambling, threat intel, scams, DoH/VPN bypass"
  echo "      4) guest - + threat intel, scams, adult"
  echo "      or type your own profile name (uses ${VLAN_DIR}/group_<profile>_*.local.txt)"
  ask _p "  Choose" "$(case $p in none) echo 1;; iot) echo 2;; kids) echo 3;; guest) echo 4;; esac)" v_profile
  case "${_p,,}" in 1) p=none ;; 2) p=iot ;; 3) p=kids ;; 4) p=guest ;; *) p="${_p,,}" ;; esac
  ask router "  Router/gateway IP in ${name}, for device names in reports ('none' to skip)" \
      "$([[ "$iface" == "${DEF_IF}" && -n "${DEF_GW}" ]] && echo "${DEF_GW}" || gw_guess "$addr")" v_ip_opt
  VLANS+="${VLANS:+ }${name}:${vid}:${spec}:${mode}:${p}"
  _names+=" ${name}"; _vids+=" ${vid}"
  _nets+=" $(python3 -I -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$addr")"
  [[ -n "$router" && "$router" != none ]] && ROUTERS+="${ROUTERS:+ }${name}=${router}"
  return 0
}

wizard() {
  local addr host iface vid more n
  _names=""; _vids=""; _nets=""; VLANS=""; ROUTERS=""
  cat <<'EOF'

  One Pi-hole serves every VLAN of the trunk. Each VLAN becomes a Pi-hole group with
  its own lists (IoT can block far more than Users) and its own DNS address on this VM.
  Any subnet size from /8 to /30 works (/24, /23, /22, ...).

EOF
  ask TRUNK_IF "Trunk interface (the NIC that carries all VLANs)" "${TRUNK_IF:-${DETECTED_IF}}" v_iface
  host=$(if_v4 "${TRUNK_IF}" | head -1)
  echo ""
  echo "  Found on ${TRUNK_IF}:"
  echo "    untagged      : ${host:-no IPv4 address}$([[ " ${MGMT_IFS} " == *" ${TRUNK_IF} "* ]] && echo "   (management)")"
  while read -r iface vid _ addr; do
    [[ -n "$iface" ]] || continue
    printf '    VLAN %-8s : %s on %s%s%s\n' "$vid" "${addr/#-/no IPv4 address}" "$iface" \
      "$([[ " ${MGMT_IFS} " == *" ${iface} "* ]] && echo "   (management)")" \
      "$(grep -qE "^    ${iface}:" "${NETPLAN_FILE}" 2>/dev/null && echo "   (added by this script)")"
  done < <(awk -v t="${TRUNK_IF}" '$3==t' <<<"${VLAN_INFO}" | sort -k2n)

  # -- untagged / native VLAN --
  echo ""
  echo "  Untagged (native) VLAN of ${TRUNK_IF}. On a Proxmox VLAN-aware bridge with no VLAN tag on"
  echo "  the VM NIC, this is the bridge's native VLAN - usually VLAN 1 on the switch."
  if [[ -n "$host" ]]; then
    if ask_yn "Serve DNS on it (this VM is ${host} there)?" y; then
      vlan_questions 0 "${TRUNK_IF}" auto "$host" "Users"
    fi
  elif ask_yn "This VM has no IPv4 address there. Give it one and serve DNS on it?" n; then
    ask addr "  This VM's IP/prefix on the untagged VLAN (static, e.g. 10.11.1.2/24)" "" v_cidr
    vlan_questions 0 "${TRUNK_IF}" "$addr" "$addr" "LAN"
  fi

  # -- tagged VLANs that already exist on this VM (fd 3: the questions read stdin) --
  while read -r -u 3 iface vid _ addr; do
    [[ -n "$iface" ]] || continue
    echo ""
    if [[ "$addr" == - ]]; then
      warn "VLAN ${vid} (${iface}) exists but has no IPv4 address; skipped (give it one in netplan to use it)."
      continue
    fi
    if ask_yn "Serve DNS on VLAN ${vid} (${iface}, this VM is ${addr})?" y; then
      vlan_questions "$vid" "$iface" auto "$addr" ""
    fi
  done 3< <(awk -v t="${TRUNK_IF}" '$3==t' <<<"${VLAN_INFO}" | sort -k2n)

  # -- new tagged VLANs (added by this script) --
  n=0
  while true; do
    echo ""
    ask_yn "Add $( (( n == 0 )) && echo "a" || echo "another") tagged VLAN that this VM is not on yet?" "$( (( n == 0 )) && echo y || echo n)" || break
    ask vid "  VLAN ID (802.1Q tag)" "" v_vid
    if [[ "$vid" == 1 && "$HV" == proxmox ]]; then
      warn "On a Proxmox VLAN-aware bridge VLAN 1 normally arrives UNTAGGED (answer it as the untagged VLAN above)."
      ask_yn "Add VLAN 1 as tagged anyway?" n || continue
    fi
    ask addr "  This VM's IP/prefix on VLAN ${vid} (static, e.g. 192.168.20.2/24 or 172.16.12.2/23)" "" v_cidr
    vlan_questions "$vid" "vlan${vid}" "$addr" "$addr" "$([[ "$vid" == 666 && " ${_names,,} " != *" iot "* ]] && echo IoT)"
    n=$((n + 1))
  done
  [[ -n "${VLANS}" ]] || die "No VLANs chosen; nothing to do."
  echo ""
  echo "  IPv6: on every VLAN this VM takes <prefix>${IPV6_TOKEN} from the prefix your router"
  echo "  advertises (SLAAC) and answers DNS there; devices asking over IPv6 get their VLAN's"
  echo "  lists too. Your router then hands out that address as the IPv6 DNS server."
  if ask_yn "Serve DNS over IPv6 as well?" "$([[ "${IPV6}" == off ]] && echo n || echo y)"; then IPV6=auto; else IPV6=off; fi
  echo ""
  ask ALERT_WEBHOOK "Alert webhook URL (ntfy topic URL / Slack / Discord; 'none' = journal only)" \
      "${ALERT_WEBHOOK:-none}" v_url_opt
  [[ "${ALERT_WEBHOOK}" == none ]] && ALERT_WEBHOOK=""
  return 0
}

show_setup() {
  echo "  Trunk   : ${TRUNK_IF}"
  local item; for item in ${VLANS}; do echo "  VLAN    : ${item}"; done
  echo "  Routers : ${ROUTERS:-none}"
  echo "  IPv6    : $([[ "${IPV6}" == off ]] && echo off || echo "on (this VM = <prefix>${IPV6_TOKEN} in each VLAN)")"
  echo "  Webhook : ${ALERT_WEBHOOK:-none}"
}

if [[ -z "${ENV_VAL[VLANS]:-}" ]] && interactive; then
  if [[ -n "${VLANS:-}" ]]; then
    echo "  Saved setup (${SAVED}):"; show_setup
    ask_yn "Use it?" y || wizard
  else
    wizard
  fi
  echo ""; echo "  Setup (NAME:VLAN:ADDRESS:ACCESS:LISTS):"; show_setup
  ask_yn "Continue with this setup?" y || die "Stopped; nothing was changed yet."
fi
TRUNK_IF="${TRUNK_IF:-${DETECTED_IF}}"
[[ -n "${TRUNK_IF}" ]] || die "Could not find the trunk interface; set TRUNK_IF=ens18 (or similar)."
ip link show "${TRUNK_IF}" >/dev/null 2>&1 || die "Interface ${TRUNK_IF} does not exist."
[[ -n "${VLANS:-}" ]] || die 'No VLANs. Run interactively, or set VLANS="Users:0:auto IoT:666:172.16.12.2/23"'
info "Trunk interface: ${TRUNK_IF}   (management: ${MGMT_IFS:-?})"

# Parse + validate (python ipaddress). Output per VLAN:
#   NAME VID IFACE ADDR/PFX SUBNET MODE PROFILE ORIGIN    ORIGIN: have = configured outside this
#   script (left alone) | add = written to ${NETPLAN_FILE}
OURS=""; [[ -r "${NETPLAN_FILE}" ]] && OURS=$(cat "${NETPLAN_FILE}")
PARSED=$(python3 -I - "${VLANS}" "${TRUNK_IF}" "$(if_v4 "${TRUNK_IF}" | tr '\n' ' ')" "${VLAN_INFO}" \
                     "${OURS}" "${MGMT_IFS}" "$(ip -4 -o route show 2>/dev/null)" <<'PY'
import ipaddress, re, sys
vlans, trunk, trunk_v4, vinfo, ours, mgmt, routes = sys.argv[1:8]
trunk_v4 = trunk_v4.split()
mgmt = mgmt.split()
existing = {}  # vid -> (iface, addr|None) for VLAN interfaces on the trunk
for line in vinfo.splitlines():
    f = line.split()
    if len(f) == 4 and f[2] == trunk and f[1].isdigit():
        existing[int(f[1])] = (f[0], None if f[3] == "-" else f[3])
our_ifaces = set(re.findall(r"^    (\S+):[^\n]*\n      id: ", ours, re.M)) - {trunk}
our_addrs = {a.strip() for grp in re.findall(r"addresses: \[([^\]]*)\]", ours) for a in grp.split(",")}

def guess_profile(name):
    n = name.lower()
    for keys, p in ((("iot", "cam", "smart"), "iot"), (("kid", "child", "famil"), "kids"), (("guest", "visit"), "guest")):
        if any(k in n for k in keys):
            return p
    return "none"

seen_n, seen_i, nets, out = set(), set(), [], []
for item in vlans.split():
    parts = item.split(":")
    if len(parts) not in (3, 4, 5):
        sys.exit("VLANS: %r is not NAME:VLAN_ID:ADDRESS[:MODE[:LISTS]]" % item)
    name, vid, addr = parts[:3]
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,30}", name):
        sys.exit("VLANS: bad name %r (letters, digits, - and _)" % name)
    if name.lower() == "default":
        sys.exit("VLANS: 'Default' is Pi-hole's built-in group (every device is in it); use e.g. LAN or Main")
    if not vid.isdigit() or int(vid) > 4094:
        sys.exit("VLANS: bad VLAN id %r (0 = untagged, 1-4094)" % vid)
    vid = int(vid)
    if name.lower() in seen_n or vid in seen_i:
        sys.exit("VLANS: duplicate name or VLAN id in %r" % item)
    seen_n.add(name.lower()); seen_i.add(vid)
    origin = "add"
    if vid == 0:
        iface = trunk
        if addr == "auto":
            if not trunk_v4:
                sys.exit("VLANS: %s uses 'auto' but %s has no IPv4 address; give a static IP/prefix" % (name, trunk))
            mine = [a for a in trunk_v4 if a in our_addrs]
            if mine:   # address this script added earlier: keep managing it
                addr = mine[0]
            else:
                addr, origin = trunk_v4[0], "have"
        elif addr in trunk_v4 and addr not in our_addrs:
            origin = "have"
    elif vid in existing and existing[vid][0] not in our_ifaces:
        iface, have = existing[vid]
        if not have:
            sys.exit("VLANS: VLAN %d exists as %s (configured outside this script) but has no IPv4 address" % (vid, iface))
        if addr not in ("auto", have):
            sys.exit("VLANS: VLAN %d already exists as %s with %s (configured outside this script); use 'auto' "
                     "or change it in your own netplan file" % (vid, iface, have))
        addr, origin = have, "have"
    else:
        iface = "vlan%d" % vid
        if addr == "auto" and vid in existing and existing[vid][1]:
            iface, addr = existing[vid]   # created by this script earlier: keep its address
        elif addr == "auto":
            sys.exit("VLANS: %s (VLAN %d) is not on this VM yet; give this VM's static IP/prefix, e.g. 172.16.12.2/23"
                     % (name, vid))
    try:
        itf = ipaddress.IPv4Interface(addr)
    except ValueError:
        sys.exit("VLANS: bad address %r for %s (use IPv4/prefix, e.g. 172.16.12.2/23)" % (addr, name))
    n = itf.network
    if not 8 <= n.prefixlen <= 30:
        sys.exit("VLANS: %s: prefix /%d - use /8 to /30" % (addr, n.prefixlen))
    if itf.ip in (n.network_address, n.broadcast_address):
        sys.exit("VLANS: %s is the %s address of %s - use a host address such as %s/%d"
                 % (itf.ip, "network" if itf.ip == n.network_address else "broadcast", n, n.network_address + 2, n.prefixlen))
    for other_name, other in nets:
        if n.overlaps(other):
            sys.exit("VLANS: %s (%s) overlaps %s (%s)" % (n, name, other, other_name))
    nets.append((name, n))
    mode = parts[3] if len(parts) >= 4 and parts[3] else ("full" if iface in mgmt else "dns-only")
    if mode not in ("full", "dns-only"):
        sys.exit("VLANS: access for %s must be full or dns-only" % name)
    if mode == "dns-only" and iface in mgmt:
        sys.exit("VLANS: %s: dns-only on %s would cut off your access (default route / SSH session); use full" % (name, iface))
    profile = (parts[4] if len(parts) == 5 and parts[4] else guess_profile(name)).lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", profile):
        sys.exit("VLANS: bad list profile %r for %s" % (profile, name))
    out.append((name, vid, iface, itf.with_prefixlen, n, mode, profile, origin))
# other routes on this VM (Docker networks, VPNs) that overlap a VLAN subnet would hijack its replies
ifaces = {o[2] for o in out}
for line in routes.splitlines():
    f = line.split()
    if not f or f[0] == "default" or "dev" not in f:
        continue
    dev = f[f.index("dev") + 1]
    try:
        dst = ipaddress.ip_network(f[0], strict=False)
    except ValueError:
        continue
    for o in out:
        if dev not in ifaces and dst.overlaps(o[4]):
            print("WARNING: %s (%s) overlaps route %s on %s - replies to %s may go the wrong way"
                  % (o[4], o[0], dst, dev, o[0]), file=sys.stderr)
for o in out:
    print(*o)
PY
) || die "Fix VLANS and re-run."
GROUP_MAP=""; WRITE=0; DNS_ONLY_IFS=""; TAG_IDS=""
while read -r name vid iface addr net mode profile origin; do
  printf '  %-14s VLAN %-4s %-10s %-18s subnet %-18s %-8s lists:%-6s %s\n' "$name" "$vid" "$iface" "$addr" "$net" "$mode" "$profile" \
    "$([[ $origin == have ]] && echo "(existing)" || echo "(added by this script)")"
  GROUP_MAP+="${GROUP_MAP:+,}${name}=${net}@${profile}"
  [[ "$origin" == add ]] && WRITE=$((WRITE + 1))
  [[ "$vid" != 0 ]] && TAG_IDS+="${TAG_IDS:+;}${vid}"
  [[ "$mode" == dns-only ]] && DNS_ONLY_IFS+=" ${iface}"
done <<<"${PARSED}"
DNS_ONLY_IFS="${DNS_ONLY_IFS# }"
if [[ -n "${TAG_IDS}" ]]; then
  case "$HV" in
    proxmox) info "Proxmox: tagged VLANs to pass to this VM: ${TAG_IDS//;/, } (optional filter: qm set <vmid> -net0 virtio=<MAC>,bridge=vmbr0,trunks=\"${TAG_IDS}\")" ;;
    vmware)  info "VMware: the port group must pass VLANs ${TAG_IDS//;/, } (4095 / VLAN trunking)." ;;
  esac
fi

# =============================================================
# 3. VLAN interfaces (netplan)
# =============================================================
section "VLAN interfaces (netplan)"
V6_ON=false; [[ "${IPV6}" != off ]] && V6_ON=true
if (( WRITE == 0 )) && ! $V6_ON; then
  info "Nothing to add: every VLAN interface/address already exists."
  if [[ -f "${NETPLAN_FILE}" ]] && ! dry; then
    info "Removing ${NETPLAN_FILE} (no longer needed) and applying netplan..."
    rm -f "${NETPLAN_FILE}"; netplan apply || warn "netplan apply failed."
  fi
else
  command -v netplan >/dev/null || die "netplan not found (Ubuntu uses netplan). Add the VLAN interfaces by hand, then re-run."
  # Line 1: netplan id of the trunk NIC (usually its name). Line 2: VLAN interfaces your own
  # netplan files define, as name:id:link:accept-ra (only those can get IPv6 settings merged in;
  # id and link are repeated in our file because netplan may read it before yours).
  NP_INFO=$(python3 -I - "${TRUNK_IF}" <<'PY'
import glob, sys
trunk = sys.argv[1]
try:
    import yaml
except ImportError:
    print(trunk); print(""); sys.exit(0)
found, vlans = None, {}
for f in sorted(glob.glob("/etc/netplan/*.yaml")) + sorted(glob.glob("/lib/netplan/*.yaml")) + sorted(glob.glob("/run/netplan/*.yaml")):
    if f.endswith("60-managed-pihole-vlans.yaml"):
        continue
    try:
        doc = yaml.safe_load(open(f)) or {}
    except Exception:
        continue
    net = doc.get("network") or {}
    for nid, cfg in (net.get("ethernets") or {}).items():
        cfg = cfg or {}
        if nid == trunk or cfg.get("set-name") == trunk:
            found = nid
    for nid, cfg in (net.get("vlans") or {}).items():
        cfg = cfg or {}
        v = vlans.setdefault(nid, {})
        for k in ("id", "link", "accept-ra"):
            if k in cfg:
                v[k] = cfg[k]
print(found or "")
print(" ".join("%s:%s:%s:%s" % (n, v.get("id", ""), v.get("link", ""), str(v.get("accept-ra", "")).lower())
               for n, v in sorted(vlans.items()) if v.get("id") is not None and v.get("link")))
PY
)
  LINK_ID=$(sed -n 1p <<<"${NP_INFO}"); OWN_VLANS=" $(sed -n 2p <<<"${NP_INFO}") "
  [[ -n "${LINK_ID}" ]] || dry || die "${TRUNK_IF} is not defined in /etc/netplan/*.yaml; add the VLAN interfaces by hand (netplan 'vlans:'), then re-run."
  LINK_ID="${LINK_ID:-${TRUNK_IF}}"
  UNTAGGED_ADD=$(awk '$2==0 && $8=="add" {print $4}' <<<"${PARSED}")
  UNTAGGED_SERVED=$(awk '$2==0 {print $1}' <<<"${PARSED}")
  # IPv6 settings for one interface: SLAAC from the router's advertisement, with a fixed
  # interface id, so this VM is <prefix>${IPV6_TOKEN} in every VLAN (stable DNS address).
  v6_lines() { # INDENT
    if $V6_ON; then
      printf '%saccept-ra: true\n%sipv6-address-token: "%s"\n' "$1" "$1" "${IPV6_TOKEN}"
    fi
  }
  NP=$( {
    echo "# Generated by managed_pihole deploy_multi_pi.sh ${SCRIPT_VERSION} - re-running the script rewrites it."
    echo "# VLANs on the trunk ${TRUNK_IF}: static IPv4, no gateway$($V6_ON && echo "; IPv6 by SLAAC as <prefix>${IPV6_TOKEN}" || echo ", no IPv6")."
    echo "# Interfaces configured in your own netplan files are not repeated; netplan merges the"
    echo "# extra settings below into them."
    echo "network:"
    echo "  version: 2"
    if [[ -n "${UNTAGGED_ADD}" ]] || { $V6_ON && [[ -n "${UNTAGGED_SERVED}" ]]; }; then
      echo "  ethernets:"
      echo "    ${LINK_ID}:              # untagged VLAN ${UNTAGGED_SERVED}"
      [[ -n "${UNTAGGED_ADD}" ]] && echo "      addresses: [${UNTAGGED_ADD}]"
      [[ -n "${UNTAGGED_SERVED}" ]] && v6_lines "      "
    fi
    vl=""
    while read -r name vid iface addr net mode profile origin; do
      [[ "$vid" == 0 ]] && continue
      if [[ "$origin" == add ]]; then
        vl+="    ${iface}:              # ${name}"$'\n'
        vl+="      id: ${vid}"$'\n'"      link: ${LINK_ID}"$'\n'"      addresses: [${addr}]"$'\n'
        vl+="      dhcp4: false"$'\n'"      dhcp6: false"$'\n'
        if $V6_ON; then vl+="$(v6_lines "      ")"$'\n'
        else vl+="      accept-ra: false"$'\n'"      link-local: []"$'\n'; fi
      elif $V6_ON; then
        own=$(tr ' ' '\n' <<<"${OWN_VLANS}" | awk -F: -v i="$iface" '$1==i {print; exit}')
        if [[ -n "$own" ]]; then
          IFS=: read -r _ own_id own_link own_ra <<<"$own"
          [[ "${own_ra}" == false ]] && warn "${iface}: your netplan file sets accept-ra: false; if it sorts after ${NETPLAN_FILE##*/}, it wins and ${iface} gets no IPv6 - remove that line to use IPv6 there."
          vl+="    ${iface}:              # ${name}: defined in your netplan file; same id/link + IPv6 settings"$'\n'
          vl+="      id: ${own_id}"$'\n'"      link: ${own_link}"$'\n'
          vl+="$(v6_lines "      ")"$'\n'
        else
          warn "${iface} is not defined in netplan; IPv6 for it is up to you (not changed)."
        fi
      fi
    done <<<"${PARSED}"
    [[ -n "$vl" ]] && printf '  vlans:\n%s' "$vl"
  } )
  OLD_NP=""; [[ -f "${NETPLAN_FILE}" ]] && OLD_NP=$(cat "${NETPLAN_FILE}")
  missing=false   # file unchanged but an interface is down / lost its address -> apply anyway
  while read -r name vid iface addr net mode profile origin; do
    [[ "$origin" == add ]] || continue
    ip -4 addr show dev "$iface" 2>/dev/null | grep -q " ${addr%/*}/" || missing=true
  done <<<"${PARSED}"
  np_state=$(put_file "${NETPLAN_FILE}" 600 <<<"${NP}")
  if dry; then
    [[ "${np_state}" == changed ]] && info "Would write ${NETPLAN_FILE} and run netplan apply." || ok "VLAN interfaces already configured."
  elif [[ "${np_state}" == changed ]] || $missing; then
    info "Applying netplan (the network may blip for a second)..."
    if $V6_ON; then   # an earlier run (IPv6 off) switched IPv6 off on dns-only interfaces
      while read -r name vid iface _; do sysctl -qw "net.ipv6.conf.${iface}.disable_ipv6=0" 2>/dev/null || true; done <<<"${PARSED}"
    fi
    if netplan generate && netplan apply; then
      ok "netplan applied (${NETPLAN_FILE})"
    else
      warn "netplan failed; restoring the previous VLAN file."
      if [[ -n "${OLD_NP}" ]]; then printf '%s\n' "${OLD_NP}" > "${NETPLAN_FILE}"; else rm -f "${NETPLAN_FILE}"; fi
      netplan apply || true
      die "VLAN interfaces not configured."
    fi
  else
    ok "VLAN interfaces already configured."
  fi
  if ! dry; then
    while read -r name vid iface addr net mode profile origin; do
      [[ "$origin" == add ]] || continue
      for ((i = 0; i < 10; i++)); do ip -4 addr show dev "$iface" 2>/dev/null | grep -q " ${addr%/*}/" && break; sleep 1; done
      ip -4 addr show dev "$iface" 2>/dev/null | grep -q " ${addr%/*}/" \
        && ok "${iface} (${name}) is up with ${addr}" || warn "${iface} does not have ${addr} yet - check: ip addr show ${iface}"
    done <<<"${PARSED}"
  fi
fi

# IPv6 addresses per VLAN (<prefix>${IPV6_TOKEN}, from the router's advertisements)
declare -A V6ADDR=()
V6_IFACES=""
if [[ "${IPV6}" != off ]]; then
  v6_of() { # IFACE -> this VM's <prefix>::token addresses on it, ULA first (stable)
    ip -6 -o addr show dev "$1" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
      | grep -i -- ":${IPV6_TOKEN#::}\$" | sort -r | awk '/^f[cd]/ {print; next} {g = g " " $0} END {if (g) print substr(g, 2)}' | tr '\n' ' ' || true
  }
  dry || info "Waiting for IPv6 router advertisements (up to 20 s)..."
  for ((t = 0; t < 20; t++)); do
    pending=0
    while read -r name vid iface _; do [[ -n "$(v6_of "$iface")" ]] || pending=1; done <<<"${PARSED}"
    (( pending == 0 )) || dry && break
    sleep 1
  done
  while read -r name vid iface _; do
    V6_IFACES+="${V6_IFACES:+,}${name}=${iface}"
    V6ADDR[$name]="$(v6_of "$iface")"
    if [[ -n "${V6ADDR[$name]// /}" ]]; then ok "IPv6 ${name} (${iface}): ${V6ADDR[$name]}"
    elif ! dry; then warn "IPv6 ${name} (${iface}): no address - your router sends no IPv6 advertisement (RA) on this VLAN yet."
    fi
  done <<<"${PARSED}"
fi

# =============================================================
# 3b. Save settings now (re-runs, daily sync) - so a failed install keeps your answers
# =============================================================
if ! dry; then
  install -d -m 755 "${PIHOLE_BASE}"
  {
    echo "# Generated by deploy_multi_pi.sh ${SCRIPT_VERSION} - edit and re-run the script to change."
    for k in VLANS TRUNK_IF ROUTERS ALERT_WEBHOOK MANAGED_REPO_RAW IPV6 IPV6_TOKEN GROUP_MAP DNS_ONLY_IFS V6_IFACES; do
      printf '%s=%q\n' "$k" "${!k}"
    done
  } | put_file "${SAVED}" 600 >/dev/null
fi

# =============================================================
# 4. Docker stack (install_pihole.sh)
# =============================================================
section "Pi-hole stack"
ENV_FILE="${PIHOLE_BASE}/pihole.env"
if [[ -r "${ENV_FILE}" ]] && grep -q '^DNS_FILTER="adguardhome"' "${ENV_FILE}"; then
  die "This host runs AdGuard Home. Per-VLAN groups need Pi-hole: re-run install_pihole.sh with DNS_FILTER=pihole first."
fi
NEED_V6_STACK=false
if [[ "${IPV6}" != off && -s "${PIHOLE_BASE}/docker-compose.yml" ]] && ! grep -q 'enable_ipv6: true' "${PIHOLE_BASE}/docker-compose.yml"; then
  NEED_V6_STACK=true
  info "Docker's network has no IPv6 yet: Pi-hole would see every IPv6 query as coming from the"
  info "Docker gateway (no per-device stats, no VLAN group). Re-running install_pihole.sh to add it;"
  info "it asks its questions again (Enter keeps the defaults)."
fi
if is_true "${SKIP_STACK:-false}"; then
  info "SKIP_STACK=true: not running install_pihole.sh"
elif [[ -s "${PIHOLE_BASE}/docker-compose.yml" ]] && ! is_true "${FORCE_STACK:-false}" && ! $NEED_V6_STACK; then
  ok "Already installed in ${PIHOLE_BASE} (FORCE_STACK=true to re-run install_pihole.sh)."
elif dry; then
  info "Would run: DNS_FILTER=pihole bash install_pihole.sh"
else
  INSTALLER="${SRC_DIR}/install_pihole.sh"
  if [[ ! -f "${INSTALLER}" ]]; then
    INSTALLER=$(mktemp); curl -fsSL "${MANAGED_REPO_RAW}/install_pihole.sh" -o "${INSTALLER}"
  fi
  # Port 53 is published on all addresses, so it answers on every VLAN address too.
  DNS_FILTER=pihole ENABLE_MCP="${ENABLE_MCP:-true}" \
    SERVE_IPV6="$([[ "${IPV6}" == off ]] && echo "${SERVE_IPV6:-auto}" || echo true)" bash "${INSTALLER}"
fi
if [[ -r "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  FILTER_IP=$(. "${ENV_FILE}"; echo "${FILTER_IP}")
else
  dry || die "${ENV_FILE} missing - is the stack installed?"
  FILTER_IP=""
fi
MAINT="${PIHOLE_BASE}/pihole-maint.sh"

# =============================================================
# 6. Groups and per-VLAN lists
# =============================================================
section "Pi-hole groups per VLAN"
GROUP_FILES=$(cd "${SRC_DIR}" && ls group_*.txt 2>/dev/null || true)
if ! dry; then
  install -d -m 755 "${VLAN_DIR}"
  for f in upsert_vlan_groups.py pihole_api.py ${GROUP_FILES}; do
    [[ -f "${SRC_DIR}/$f" ]] && install -m "$([[ $f == *.py ]] && echo 755 || echo 644)" "${SRC_DIR}/$f" "${VLAN_DIR}/$f"
  done
  [[ -f "${VLAN_DIR}/upsert_vlan_groups.py" ]] || curl -fsSL "${MANAGED_REPO_RAW}/upsert_vlan_groups.py" -o "${VLAN_DIR}/upsert_vlan_groups.py"
  [[ -f "${VLAN_DIR}/pihole_api.py" ]] || curl -fsSL "${MANAGED_REPO_RAW}/pihole_api.py" -o "${VLAN_DIR}/pihole_api.py"
  chmod 755 "${VLAN_DIR}"/*.py
  put_file "${VLAN_DIR}/vlan-sync.sh" 700 >/dev/null <<SYNC
#!/bin/bash
# Generated by deploy_multi_pi.sh ${SCRIPT_VERSION}: daily re-sync of the per-VLAN Pi-hole groups.
#   ${VLAN_DIR}/vlan-sync.sh [--dry-run]
# Your own additions: ${VLAN_DIR}/group_<name>_{blocklists,regex_deny,deny,allow,regex_allow}.local.txt
set -euo pipefail
. "${SAVED}"
. "${ENV_FILE}"
D="${VLAN_DIR}"
fetch=""
if [[ "\${1:-}" != "--no-fetch" ]]; then
  for f in upsert_vlan_groups.py pihole_api.py; do   # newest scripts; keep the old copy on failure
    curl -fsSL --max-time 60 "\${MANAGED_REPO_RAW}/\$f" -o "\$D/\$f.tmp" 2>/dev/null && mv "\$D/\$f.tmp" "\$D/\$f" || rm -f "\$D/\$f.tmp"
  done
  fetch="--fetch \${MANAGED_REPO_RAW}"
else
  shift
fi
chmod 755 "\$D"/*.py
PIHOLE_API_URL="http://\${FILTER_IP}/api" PIHOLE_PASSWORD="\$(cat "\${PIHOLE_BASE}/secrets/pihole_password.txt")" \\
  exec python3 "\$D/upsert_vlan_groups.py" --vlans "\${GROUP_MAP}" --dir "\$D" \${fetch} \
  \${V6_IFACES:+--v6-from "\${V6_IFACES}"} "\$@"
SYNC
  "${VLAN_DIR}/vlan-sync.sh" --no-fetch || warn "Group sync reported a problem (see above)."
else
  info "Would sync groups: ${GROUP_MAP}  (files: ${GROUP_FILES//$'\n'/ })"
fi

# Per-VLAN reverse DNS: device names instead of bare IPs in reports
if [[ -n "${ROUTERS}" ]]; then
  REV=$(python3 -I - "${ROUTERS}" "${GROUP_MAP}" <<'PY'
import json, sys
routers = dict(r.split("=", 1) for r in sys.argv[1].split() if "=" in r)
nets = dict(g.split("=", 1) for g in sys.argv[2].split(",") if "=" in g)
low = {k.lower(): k for k in nets}
out = []
for name, ip in routers.items():
    key = low.get(name.lower())
    if not key:
        sys.exit("ROUTERS: unknown VLAN %r" % name)
    out.append("true,%s,%s" % (nets[key], ip))
print(json.dumps(out))
PY
) || die "Fix ROUTERS (NAME=router-ip ...)."
  if dry; then info "Would set dns.revServers ${REV}"
  elif docker exec pihole pihole-FTL --config dns.revServers "${REV}" >/dev/null 2>&1; then
    ok "Reverse lookups per VLAN: ${REV}"
  else
    warn "Could not set dns.revServers (read-only because CONDITIONAL_FORWARDING was used in install_pihole.sh?)."
  fi
fi

# =============================================================
# 7. DNS-only firewall for restricted VLANs
# =============================================================
section "Firewall for dns-only VLANs"
put_file "${FW_SCRIPT}" 755 >/dev/null <<FW
#!/bin/sh
# Generated by deploy_multi_pi.sh ${SCRIPT_VERSION}. On these interfaces this VM answers DNS (and
# ping) and nothing else: no web UI, no SSH, no forwarding/routing through the VM.
#   INPUT       -> MULTIPI-IN   (services on the host, e.g. sshd)
#   DOCKER-USER -> MULTIPI-FWD  (published container ports; Docker bypasses ufw)
# The same for IPv6 with ip6tables (IPV6=auto), or IPv6 switched off there (IPV6=off).
IFACES="${DNS_ONLY_IFS}"
IPV6="${IPV6}"
set -e
case "\${1:-start}" in
  stop)
    iptables -D INPUT -j MULTIPI-IN 2>/dev/null || true
    iptables -D DOCKER-USER -j MULTIPI-FWD 2>/dev/null || true
    iptables -F MULTIPI-IN 2>/dev/null || true; iptables -X MULTIPI-IN 2>/dev/null || true
    iptables -F MULTIPI-FWD 2>/dev/null || true; iptables -X MULTIPI-FWD 2>/dev/null || true
    if command -v ip6tables >/dev/null; then
      ip6tables -D INPUT -j MULTIPI-IN 2>/dev/null || true
      ip6tables -D DOCKER-USER -j MULTIPI-FWD 2>/dev/null || true
      ip6tables -F MULTIPI-IN 2>/dev/null || true; ip6tables -X MULTIPI-IN 2>/dev/null || true
      ip6tables -F MULTIPI-FWD 2>/dev/null || true; ip6tables -X MULTIPI-FWD 2>/dev/null || true
    fi
    exit 0 ;;
esac
iptables -N MULTIPI-IN 2>/dev/null || iptables -F MULTIPI-IN
iptables -N MULTIPI-FWD 2>/dev/null || iptables -F MULTIPI-FWD
iptables -N DOCKER-USER 2>/dev/null || true
V6=false
if [ "\$IPV6" != off ] && command -v ip6tables >/dev/null; then
  V6=true
  ip6tables -N MULTIPI-IN 2>/dev/null || ip6tables -F MULTIPI-IN
  ip6tables -N MULTIPI-FWD 2>/dev/null || ip6tables -F MULTIPI-FWD
  ip6tables -N DOCKER-USER 2>/dev/null || true
fi
for i in \$IFACES; do
  if \$V6; then
    sysctl -qw "net.ipv6.conf.\$i.disable_ipv6=0" 2>/dev/null || true
    for c in MULTIPI-IN MULTIPI-FWD; do
      ip6tables -A \$c -i "\$i" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
      ip6tables -A \$c -i "\$i" -p udp --dport 53 -j RETURN
      ip6tables -A \$c -i "\$i" -p tcp --dport 53 -j RETURN
    done
    # ICMPv6 is how IPv6 works (neighbor discovery, router advertisements) - and ping
    ip6tables -A MULTIPI-IN -i "\$i" -p ipv6-icmp -j RETURN
    ip6tables -A MULTIPI-IN -i "\$i" -j DROP
    ip6tables -A MULTIPI-FWD -i "\$i" -j DROP
  else
    # IPv4 only on these VLANs: no IPv6 address = nothing to reach around these IPv4 rules
    sysctl -qw "net.ipv6.conf.\$i.disable_ipv6=1" 2>/dev/null || true
  fi
  for c in MULTIPI-IN MULTIPI-FWD; do
    iptables -A \$c -i "\$i" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    iptables -A \$c -i "\$i" -p udp --dport 53 -j RETURN
    iptables -A \$c -i "\$i" -p tcp --dport 53 -j RETURN
  done
  iptables -A MULTIPI-IN -i "\$i" -p icmp --icmp-type echo-request -j RETURN
  iptables -A MULTIPI-IN -i "\$i" -j DROP
  iptables -A MULTIPI-FWD -i "\$i" -j DROP
done
iptables -C INPUT -j MULTIPI-IN 2>/dev/null || iptables -I INPUT 1 -j MULTIPI-IN
iptables -C DOCKER-USER -j MULTIPI-FWD 2>/dev/null || iptables -I DOCKER-USER 1 -j MULTIPI-FWD
if \$V6; then
  ip6tables -C INPUT -j MULTIPI-IN 2>/dev/null || ip6tables -I INPUT 1 -j MULTIPI-IN
  ip6tables -C DOCKER-USER -j MULTIPI-FWD 2>/dev/null || ip6tables -I DOCKER-USER 1 -j MULTIPI-FWD
fi
echo "multi-pi firewall: dns-only on \${IFACES:-<none>}"
FW
put_file /etc/systemd/system/multi-pi-firewall.service 644 >/dev/null <<'UNIT'
[Unit]
Description=managed_pihole: DNS-only firewall on restricted VLAN interfaces
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/multi-pi-firewall.sh start
ExecStop=/usr/local/sbin/multi-pi-firewall.sh stop

[Install]
WantedBy=multi-user.target docker.service
UNIT
if ! dry; then
  systemctl daemon-reload
  systemctl enable multi-pi-firewall.service >/dev/null 2>&1
  if systemctl restart multi-pi-firewall.service; then ok "dns-only on: ${DNS_ONLY_IFS:-<none>}"
  else warn "Firewall did not apply (journalctl -u multi-pi-firewall)."; fi
else
  info "Would enable multi-pi-firewall.service for: ${DNS_ONLY_IFS:-<none>}"
fi

# =============================================================
# 8. Monitoring: report CLI, MCP tools, alerts
# =============================================================
section "Per-VLAN monitoring"
if dry; then
  info "Would install vlan_report.py to ${MCP_DIR}, dns-vlan-report, alerts every 15 min."
elif ! id -u "${MCP_USER}" >/dev/null 2>&1 || [[ ! -f "${MCP_DIR}/managed_pihole.conf" ]]; then
  warn "MCP user/config missing (ENABLE_MCP=false?). Run: sudo ${MAINT} mcp   then re-run this script."
else
  for f in vlan_report.py mcp_server.py pihole_api.py; do
    [[ -f "${SRC_DIR}/$f" ]] && install -m 755 -o root -g root "${SRC_DIR}/$f" "${MCP_DIR}/$f"
  done
  [[ -f "${MCP_DIR}/vlan_report.py" ]] || curl -fsSL "${MANAGED_REPO_RAW}/vlan_report.py" -o "${MCP_DIR}/vlan_report.py"
  chmod 755 "${MCP_DIR}"/*.py
  # Site settings next to the generated MCP config (survives "pihole-maint.sh mcp").
  # Stricter thresholds on dns-only (IoT) VLANs, looser on full (people) VLANs.
  LOCAL="${MCP_DIR}/managed_pihole.local.conf"
  install -m 640 -o root -g "${MCP_USER}" /dev/null "${LOCAL}.tmp"
  {
    echo "# Generated by deploy_multi_pi.sh ${SCRIPT_VERSION} - read by vlan_report.py / mcp_server.py"
    echo "# Thresholds: see vlan_report.py. Per VLAN: KEY_<VLANNAME>=value. Re-running the script rewrites this file;"
    echo "# put permanent changes in the environment of the run (e.g. sudo ALERT_BLOCKED_PCT_IOT=80 bash deploy_multi_pi.sh)."
    echo "ALERT_STATE_FILE=/var/lib/${MCP_USER}/vlan_alerts.json"
    [[ -n "${ALERT_WEBHOOK}" ]] && echo "ALERT_WEBHOOK=${ALERT_WEBHOOK}"
    while read -r name vid iface addr net mode profile origin; do
      u=$(tr '[:lower:]-' '[:upper:]_' <<<"$name")
      if [[ "$mode" == full ]]; then
        echo "ALERT_BLOCKED_PCT_${u}=70"; echo "ALERT_NXDOMAIN_PCT_${u}=40"; echo "ALERT_QUERIES_PER_HOUR_${u}=6000"
      else
        echo "ALERT_BLOCKED_PCT_${u}=50"; echo "ALERT_NXDOMAIN_PCT_${u}=20"; echo "ALERT_QUERIES_PER_HOUR_${u}=1500"
        echo "ALERT_BYPASS_HITS_${u}=1"
      fi
    done <<<"${PARSED}"
    env | grep -E '^ALERT_[A-Z0-9_]+=' | grep -vE '^ALERT_(WEBHOOK|STATE_FILE)=' | sort || true
  } > "${LOCAL}.tmp"
  mv "${LOCAL}.tmp" "${LOCAL}"
  # MCP files are refreshed from the repo daily; include vlan_report.py
  if [[ -f "${MAINT}" ]] && ! grep -q 'vlan_report.py' "${MAINT}"; then
    sed -i 's/^MCP_FILES="mcp_server.py pihole_api.py upsert_adguardhome.py"$/MCP_FILES="mcp_server.py pihole_api.py upsert_adguardhome.py vlan_report.py"/' "${MAINT}"
  fi
  put_file /usr/local/bin/dns-vlan-report 755 >/dev/null <<WRAP
#!/bin/sh
# Generated by deploy_multi_pi.sh: per-VLAN DNS report (runs as ${MCP_USER}, read-only)
#   sudo dns-vlan-report [--hours 24] [--vlan IoT] [--client 192.168.66.23] [--json]
[ "\$(id -u)" = 0 ] || exec sudo "\$0" "\$@"
exec runuser -u ${MCP_USER} -- /usr/bin/python3 ${MCP_DIR}/vlan_report.py "\$@"
WRAP
  put_file /etc/systemd/system/dns-vlan-alerts.service 644 >/dev/null <<UNIT
[Unit]
Description=managed_pihole: per-VLAN DNS alerts (threat hits, floods, DNS bypass, NXDOMAIN)
After=docker.service network-online.target

[Service]
Type=oneshot
User=${MCP_USER}
Nice=10
ExecStart=/usr/bin/python3 ${MCP_DIR}/vlan_report.py --hours 1 --alert --quiet
UNIT
  put_file /etc/systemd/system/dns-vlan-alerts.timer 644 >/dev/null <<'UNIT'
[Unit]
Description=managed_pihole: per-VLAN DNS alerts every 15 minutes

[Timer]
OnCalendar=*:0/15
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  put_file /etc/systemd/system/multi-pi-vlan-sync.service 644 >/dev/null <<UNIT
[Unit]
Description=managed_pihole: re-sync per-VLAN Pi-hole groups and lists
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Nice=10
ExecStart=${VLAN_DIR}/vlan-sync.sh
UNIT
  put_file /etc/systemd/system/multi-pi-vlan-sync.timer 644 >/dev/null <<'UNIT'
[Unit]
Description=managed_pihole: daily per-VLAN group sync

[Timer]
OnCalendar=*-*-* 05:15:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  # IPv6 prefixes (a new ISP prefix) -> VLAN groups, hourly; no downloads, no gravity
  put_file /etc/systemd/system/multi-pi-v6-sync.service 644 >/dev/null <<UNIT
[Unit]
Description=managed_pihole: IPv6 prefixes of each VLAN into its Pi-hole group
After=docker.service network-online.target

[Service]
Type=oneshot
Nice=10
ExecStart=${VLAN_DIR}/vlan-sync.sh --no-fetch --gravity never
UNIT
  put_file /etc/systemd/system/multi-pi-v6-sync.timer 644 >/dev/null <<'UNIT'
[Unit]
Description=managed_pihole: hourly IPv6 prefix refresh of the VLAN groups

[Timer]
OnCalendar=hourly
RandomizedDelaySec=5m
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now dns-vlan-alerts.timer multi-pi-vlan-sync.timer >/dev/null
  if [[ "${IPV6}" != off ]]; then systemctl enable --now multi-pi-v6-sync.timer >/dev/null
  else systemctl disable --now multi-pi-v6-sync.timer >/dev/null 2>&1 || true; fi
  ok "dns-vlan-report, MCP VLAN tools, alerts every 15 min (journalctl -u dns-vlan-alerts)"
  runuser -u "${MCP_USER}" -- python3 "${MCP_DIR}/vlan_report.py" --hours 24 | head -12 || warn "Report test failed."
fi

# =============================================================
# Summary
# =============================================================
section "Done"
HOST_IP=$(awk -v m=" ${MGMT_IFS} " 'index(m, " "$3" ") {print $4; exit}' <<<"${PARSED}" | cut -d/ -f1)
HOST_IP="${HOST_IP:-$(awk '$6=="full" {print $4; exit}' <<<"${PARSED}" | cut -d/ -f1)}"
cat <<EOF
  Pi-hole admin     : http://${HOST_IP:-<vm-ip>}/admin   (from a "full" VLAN; not from dns-only ones)
                      password: sudo cat ${PIHOLE_BASE}/secrets/pihole_password.txt
                      change it: sudo ${MAINT} password
  Unbound           : no web UI. Stats: sudo docker exec unbound unbound-control stats_noreset
  Per-VLAN DNS server - on your router, make it the ONLY DNS server of each VLAN:
    IPv4: in the VLAN's DHCP settings.$( [[ "${IPV6}" != off ]] && printf '\n    IPv6: as the VLAN'"'"'s IPv6 DNS (RDNSS in router advertisements and/or DHCPv6). Prefer\n          the fd.. (ULA) address: it stays the same when your ISP changes your prefix.' )
EOF
while read -r name vid iface addr net mode profile origin; do
  printf '    %-14s VLAN %-4s -> DNS %-15s (%s, %s, lists: %s)\n' "$name" "$vid" "${addr%/*}" "$net" "$mode" "$profile"
  if [[ "${IPV6}" != off ]]; then
    v6="${V6ADDR[$name]:-}"; v6="${v6% }"
    printf '    %-14s           IPv6 %s\n' "" "${v6:-none yet: no IPv6 advertisement (RA) from your router on this VLAN}"
  fi
done <<<"${PARSED}"
cat <<EOF

  Lists             : every VLAN gets the normal managed lists, plus its profile's
                      ${VLAN_DIR}/group_<profile>_*.txt and group_<name>_*.txt (+ your *.local.txt).
                      Re-synced daily. Unblock something for one VLAN only, e.g. IoT:
                        echo domain >> ${VLAN_DIR}/group_iot_allow.local.txt
                        sudo ${VLAN_DIR}/vlan-sync.sh --no-fetch
  See each VLAN     : sudo dns-vlan-report --hours 24      (or --vlan IoT, --client <ip>)
                      Pi-hole UI: Query Log, filter by client; Group Management shows the groups
  AI agent (MCP)    : claude mcp add dns -- ssh ${MCP_USER}@${HOST_IP:-<vm-ip>}
                      ask: "which IoT device sent the most bad DNS traffic today?"
  Alerts            : every 15 min -> journalctl -u dns-vlan-alerts$( [[ -n "${ALERT_WEBHOOK}" ]] && echo " + webhook" )
  Firewall          : dns-only on ${DNS_ONLY_IFS:-<none>}$( [[ "${IPV6}" != off ]] && echo ", IPv4 and IPv6" || echo " (IPv6 off there)" ) (systemctl status multi-pi-firewall)
  Settings          : ${SAVED}  (edit, then re-run this script)

  Note: devices on dns-only VLANs can still reach the internet through your router;
  this VM only refuses everything except DNS on that VLAN. Block IoT -> other VLANs and
  IoT -> any other DNS server (port 53/853) on the router so they must use this Pi-hole.
EOF
