#!/bin/bash
#-------------------------------------------------------------------------------
#  deploy_multi_pi.sh  -  ONE Pi-hole serving several VLANs (from a trunk), with
#                         different block lists per VLAN and per-VLAN monitoring
#
#  Version:       1.0.0
#  Last Updated:  11/5/2026
#  Author:        Christopher Gray
#  Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Ubuntu 22.04 / 24.04 / 26.04 VM on Proxmox or VMware, VLANs arriving as a trunk:
#
#      trunk (ens18) ──┬─ untagged (VLAN 0)  Users  192.168.1.10/24   (VM's normal address)
#                      └─ ens18.666 → vlan666 IoT   192.168.66.2/24   (added by this script)
#                                 │
#                     Docker: Pi-hole (+ Unbound + dnscrypt-proxy, install_pihole.sh)
#                             group "Users" = 192.168.1.0/24  → normal lists
#                             group "IoT"   = 192.168.66.0/24 → normal lists + group_iot_*.txt
#
#  What it does (safe to re-run; it only changes what differs):
#    1. checks the hypervisor (Proxmox/KVM or VMware) and prints what to set there
#    2. adds one VLAN sub-interface per tagged VLAN on the trunk (netplan, static IP,
#       no gateway, no IPv6) - the existing untagged config is not touched
#    3. installs the Docker stack with install_pihole.sh (Pi-hole, Unbound, dnscrypt-proxy,
#       managed lists, MCP server) unless it is already installed
#    4. one Pi-hole group per VLAN, the VLAN subnet as its client, and the group's own
#       lists (upsert_vlan_groups.py + group_<name>_*.txt) - re-synced daily
#    5. "dns-only" VLANs (IoT by default): the VM answers DNS (and ping) there and
#       nothing else - no web UI, no SSH, no routing through the VM
#    6. optional per-VLAN reverse lookups (ROUTERS) so reports show device names
#    7. per-VLAN monitoring: `sudo dns-vlan-report`, MCP tools for AI agents
#       (pihole_vlan_report, pihole_client_report) and alerts every 15 minutes when a
#       device hits threat lists, floods, tries to bypass DNS, or gets lots of NXDOMAIN
#       (journal, plus ALERT_WEBHOOK: ntfy / Slack / Discord / any URL)
#
#  Usage:
#    sudo bash deploy_multi_pi.sh          # asks: trunk NIC, each VLAN (ID, name, this VM's
#                                          # IP/prefix, dns-only/full, router), alert webhook
#    sudo VLANS="Users:0:auto IoT:666:192.168.66.2/24" \
#         ROUTERS="Users=192.168.1.1 IoT=192.168.66.1" \
#         ALERT_WEBHOOK=https://ntfy.sh/my-secret-topic bash deploy_multi_pi.sh
#    DRY_RUN=true bash deploy_multi_pi.sh                           # show what would change
#
#  Settings (env; saved to ${PIHOLE_BASE}/multi_pi.conf and reused on the next run):
#    VLANS        space separated NAME:VLAN_ID:ADDRESS[:MODE]
#                   VLAN_ID 0  = untagged / native VLAN of the trunk; ADDRESS "auto" = the
#                                VM's existing address on TRUNK_IF
#                   VLAN_ID 1-4094 = tagged; ADDRESS = this VM's IP/prefix in that VLAN
#                   MODE full | dns-only   (default: full for VLAN 0, dns-only otherwise)
#                 not set: asked interactively (re-runs offer the saved setup)
#    TRUNK_IF     interface carrying the trunk          (default: the one with the default route)
#    ROUTERS      "NAME=router-ip ..." per-VLAN reverse DNS (device names in reports)
#    ALERT_WEBHOOK  URL that receives alerts (POST)     (default: none, journal only)
#    ALERT_*      thresholds, see vlan_report.py        (written to the MCP local config)
#    FORCE_STACK=true   re-run install_pihole.sh even if already installed
#    SKIP_STACK=true    never run install_pihole.sh
#    Everything install_pihole.sh understands (UPSTREAM_MODE, SOCIAL_CLIENTS, ...) is
#    passed through. DNS_FILTER is always pihole (groups are a Pi-hole feature).
#
#  ChangeLog:
#    1.0.0  11/5/2026  New file (Claude Code).
#-------------------------------------------------------------------------------
set -euo pipefail

SCRIPT_VERSION="1.0.0"   # not VERSION: /etc/os-release (sourced below) sets that
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
KEYS="VLANS TRUNK_IF ROUTERS ALERT_WEBHOOK MANAGED_REPO_RAW"
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
      (Linux bridge default bridge-vids 2-4094 already includes 666.)
    - VM > Hardware > Network Device: leave "VLAN Tag" EMPTY. Untagged frames = Users,
      tagged frames (666) pass through to the VM. Optional, to allow only what you need:
        qm set <vmid> -net0 virtio=<MAC>,bridge=vmbr0,trunks=666
    - Physical switch port to the Proxmox host: trunk, VLAN 666 tagged, Users untagged (native).
    - Open vSwitch bridge instead of Linux bridge: same idea, VM port with no tag (trunk).
EOF
    ;;
    vmware) cat <<'EOF'
  VMware (detected). For the trunk to reach this VM:
    - Standard vSwitch: the VM's port group VLAN ID = 4095 (all VLANs, tagging done in the VM).
    - Distributed switch: port group VLAN type "VLAN trunking", range incl. 666.
    - Physical uplink port: trunk, VLAN 666 tagged, Users untagged (native).
    - No promiscuous mode / MAC changes / forged transmits needed: every VLAN uses the
      VM's own MAC (tagged sub-interface, not macvlan).
EOF
    ;;
    *) cat <<'EOF'
  Hypervisor: not Proxmox/KVM or VMware (or bare metal). The switch port / virtual NIC must
  deliver the Users VLAN untagged and the other VLANs tagged (802.1Q trunk).
EOF
    ;;
  esac
}
hv_notes

# =============================================================
# 2. VLAN definitions
# =============================================================
section "VLANs"
DETECTED_IF="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"

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
v_iface() { ip link show "$1" >/dev/null 2>&1 || { warn "No interface '$1'. Interfaces: $(ls /sys/class/net | grep -vE '^(lo|docker|br-|veth|vlan)' | tr '\n' ' ')"; return 1; }; }
v_name()  { [[ "$1" =~ ^[A-Za-z][A-Za-z0-9_-]{0,30}$ ]] || { warn "Use letters, digits, - or _ (start with a letter)."; return 1; }
            [[ " ${_names,,} " != *" ${1,,} "* ]] || { warn "Name '$1' is already used."; return 1; }; }
v_vid()   { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 4094 )) || { warn "VLAN ID must be 1-4094 (the untagged VLAN is already set)."; return 1; }
            [[ " ${_vids} " != *" $1 "* ]] || { warn "VLAN $1 is already defined."; return 1; }; }
v_cidr()  { python3 -I -c 'import ipaddress,sys; i=ipaddress.ip_interface(sys.argv[1]); sys.exit(0 if i.version==4 and "/" in sys.argv[1] and i.network.prefixlen<=30 and i.ip not in (i.network.network_address,i.network.broadcast_address) else 1)' "$1" 2>/dev/null \
            || { warn "Enter this VM's address WITH prefix, e.g. 192.168.66.2/24"; return 1; }; }
v_ip_opt() { [[ -z "$1" || "$1" == none ]] || python3 -I -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$1" 2>/dev/null || { warn "Enter an IPv4 address, or 'none'."; return 1; }; }
v_url_opt() { [[ -z "$1" || "$1" == none || "$1" =~ ^https?://[^[:space:]]+$ ]] || { warn "Enter an http(s):// URL, or 'none'."; return 1; }; }
gw_guess() { python3 -I -c 'import ipaddress,sys; print(next(ipaddress.ip_interface(sys.argv[1]).network.hosts()))' "$1" 2>/dev/null || true; }

wizard() {
  local name vid addr mode router more=y def_name def_vid _m
  _names=""; _vids=""; VLANS=""; ROUTERS=""
  cat <<'EOF'

  One Pi-hole serves every VLAN of the trunk. Each VLAN becomes a Pi-hole group with
  its own lists (IoT can block far more than Users) and its own DNS address on this VM.

EOF
  ask TRUNK_IF "Trunk interface (carries all VLANs)" "${TRUNK_IF:-${DETECTED_IF}}" v_iface
  local host; host=$(ip -4 -o addr show dev "${TRUNK_IF}" scope global 2>/dev/null | awk '{print $4; exit}')
  [[ -n "$host" ]] || die "${TRUNK_IF} has no IPv4 address. The untagged VLAN must already work (it is how you reach this VM)."
  echo ""
  echo "  Untagged / native VLAN (VLAN 0) on ${TRUNK_IF}: this VM is ${host} (kept as is)."
  ask name "  Name for this VLAN's group" "Users" v_name
  ask router "  Router/gateway IP on it, for device names in reports ('none' to skip)" \
      "$(ip -4 route show default dev "${TRUNK_IF}" 2>/dev/null | awk '{print $3; exit}')" v_ip_opt
  VLANS="${name}:0:auto:full"; _names="${name}"; _vids="0"
  [[ -n "$router" && "$router" != none ]] && ROUTERS="${name}=${router}"
  local n=0
  while true; do
    echo ""
    if (( n == 0 )); then ask_yn "Add a tagged VLAN (e.g. IoT)?" y || break
    else ask_yn "Add another tagged VLAN?" n || break; fi
    def_vid=$([[ $n == 0 && " ${_vids} " != *" 666 "* ]] && echo 666 || echo "")
    def_name=$([[ $n == 0 && " ${_names,,} " != *" iot "* ]] && echo IoT || echo "")
    ask vid  "  VLAN ID (802.1Q tag)" "${def_vid}" v_vid
    ask name "  Name for VLAN ${vid}'s group" "${def_name}" v_name
    ask addr "  This VM's IP/prefix on VLAN ${vid} (static, e.g. 192.168.$( (( vid <= 255 )) && echo "${vid}" || echo X ).2/24)" "" v_cidr
    echo "  Access to this VM from VLAN ${vid}:"
    echo "    1) dns-only - only DNS (and ping); no web UI, no SSH  (recommended for IoT/guests)"
    echo "    2) full     - like the untagged VLAN"
    ask _m "  Choose" "1" 
    mode=$([[ "$_m" == 2 || "$_m" == full ]] && echo full || echo dns-only)
    ask router "  Router IP on VLAN ${vid}, for device names ('none' to skip)" "$(gw_guess "$addr")" v_ip_opt
    VLANS+=" ${name}:${vid}:${addr}:${mode}"; _names+=" ${name}"; _vids+=" ${vid}"
    [[ -n "$router" && "$router" != none ]] && ROUTERS+="${ROUTERS:+ }${name}=${router}"
    n=$((n + 1))
  done
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
  echo "  Webhook : ${ALERT_WEBHOOK:-none}"
}

if [[ -z "${ENV_VAL[VLANS]:-}" ]] && interactive; then
  if [[ -n "${VLANS:-}" ]]; then
    echo "  Saved setup (${SAVED}):"; show_setup
    ask_yn "Use it?" y || wizard
  else
    wizard
  fi
  echo ""; echo "  Setup:"; show_setup
  ask_yn "Continue with this setup?" y || die "Stopped; nothing was changed yet."
fi
TRUNK_IF="${TRUNK_IF:-${DETECTED_IF}}"
[[ -n "${TRUNK_IF}" ]] || die "Could not find the trunk interface; set TRUNK_IF=ens18 (or similar)."
ip link show "${TRUNK_IF}" >/dev/null 2>&1 || die "Interface ${TRUNK_IF} does not exist."
[[ -n "${VLANS:-}" ]] || die 'No VLANs. Run interactively, or set VLANS="Users:0:auto IoT:666:192.168.66.2/24"'
info "Trunk interface: ${TRUNK_IF}"

# Parse + validate with python (ipaddress); output: NAME ID IFACE ADDR/PFX SUBNET MODE
host_addr=$(ip -4 -o addr show dev "${TRUNK_IF}" scope global 2>/dev/null | awk '{print $4; exit}')
PARSED=$(python3 -I - "${VLANS}" "${TRUNK_IF}" "${host_addr}" <<'PY'
import ipaddress, re, sys
vlans, trunk, host = sys.argv[1], sys.argv[2], sys.argv[3]
seen_n, seen_i, nets = set(), set(), []
for item in vlans.split():
    parts = item.split(":")
    if len(parts) not in (3, 4):
        sys.exit("VLANS: %r is not NAME:VLAN_ID:ADDRESS[:MODE]" % item)
    name, vid, addr = parts[:3]
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,30}", name):
        sys.exit("VLANS: bad name %r (letters, digits, - and _)" % name)
    if not vid.isdigit() or int(vid) > 4094:
        sys.exit("VLANS: bad VLAN id %r (0 = untagged, 1-4094)" % vid)
    vid = int(vid)
    mode = parts[3] if len(parts) == 4 else ("full" if vid == 0 else "dns-only")
    if mode not in ("full", "dns-only"):
        sys.exit("VLANS: mode for %s must be full or dns-only" % name)
    if name.lower() in seen_n or vid in seen_i:
        sys.exit("VLANS: duplicate name or VLAN id in %r" % item)
    seen_n.add(name.lower()); seen_i.add(vid)
    if vid == 0:
        if addr == "auto":
            if not host:
                sys.exit("VLANS: %s uses 'auto' but %s has no IPv4 address" % (name, trunk))
            addr = host
        iface = trunk
    else:
        if addr == "auto":
            sys.exit("VLANS: %s (VLAN %d) needs a static IP/prefix, e.g. 192.168.66.2/24" % (name, vid))
        iface = "vlan%d" % vid
    try:
        itf = ipaddress.ip_interface(addr)
    except ValueError:
        sys.exit("VLANS: bad address %r for %s (use IP/prefix)" % (addr, name))
    if itf.version != 4 or itf.network.prefixlen > 30 or itf.ip in (itf.network.network_address, itf.network.broadcast_address):
        sys.exit("VLANS: %s must be a usable IPv4 host address with a prefix of /30 or shorter" % addr)
    for n, other in nets:
        if itf.network.overlaps(other):
            sys.exit("VLANS: %s overlaps %s" % (itf.network, n))
    nets.append((name, itf.network))
    print(name, vid, iface, itf.with_prefixlen, itf.network, mode)
PY
) || die "Fix VLANS and re-run."
GROUP_MAP=""; TAGGED=0; DNS_ONLY_IFS=""
while read -r name vid iface addr net mode; do
  printf '  %-8s VLAN %-4s %-8s %-18s subnet %-18s %s\n' "$name" "$vid" "$iface" "$addr" "$net" "$mode"
  GROUP_MAP+="${GROUP_MAP:+,}${name}=${net}"
  [[ "$vid" != 0 ]] && TAGGED=$((TAGGED + 1))
  if [[ "$mode" == dns-only ]]; then
    [[ "$vid" == 0 ]] && die "${name}: dns-only on the untagged VLAN would cut off your SSH/web access; use full."
    DNS_ONLY_IFS+=" ${iface}"
  fi
done <<<"${PARSED}"
DNS_ONLY_IFS="${DNS_ONLY_IFS# }"

# =============================================================
# 3. VLAN sub-interfaces (netplan)
# =============================================================
section "VLAN interfaces (netplan)"
if (( TAGGED == 0 )); then
  info "No tagged VLANs; nothing to add."
else
  command -v netplan >/dev/null || die "netplan not found (Ubuntu uses netplan). Add the VLAN interfaces by hand, then re-run."
  # netplan id of the trunk NIC (usually its name). A definition we do not know about
  # would conflict, so refuse instead of guessing.
  LINK_ID=$(python3 -I - "${TRUNK_IF}" <<'PY'
import glob, sys
trunk = sys.argv[1]
try:
    import yaml
except ImportError:
    print(trunk); sys.exit(0)
found = None
for f in sorted(glob.glob("/etc/netplan/*.yaml")) + sorted(glob.glob("/lib/netplan/*.yaml")) + sorted(glob.glob("/run/netplan/*.yaml")):
    if f.endswith("60-managed-pihole-vlans.yaml"):
        continue
    try:
        doc = yaml.safe_load(open(f)) or {}
    except Exception:
        continue
    for nid, cfg in ((doc.get("network") or {}).get("ethernets") or {}).items():
        cfg = cfg or {}
        if nid == trunk or cfg.get("set-name") == trunk:
            found = nid
print(found or "")
PY
)
  [[ -n "${LINK_ID}" ]] || dry || die "${TRUNK_IF} is not defined in /etc/netplan/*.yaml; add the VLAN interfaces by hand (netplan 'vlans:'), then re-run."
  LINK_ID="${LINK_ID:-${TRUNK_IF}}"
  NP=$( {
    echo "# Generated by managed_pihole deploy_multi_pi.sh ${SCRIPT_VERSION} - re-running the script rewrites it."
    echo "# Tagged VLANs on the trunk ${TRUNK_IF}: static address, no gateway, no IPv6."
    echo "network:"
    echo "  version: 2"
    echo "  vlans:"
    while read -r name vid iface addr net mode; do
      [[ "$vid" == 0 ]] && continue
      cat <<EOF
    ${iface}:              # ${name}
      id: ${vid}
      link: ${LINK_ID}
      addresses: [${addr}]
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
EOF
    done <<<"${PARSED}"
  } )
  OLD_NP=""; [[ -f "${NETPLAN_FILE}" ]] && OLD_NP=$(cat "${NETPLAN_FILE}")
  missing=false   # file unchanged but an interface is down / lost its address -> apply anyway
  while read -r name vid iface addr net mode; do
    [[ "$vid" == 0 ]] && continue
    ip -4 addr show dev "$iface" 2>/dev/null | grep -q " ${addr%/*}/" || missing=true
  done <<<"${PARSED}"
  if { [[ "$(put_file "${NETPLAN_FILE}" 600 <<<"${NP}")" == changed ]] || $missing; } && ! dry; then
    info "Applying netplan (the network may blip for a second)..."
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
    while read -r name vid iface addr net mode; do
      [[ "$vid" == 0 ]] && continue
      for ((i = 0; i < 10; i++)); do ip -4 addr show dev "$iface" 2>/dev/null | grep -q " ${addr%/*}/" && break; sleep 1; done
      ip -4 addr show dev "$iface" 2>/dev/null | grep -q " ${addr%/*}/" \
        && ok "${iface} (${name}) is up with ${addr}" || warn "${iface} does not have ${addr} yet - check: ip addr show ${iface}"
    done <<<"${PARSED}"
  fi
fi

# =============================================================
# 4. Docker stack (install_pihole.sh)
# =============================================================
section "Pi-hole stack"
ENV_FILE="${PIHOLE_BASE}/pihole.env"
if [[ -r "${ENV_FILE}" ]] && grep -q '^DNS_FILTER="adguardhome"' "${ENV_FILE}"; then
  die "This host runs AdGuard Home. Per-VLAN groups need Pi-hole: re-run install_pihole.sh with DNS_FILTER=pihole first."
fi
if is_true "${SKIP_STACK:-false}"; then
  info "SKIP_STACK=true: not running install_pihole.sh"
elif [[ -s "${PIHOLE_BASE}/docker-compose.yml" ]] && ! is_true "${FORCE_STACK:-false}"; then
  ok "Already installed in ${PIHOLE_BASE} (FORCE_STACK=true to re-run install_pihole.sh)."
elif dry; then
  info "Would run: DNS_FILTER=pihole bash install_pihole.sh"
else
  INSTALLER="${SRC_DIR}/install_pihole.sh"
  if [[ ! -f "${INSTALLER}" ]]; then
    INSTALLER=$(mktemp); curl -fsSL "${MANAGED_REPO_RAW}/install_pihole.sh" -o "${INSTALLER}"
  fi
  # Port 53 is published on all addresses, so it answers on every VLAN address too.
  DNS_FILTER=pihole ENABLE_MCP="${ENABLE_MCP:-true}" bash "${INSTALLER}"
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
# 5. Save settings (re-runs, daily sync)
# =============================================================
if ! dry; then
  install -d -m 755 "${PIHOLE_BASE}"
  {
    echo "# Generated by deploy_multi_pi.sh ${SCRIPT_VERSION} - edit and re-run the script to change."
    for k in VLANS TRUNK_IF ROUTERS ALERT_WEBHOOK MANAGED_REPO_RAW GROUP_MAP DNS_ONLY_IFS; do
      printf '%s=%q\n' "$k" "${!k}"
    done
  } | put_file "${SAVED}" 600 >/dev/null
fi

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
  exec python3 "\$D/upsert_vlan_groups.py" --vlans "\${GROUP_MAP}" --dir "\$D" \${fetch} "\$@"
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
# ping) and nothing else: no web UI, no SSH, no forwarding/routing through the VM, no IPv6.
#   INPUT       -> MULTIPI-IN   (services on the host, e.g. sshd)
#   DOCKER-USER -> MULTIPI-FWD  (published container ports; Docker bypasses ufw)
IFACES="${DNS_ONLY_IFS}"
set -e
case "\${1:-start}" in
  stop)
    iptables -D INPUT -j MULTIPI-IN 2>/dev/null || true
    iptables -D DOCKER-USER -j MULTIPI-FWD 2>/dev/null || true
    iptables -F MULTIPI-IN 2>/dev/null || true; iptables -X MULTIPI-IN 2>/dev/null || true
    iptables -F MULTIPI-FWD 2>/dev/null || true; iptables -X MULTIPI-FWD 2>/dev/null || true
    exit 0 ;;
esac
iptables -N MULTIPI-IN 2>/dev/null || iptables -F MULTIPI-IN
iptables -N MULTIPI-FWD 2>/dev/null || iptables -F MULTIPI-FWD
iptables -N DOCKER-USER 2>/dev/null || true
for i in \$IFACES; do
  # IPv4 only on these VLANs: no IPv6 address = nothing to reach around these IPv4 rules
  sysctl -qw "net.ipv6.conf.\$i.disable_ipv6=1" 2>/dev/null || true
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
    while read -r name vid iface addr net mode; do
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
  systemctl daemon-reload
  systemctl enable --now dns-vlan-alerts.timer multi-pi-vlan-sync.timer >/dev/null
  ok "dns-vlan-report, MCP VLAN tools, alerts every 15 min (journalctl -u dns-vlan-alerts)"
  runuser -u "${MCP_USER}" -- python3 "${MCP_DIR}/vlan_report.py" --hours 24 | head -12 || warn "Report test failed."
fi

# =============================================================
# Summary
# =============================================================
section "Done"
HOST_IP=$(awk '$2==0 {print $4}' <<<"${PARSED}" | cut -d/ -f1)
cat <<EOF
  Pi-hole admin     : http://${HOST_IP:-<vm-ip>}/admin   (password: ${PIHOLE_BASE}/secrets/pihole_password.txt)
  Per-VLAN DNS server (set it as the ONLY DNS server in each VLAN's DHCP on your router):
EOF
while read -r name vid iface addr net mode; do
  printf '    %-8s VLAN %-4s -> DNS %-15s (%s, group "%s", %s)\n' "$name" "$vid" "${addr%/*}" "$net" "$name" "$mode"
done <<<"${PARSED}"
cat <<EOF

  Lists             : every VLAN gets the normal managed lists; a group also gets
                      ${VLAN_DIR}/group_<name>_*.txt (+ your *.local.txt). Re-synced daily.
                      Unblock something for IoT only: echo domain >> ${VLAN_DIR}/group_iot_allow.local.txt
                      then: sudo ${VLAN_DIR}/vlan-sync.sh --no-fetch
  See each VLAN     : sudo dns-vlan-report --hours 24      (or --vlan IoT, --client <ip>)
                      Pi-hole UI: Query Log, filter by client; Group Management shows the groups
  AI agent (MCP)    : claude mcp add dns -- ssh ${MCP_USER}@${HOST_IP:-<vm-ip>}
                      ask: "which IoT device sent the most bad DNS traffic today?"
  Alerts            : every 15 min -> journalctl -u dns-vlan-alerts$( [[ -n "${ALERT_WEBHOOK}" ]] && echo " + webhook" )
  Firewall          : dns-only on ${DNS_ONLY_IFS:-<none>} (systemctl status multi-pi-firewall)
  Settings          : ${SAVED}  (edit, then re-run this script)

  Note: devices on dns-only VLANs can still reach the internet through your router;
  this VM only refuses everything except DNS on that VLAN. Block IoT -> other VLANs and
  IoT -> any other DNS server (port 53/853) on the router so they must use this Pi-hole.
EOF
