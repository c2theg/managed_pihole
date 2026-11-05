#!/bin/sh
#
[ -t 1 ] && clear   # only clear when run interactively (not from cron)
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

now=$(date)
printf '%s\n' "Running update_lists.sh at $now
Current working dir: $SCRIPTPATH

 _____             _         _    _          _
|     |___ ___ ___| |_ ___ _| |  | |_ _ _   |_|
|   --|  _| -_| .'|  _| -_| . |  | . | | |   _
|_____|_| |___|__,|_| |___|___|  |___|_  |  |_|
                                     |___|

 _____ _       _     _           _              _____    __    _____
|     | |_ ___|_|___| |_ ___ ___| |_ ___ ___   |     |__|  |  |   __|___ ___ _ _
|   --|   |  _| |_ -|  _| . | . |   | -_|  _|  | | | |  |  |  |  |  |  _| .'| | |
|_____|_|_|_| |_|___|_| |___|  _|_|_|___|_|    |_|_|_|_____|  |_____|_| |__,|_  |
                            |_|                                             |___|

Version:       1.0.1
Last Updated:  11/5/2026
Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
"
#-------------------------------------------------------------------------------
#  Keeps a Pi-hole v6 install (native OS install OR Docker) up to date with the
#  managed_pihole lists:
#    1. checks Internet access
#    2. updates the OS packages (skip with SKIP_OS_UPDATE=1)
#    3. backs up Pi-hole (Teleporter + databases) with backup_dbs.py
#    4. downloads the latest managed_pihole files into this folder (skip: SKIP_DOWNLOAD=1)
#    5. updates Pi-hole  (native: pihole -up | docker: docker compose pull/up, needs
#       PIHOLE_COMPOSE_DIR)  (skip with SKIP_PIHOLE_UPDATE=1)
#    6. adds the allow list (pihole_allowlist.sh)
#    7. adds block lists / regexes / excluded domains and runs gravity (upsert_lists.py)
#
#  AdGuard Home instead of Pi-hole: set DNS_FILTER=adguardhome (+ ADGUARD_PASSWORD).
#  Steps 5-7 are then replaced by upsert_adguardhome.py (lists, rules, refresh).
#  Unbound: see setup_unbound.sh (native) or install_pihole.sh (Docker).
#
#  Settings: see pihole_common.sh (env vars or /etc/managed_pihole.conf)
#    MANAGED_PIHOLE_REPO  raw URL to download from
#                         (default https://raw.githubusercontent.com/c2theg/managed_pihole/main)
#
#  ChangeLog:
#    1.0.1  11/5/2026  (Claude Code) Also downloads mcp_server.py, vlan_report.py,
#                      upsert_vlan_groups.py and the group_iot_*.txt lists.
#    1.0.0  11/5/2026  (Claude Code) Updated for Pi-hole v6 and Docker:
#             - Works with Docker installs via pihole_common.sh.
#             - FIX: the script deleted and re-downloaded itself while running, which
#               can corrupt a running sh script. Files now download to a temp folder
#               and are moved into place only if the download worked.
#             - FIX: backup step only ran if the backup folder already existed, and
#               copied v5-only files (setupVars.conf, whitelist.txt, blacklist.txt).
#               Now runs backup_dbs.py (Teleporter + databases).
#             - FIX: API_EXCLUDE_DOMAINS in setupVars.conf does not exist in v6. Excluded
#               domains are now set by upsert_lists.py (webserver.api.excludeDomains).
#             - Removed downloads of initial_setup.sh / initial_setup.py (no longer in
#               the repo) and the copies into /root (everything runs from this folder).
#             - Removed "chown pihole:www-data" (v6 has no lighttpd/www-data web server).
#             - Docker: Pi-hole is updated by pulling the new image, never "pihole -up"
#               (not supported inside the container). OS update runs on the host.
#             - Internet check falls back to HTTPS if ping (ICMP) is blocked.
#             - "\r\n" in echo replaced with printf (dash printed them literally).
#             - NEW: DNS_FILTER=adguardhome runs upsert_adguardhome.py instead of the
#               Pi-hole steps. Downloads upsert_adguardhome.py and setup_unbound.sh too.
#    0.5.11 9/29/2023  Last Pi-hole v5 version.
#-------------------------------------------------------------------------------

# Settings file(s) first: DNS_FILTER decides which filter we manage
for _cfg in /etc/managed_pihole.conf "$SCRIPTPATH/managed_pihole.conf"; do
    # shellcheck disable=SC1090
    [ -r "$_cfg" ] && . "$_cfg"
done
DNS_FILTER="${DNS_FILTER:-pihole}"
echo "DNS filter: $DNS_FILTER"
if [ "$DNS_FILTER" = "adguardhome" ]; then
    PIHOLE_MODE="adguardhome"   # not used by the AdGuard Home path
    SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
else
    . "$SCRIPTPATH/pihole_common.sh"
fi

# Native installs need root (pihole -up, /etc/pihole/cli_pw). Re-run with sudo, keeping settings.
if [ "$PIHOLE_MODE" = "native" ] && [ "$(id -u)" -ne 0 ]; then
    echo "Re-running with sudo..."
    exec sudo -E "$SCRIPT" "$@"
fi

REPO="${MANAGED_PIHOLE_REPO:-https://raw.githubusercontent.com/c2theg/managed_pihole/main}"
FILES="update_lists.sh pihole_common.sh pihole_api.py upsert_lists.py backup_dbs.py
pihole_allowlist.sh export_custom_lists.sh cleanup.sh upsert_adguardhome.py setup_unbound.sh doh_servers.txt
cgray_blocklists.txt blocklist_regexs_cg.txt allowlist_regexs_cg.txt allow_regex_social_cg.txt
pihole_exclude_list.txt mcp_server.py vlan_report.py
upsert_vlan_groups.py group_iot_blocklists.txt group_iot_regex_deny.txt"

#-------------------------------------------------------------------------------
echo "Checking Internet status..."
if ping -q -c3 github.com > /dev/null 2>&1 || wget -q --spider --timeout=10 https://github.com > /dev/null 2>&1; then
    echo "Connected!!!"
else
    printf '\n\tNot connected to the Internet. Fix that first and try again\n\n'
    exit 1
fi

#--- OS updates (on the host - for Docker that is the machine running the container) ---
if [ "${SKIP_OS_UPDATE:-0}" != "1" ] && command -v apt-get > /dev/null 2>&1; then
    echo "Updating OS packages... "
    $SUDO apt-get update
    $SUDO apt-get dist-upgrade -y
    $SUDO apt-get autoclean
fi

#--- Backup (Pi-hole) ---
if [ "$DNS_FILTER" != "adguardhome" ] && [ -f "$SCRIPTPATH/backup_dbs.py" ] && command -v python3 > /dev/null 2>&1; then
    echo "Backing up pihole... "
    python3 "$SCRIPTPATH/backup_dbs.py" --keep 7 || echo "WARNING: backup had errors - continuing."
fi

#--- Download latest versions ---
if [ "${SKIP_DOWNLOAD:-0}" != "1" ]; then
    echo "Downloading latest versions from $REPO ..."
    TMPDIR_DL=$(mktemp -d)
    for f in $FILES; do
        if wget -q -O "$TMPDIR_DL/$f" "$REPO/$f" && [ -s "$TMPDIR_DL/$f" ]; then
            # mv replaces the file without touching the copy this script is running from
            mv -f "$TMPDIR_DL/$f" "$SCRIPTPATH/$f"
            echo "  updated $f"
        else
            echo "  !! could not download $f - keeping the current copy"
        fi
    done
    rm -rf "$TMPDIR_DL"
    chmod 755 "$SCRIPTPATH"/*.sh "$SCRIPTPATH"/*.py
fi

#--- AdGuard Home: lists + rules + refresh, then done ---
if [ "$DNS_FILTER" = "adguardhome" ]; then
    echo "Applying managed lists to AdGuard Home..."
    python3 "$SCRIPTPATH/upsert_adguardhome.py" --dir "$SCRIPTPATH"
    echo "update_lists.sh finished at $(date)"
    exit 0
fi

#--- Update Pi-hole ---
if [ "${SKIP_PIHOLE_UPDATE:-0}" != "1" ]; then
    echo "Updating pihole..."
    if [ "$PIHOLE_MODE" = "native" ]; then
        pihole -up
    elif [ -n "$PIHOLE_COMPOSE_DIR" ] && [ -d "$PIHOLE_COMPOSE_DIR" ]; then
        if docker compose version > /dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
        (cd "$PIHOLE_COMPOSE_DIR" && $DC pull && $DC up -d)
        echo "Waiting for the Pi-hole container to come back..."
        i=0
        until docker exec "$PIHOLE_CONTAINER" pihole status > /dev/null 2>&1 || [ $i -ge 30 ]; do
            sleep 5; i=$((i + 1))
        done
    else
        echo "  Docker install: set PIHOLE_COMPOSE_DIR to your docker-compose.yml folder to"
        echo "  update automatically, or run:  docker compose pull && docker compose up -d"
    fi
fi

#--- Lists ---
echo "Allow list..."
sh "$SCRIPTPATH/pihole_allowlist.sh"

echo "Block lists, regexes, excluded domains and gravity..."
python3 "$SCRIPTPATH/upsert_lists.py" --dir "$SCRIPTPATH"

echo "update_lists.sh finished at $(date)"
