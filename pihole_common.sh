#!/bin/sh
#-------------------------------------------------------------------------------
#  pihole_common.sh  -  shared helpers for the managed_pihole shell scripts
#
#  Version:       1.0.0
#  Last Updated:  11/5/2026
#  Author:        Christopher Gray
#  Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Purpose:
#    Lets every script in this repo work against BOTH kinds of Pi-hole v6 install:
#      - "native"  : installed on the OS with  curl -sSL https://install.pi-hole.net | bash
#      - "docker"  : the official pihole/pihole container image
#
#    Source it from another script:   . "$SCRIPTPATH/pihole_common.sh"
#    then use:   ph <pihole args>        e.g.  ph allow example.com
#                ph_ftl <pihole-FTL args> e.g.  ph_ftl sqlite3 /etc/pihole/gravity.db "..."
#                ph_sh "<shell command>"  runs a shell command where Pi-hole lives
#
#  Settings (environment variables, or KEY=VALUE lines in /etc/managed_pihole.conf
#  or ./managed_pihole.conf next to the scripts):
#    PIHOLE_MODE         auto | native | docker      (default: auto)
#    PIHOLE_CONTAINER    docker container name        (default: pihole)
#    PIHOLE_COMPOSE_DIR  folder holding docker-compose.yml, used to upgrade the
#                        container image (optional)
#    PIHOLE_API_URL      e.g. http://127.0.0.1:8080/api  (optional, used by the .py tools)
#    PIHOLE_PASSWORD     web/API password or app password (optional, used by the .py tools)
#    PIHOLE_DIR          host folder that holds Pi-hole's /etc/pihole
#                        (native: /etc/pihole, docker: your ./etc-pihole volume)
#    DNS_FILTER          pihole | adguardhome  (read by update_lists.sh; AdGuard Home
#                        uses ADGUARD_URL / ADGUARD_USER / ADGUARD_PASSWORD instead)
#
#  ChangeLog:
#    1.0.0  11/5/2026  New file (Claude Code). Native/Docker detection and command
#                      wrappers added for Pi-hole v6 support.
#-------------------------------------------------------------------------------

# Load optional config files (later files override earlier ones)
for _cfg in /etc/managed_pihole.conf "${SCRIPTPATH:-.}/managed_pihole.conf"; do
    if [ -r "$_cfg" ]; then
        # shellcheck disable=SC1090
        . "$_cfg"
    fi
done

PIHOLE_MODE="${PIHOLE_MODE:-auto}"
PIHOLE_CONTAINER="${PIHOLE_CONTAINER:-pihole}"

if [ "$PIHOLE_MODE" = "auto" ]; then
    if command -v pihole >/dev/null 2>&1; then
        PIHOLE_MODE="native"
    elif command -v docker >/dev/null 2>&1 && \
         [ "$(docker inspect -f '{{.State.Running}}' "$PIHOLE_CONTAINER" 2>/dev/null)" = "true" ]; then
        PIHOLE_MODE="docker"
    else
        echo "ERROR: Could not find Pi-hole. No 'pihole' command and no running docker container named '$PIHOLE_CONTAINER'."
        echo "       Set PIHOLE_MODE=native|docker and/or PIHOLE_CONTAINER=<name>."
        exit 1
    fi
fi

if [ -z "$PIHOLE_DIR" ] && [ "$PIHOLE_MODE" = "native" ]; then
    PIHOLE_DIR="/etc/pihole"
fi

# Use sudo only when not already root (cron jobs usually run as root)
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

export PIHOLE_MODE PIHOLE_CONTAINER PIHOLE_COMPOSE_DIR PIHOLE_API_URL PIHOLE_PASSWORD PIHOLE_DIR

# Run the pihole CLI
ph() {
    if [ "$PIHOLE_MODE" = "docker" ]; then
        docker exec "$PIHOLE_CONTAINER" pihole "$@"
    else
        $SUDO pihole "$@"
    fi
}

# Run pihole-FTL (e.g. 'sqlite3', '--config', '--teleporter')
ph_ftl() {
    if [ "$PIHOLE_MODE" = "docker" ]; then
        docker exec "$PIHOLE_CONTAINER" pihole-FTL "$@"
    else
        $SUDO pihole-FTL "$@"
    fi
}

# Run a shell command line on the machine/container where Pi-hole runs
ph_sh() {
    if [ "$PIHOLE_MODE" = "docker" ]; then
        docker exec "$PIHOLE_CONTAINER" sh -c "$1"
    else
        $SUDO sh -c "$1"
    fi
}

echo "Pi-hole install type: $PIHOLE_MODE$( [ "$PIHOLE_MODE" = "docker" ] && echo " (container: $PIHOLE_CONTAINER)")"
