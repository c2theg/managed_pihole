#!/bin/sh
#
[ -t 1 ] && clear
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

now=$(date)
echo "Running cleanup.sh at $now
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
Version:       1.0.0
Last Updated:  11/5/2026
Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
"
#-------------------------------------------------------------------------------
#  Cleans up Pi-hole v6 logs (native OS install or Docker).
#    - deletes rotated log files in /var/log/pihole/  (pihole.log.N, FTL.log.N, ...)
#    - "pihole flush": empties pihole.log and purges the last 24h of queries
#    Pi-hole itself is updated by update_lists.sh, not here.
#
#  ChangeLog:
#    1.0.0  11/5/2026  (Claude Code) Updated for Pi-hole v6:
#             - FIX: a blank first line stopped "#!/bin/sh" from working.
#             - Log paths moved in v6: /var/log/pihole-FTL.log.* and /var/log/pihole.log.*
#               are now /var/log/pihole/*.log.*
#             - "pihole -v -c": "-c" is now "chronometer" in v6, so just "pihole -v".
#             - Removed "pihole -up" (it was labelled "Stopping pihole-FTL", and
#               update_lists.sh already updates Pi-hole). Removed the
#               "service pihole-FTL start" since FTL is never stopped.
#             - Works with Docker (see pihole_common.sh).
#    0.0.1  12/26/2020 Initial version.
#-------------------------------------------------------------------------------
. "$SCRIPTPATH/pihole_common.sh"

ph -v
ph status

echo "Deleting rotated Pi-hole logs..."
ph_sh 'rm -f /var/log/pihole/*.log.* /var/log/pihole-FTL.log.* /var/log/pihole.log.*'

echo "Flushing Pi-hole query log..."
ph flush

echo "Done."
