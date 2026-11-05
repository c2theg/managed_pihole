#!/bin/sh
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
echo "
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
#  Exports your custom Pi-hole v6 domains and subscribed lists to text files.
#  Works for native installs and Docker (see pihole_common.sh).
#
#  Usage:   ./export_custom_lists.sh [output_folder]     (default: current folder)
#
#  Output files (same names as before, plus two new ones):
#    exwhite.txt   exact allow domains     (domainlist type 0)
#    exblack.txt   exact deny domains      (domainlist type 1)
#    regwhite.txt  regex allow domains     (domainlist type 2)
#    regblack.txt  regex deny domains      (domainlist type 3)
#    adlists_block.txt / adlists_allow.txt   subscribed lists (adlist type 0 / 1)
#
#  ChangeLog:
#    1.0.0  11/5/2026  (Claude Code) Updated for Pi-hole v6:
#             - Works with Docker (runs pihole-FTL sqlite3 inside the container).
#             - Opens gravity.db read-only so it is safe while Pi-hole is running.
#             - NEW: exports subscribed block/allow lists; optional output folder.
#             - FIX: "\r\n" printed literally by dash; replaced with plain echo.
#    0.0.1  9/29/2023  Initial version.
#-------------------------------------------------------------------------------
. "$SCRIPTPATH/pihole_common.sh"

OUT="${1:-.}"
mkdir -p "$OUT"

q() {
    ph_ftl sqlite3 -readonly /etc/pihole/gravity.db "$1"
}

q "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 0;" > "$OUT/exwhite.txt"
q "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 1;" > "$OUT/exblack.txt"
q "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 2;" > "$OUT/regwhite.txt"
q "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 3;" > "$OUT/regblack.txt"
q "SELECT address FROM adlist WHERE enabled = 1 AND type = 0;"    > "$OUT/adlists_block.txt"
q "SELECT address FROM adlist WHERE enabled = 1 AND type = 1;"    > "$OUT/adlists_allow.txt"

wc -l "$OUT"/exwhite.txt "$OUT"/exblack.txt "$OUT"/regwhite.txt "$OUT"/regblack.txt \
      "$OUT"/adlists_block.txt "$OUT"/adlists_allow.txt
echo "Done exporting all files to $OUT"
