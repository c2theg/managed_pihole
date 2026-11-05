#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
Version = "1.0.0"
Updated = "11/5/2026"
#  Updated by: Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Backs up a Pi-hole v6 install (native OS install OR Docker):
#    1. Teleporter archive (.zip) from the v6 API: pihole.toml, gravity.db (lists,
#       domains, groups, clients), custom DNS, DHCP leases ... This is the file you
#       restore in the web UI under Settings > Teleporter.
#    2. Optional: gzip'd online copies of gravity.db and pihole-FTL.db (query history),
#       made with SQLite's backup API so they are safe while pihole-FTL is running.
#       Needs read access to Pi-hole's folder: /etc/pihole (native, run with sudo) or
#       your docker volume, e.g. --pihole-dir /opt/pihole/etc-pihole
#
#  Usage:
#    sudo ./backup_dbs.py                         # -> /home/pi/pihole_backups (or $HOME)
#    sudo ./backup_dbs.py --dest /mnt/usb/backups --keep 14
#    ./backup_dbs.py --pihole-dir ./etc-pihole    # docker volume on the host
#    ./backup_dbs.py --no-teleporter              # only the sqlite copies
#
#  ChangeLog:
#    1.0.0  11/5/2026  (Claude Code) Rewritten for Pi-hole v6:
#             - FIX: script could not run (syntax error on the sqlite3 line, and shutil
#               was never imported).
#             - NEW: Teleporter backup through the v6 API (works for Docker too).
#             - Uses sqlite3.Connection.backup() for consistent copies of live dbs.
#             - Timestamped file names, --keep N old backups, --dest, --pihole-dir.
#    0.0.1  11/7/2020  Initial release for James.
#
#  Sources:
#     https://docs.pi-hole.net/database/
#     https://docs.pi-hole.net/api/   (GET /api/teleporter)
#-------------------------------------------------------------------------------
import argparse
import datetime
import glob
import gzip
import os
import shutil
import signal
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pihole_api import PiholeAPI, PiholeAPIError, load_settings  # noqa: E402

DB_FILES = ["gravity.db", "pihole-FTL.db"]


def set_run_timeout(seconds):
    def alarm(*_):
        raise SystemExit("Timed out!")
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(seconds)


def default_dest():
    return "/home/pi/pihole_backups" if os.path.isdir("/home/pi") else os.path.expanduser("~/pihole_backups")


def prune(dest, pattern, keep):
    files = sorted(glob.glob(os.path.join(dest, pattern)))
    for old in files[:-keep] if keep > 0 else []:
        print("  Removing old backup", old)
        os.remove(old)


def backup_sqlite(src, dest_gz):
    tmp = dest_gz[:-3]
    src_conn = sqlite3.connect("file:%s?mode=ro" % src, uri=True)
    dst_conn = sqlite3.connect(tmp)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()
    with open(tmp, "rb") as f_in, gzip.open(dest_gz, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(tmp)


def main():
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Back up Pi-hole v6")
    parser.add_argument("--dest", default=default_dest(), help="backup folder")
    parser.add_argument("--pihole-dir", default=settings.get("PIHOLE_DIR") or "/etc/pihole",
                        help="host path of Pi-hole's /etc/pihole (docker: your volume)")
    parser.add_argument("--keep", type=int, default=7, help="how many backups of each kind to keep")
    parser.add_argument("--no-teleporter", action="store_true", help="skip the Teleporter archive")
    parser.add_argument("--no-db", action="store_true", help="skip the raw sqlite copies")
    args = parser.parse_args()

    print("backup_dbs.py  Version:", Version, " Updated:", Updated)
    set_run_timeout(1800)
    os.makedirs(args.dest, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    ok = True

    if not args.no_teleporter:
        out = os.path.join(args.dest, "pihole-teleporter_%s.zip" % stamp)
        print("Exporting Teleporter archive to", out, "...")
        try:
            with PiholeAPI(settings=settings) as api:
                api.download("/teleporter", out)
            print("  Done.")
            prune(args.dest, "pihole-teleporter_*.zip", args.keep)
        except PiholeAPIError as e:
            ok = False
            print("  !! Teleporter export failed:", e)
            print("     (App passwords need webserver.api.app_sudo = true to export.)")

    if not args.no_db:
        for name in DB_FILES:
            src = os.path.join(args.pihole_dir, name)
            if not os.access(src, os.R_OK):
                print("Skipping %s (not readable - run with sudo, or pass --pihole-dir)" % src)
                continue
            out = os.path.join(args.dest, "%s_%s.backup.gz" % (name, stamp))
            print("Backing up %s -> %s ..." % (src, out))
            try:
                backup_sqlite(src, out)
                print("  Done.")
                prune(args.dest, "%s_*.backup.gz" % name, args.keep)
            except (sqlite3.Error, OSError) as e:
                ok = False
                print("  !! Failed:", e)

    print("\nAll backups have been completed!" if ok else "\nFinished with errors (see above).")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
