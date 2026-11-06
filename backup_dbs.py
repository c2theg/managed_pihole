#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
Version = "2.0.0"
Updated = "11/6/2026"
#  Updated by: Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Backs up the config of Pi-hole v6, Unbound and AdGuard Home, whichever of them are
#  on this machine (native OS install OR Docker). Keeps the newest --keep of each kind.
#    1. Pi-hole: Teleporter archive (.zip) from the v6 API: pihole.toml, gravity.db
#       (lists, domains, groups, clients), custom DNS, DHCP leases ... Restore it in the
#       web UI under Settings > Teleporter.
#       Optional: gzip'd online copies of gravity.db and pihole-FTL.db (query history),
#       made with SQLite's backup API so they are safe while pihole-FTL is running.
#       Needs read access to Pi-hole's folder: /etc/pihole (native, run with sudo) or
#       your docker volume, e.g. --pihole-dir /opt/pihole/etc-pihole
#    2. Unbound: unbound-config_<time>.tar.gz of /etc/unbound (native), or of
#       /etc/unbound inside the "unbound" container (docker cp; includes bind mounts).
#    3. AdGuard Home: adguardhome-config_<time>.tar.gz with AdGuardHome.yaml (native:
#       /opt/AdGuardHome, the snap, or the -c path of its systemd unit; docker: the
#       container's /opt/adguardhome/conf). That file is AdGuard Home's whole config:
#       filters, rules, clients, DNS settings and the (hashed) login.
#  Backups hold password hashes and keys, so files are written mode 600 (folder 700).
#
#  Usage:
#    sudo ./backup_dbs.py                         # everything found -> default folder
#    sudo ./backup_dbs.py --dest /mnt/usb/backups --keep 14
#    sudo ./backup_dbs.py --only unbound,adguardhome
#    ./backup_dbs.py --pihole-dir ./etc-pihole    # docker volume on the host
#    ./backup_dbs.py --no-teleporter              # only the Pi-hole sqlite copies
#    sudo ./backup_dbs.py --install-timer         # daily at 03:00, keep 4 (systemd or cron)
#    sudo ./backup_dbs.py --install-timer --at 02:15 --keep 7 --dest /mnt/usb/dns
#    sudo ./backup_dbs.py --remove-timer
#
#  Settings (env vars or /etc/managed_pihole.conf):
#    BACKUP_DIR        backup folder   (default /home/pi/pihole_backups, else ~/pihole_backups)
#    BACKUP_KEEP       backups of each kind to keep (default 4)
#    BACKUP_SERVICES   auto | any of pihole,unbound,adguardhome (default auto = all found)
#    BACKUP_TIME       --install-timer time of day, HH:MM (default 03:00, local time)
#    PIHOLE_CONTAINER / UNBOUND_CONTAINER / ADGUARD_CONTAINER   docker container names
#    ADGUARD_CONF      path of a native AdGuardHome.yaml, if not in a standard place
#
#  Restore:
#    Pi-hole       web UI > Settings > Teleporter > Restore  (or: pihole-FTL --teleporter FILE)
#    Unbound       tar -xzf unbound-config_*.tar.gz -C /   (docker: into your mounted folder)
#                  then unbound-checkconf && systemctl restart unbound
#    AdGuard Home  stop it, put AdGuardHome.yaml back, start it
#
#  ChangeLog:
#    2.0.0  11/6/2026  (Claude Code) Backs up Unbound and AdGuard Home config too.
#             - NEW: Unbound (/etc/unbound, native or docker) and AdGuard Home
#               (AdGuardHome.yaml, native or docker). Each is found automatically and
#               skipped when not installed; --only / BACKUP_SERVICES to choose.
#             - NEW: --install-timer [--at HH:MM] installs a daily job (systemd timer,
#               cron if no systemd); --remove-timer removes it.
#             - NEW: --subdir (update_lists.sh keeps its pre-update backup apart, so it
#               does not push daily backups out of the rotation).
#             - --keep default 7 -> 4 (BACKUP_KEEP). Backups are mode 600, folder 700.
#             - Pi-hole is skipped (not an error) when it is not installed.
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
#     https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration
#-------------------------------------------------------------------------------
import argparse
import datetime
import glob
import gzip
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pihole_api import PiholeAPI, PiholeAPIError, load_settings  # noqa: E402

DB_FILES = ["gravity.db", "pihole-FTL.db"]
SERVICES = ("pihole", "unbound", "adguardhome")
UNIT = "managed-dns-backup"
CRON_FILE = "/etc/cron.d/managed-dns-backup"
AGH_CANDIDATES = ["/opt/AdGuardHome/AdGuardHome.yaml",
                  "/var/snap/adguard-home/current/AdGuardHome.yaml",
                  "/usr/local/AdGuardHome/AdGuardHome.yaml"]


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


def run(cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


def container_running(name):
    if not name or not shutil.which("docker"):
        return False
    r = run(["docker", "inspect", "-f", "{{.State.Running}}", name])
    return r.returncode == 0 and r.stdout.decode().strip() == "true"


def finish(tmp, out):
    """Move a finished temp file into place (so a failed run never leaves half a backup)."""
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)


#--- Pi-hole -------------------------------------------------------------------
def pihole_present(settings):
    return bool(shutil.which("pihole") or settings.get("PIHOLE_API_URL")
                or container_running(settings.get("PIHOLE_CONTAINER", "pihole")))


def backup_sqlite(src, dest_gz):
    tmp = dest_gz[:-3]
    src_conn = sqlite3.connect("file:%s?mode=ro" % src, uri=True)
    dst_conn = sqlite3.connect(tmp)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()
    with open(tmp, "rb") as f_in, gzip.open(dest_gz + ".part", "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(tmp)
    finish(dest_gz + ".part", dest_gz)


def backup_pihole(args, settings, stamp):
    ok = True
    if not args.no_teleporter:
        out = os.path.join(args.dest, "pihole-teleporter_%s.zip" % stamp)
        print("Pi-hole: Teleporter archive ->", out)
        try:
            with PiholeAPI(settings=settings) as api:
                api.download("/teleporter", out + ".part")
            finish(out + ".part", out)
            print("  Done.")
            prune(args.dest, "pihole-teleporter_*.zip", args.keep)
        except (PiholeAPIError, OSError) as e:
            ok = False
            print("  !! Teleporter export failed:", e)
            print("     (App passwords need webserver.api.app_sudo = true to export.)")
            if os.path.exists(out + ".part"):
                os.remove(out + ".part")

    if not args.no_db:
        for name in DB_FILES:
            src = os.path.join(args.pihole_dir, name)
            if not os.access(src, os.R_OK):
                print("Pi-hole: skipping %s (not readable - run with sudo, or pass --pihole-dir)" % src)
                continue
            out = os.path.join(args.dest, "%s_%s.backup.gz" % (name, stamp))
            print("Pi-hole: %s -> %s" % (src, out))
            try:
                backup_sqlite(src, out)
                print("  Done.")
                prune(args.dest, "%s_*.backup.gz" % name, args.keep)
            except (sqlite3.Error, OSError) as e:
                ok = False
                print("  !! Failed:", e)
    return ok


#--- Unbound / AdGuard Home: config folders -> .tar.gz ----------------------------
def tar_paths(out, paths):
    """Native: tar the given files/folders (stored with their absolute path, minus the /)."""
    tmp = out + ".part"
    with tarfile.open(tmp, "w:gz") as tar:
        for p in paths:
            tar.add(p, arcname=p.lstrip("/"))
    finish(tmp, out)


def tar_from_container(out, container, path, must_have=None):
    """Docker: `docker cp CONTAINER:PATH -` streams a tar (bind mounts included); gzip it."""
    tmp = out + ".part"
    proc = subprocess.Popen(["docker", "cp", "%s:%s" % (container, path), "-"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with gzip.open(tmp, "wb") as f_out:
        shutil.copyfileobj(proc.stdout, f_out)
    err = proc.stderr.read().decode(errors="replace").strip()
    if proc.wait() != 0:
        os.remove(tmp)
        raise OSError("docker cp %s:%s failed: %s" % (container, path, err))
    with tarfile.open(tmp, "r:gz") as tar:   # make sure it is readable and holds the config
        names = [m.name for m in tar.getmembers() if m.isfile()]
    if not names or (must_have and not any(os.path.basename(n) == must_have for n in names)):
        os.remove(tmp)
        raise OSError("%s:%s has no %s (not set up yet?)" % (container, path, must_have or "files"))
    finish(tmp, out)


def unbound_source(settings):
    """('native', '/etc/unbound') | ('docker', container) | None"""
    if os.path.isfile("/etc/unbound/unbound.conf"):
        return ("native", "/etc/unbound")
    name = settings.get("UNBOUND_CONTAINER") or "unbound"
    if container_running(name):
        return ("docker", name)
    return None


def adguard_native_conf(settings):
    if settings.get("ADGUARD_CONF"):
        return settings["ADGUARD_CONF"]
    # The systemd unit made by "AdGuardHome -s install" may name the config with -c/--config
    if shutil.which("systemctl"):
        r = run(["systemctl", "show", "-p", "ExecStart", "--value", "AdGuardHome"])
        m = re.search(r"argv\[\]=(.*?)(?: ;|$)", r.stdout.decode(errors="replace"))
        if m:
            argv = shlex.split(m.group(1))
            for i, a in enumerate(argv[:-1]):
                if a in ("-c", "--config"):
                    conf = argv[i + 1]
                    if not os.path.isabs(conf):   # relative to the working dir = binary's dir
                        conf = os.path.join(os.path.dirname(argv[0]), conf)
                    return conf
            if argv:
                cand = os.path.join(os.path.dirname(argv[0]), "AdGuardHome.yaml")
                if os.path.exists(cand):
                    return cand
    for cand in AGH_CANDIDATES:
        if os.path.exists(cand):
            return cand
    return None


def adguard_source(settings):
    conf = adguard_native_conf(settings)
    if conf and os.path.exists(conf):
        return ("native", conf)
    name = settings.get("ADGUARD_CONTAINER") or "adguardhome"
    if container_running(name):
        return ("docker", name)
    return None


def backup_config(args, kind, label, source, docker_path, stamp, must_have=None):
    out = os.path.join(args.dest, "%s-config_%s.tar.gz" % (kind, stamp))
    how, where = source
    print("%s (%s: %s) -> %s" % (label, how, where, out))
    try:
        if how == "native":
            if not os.access(where, os.R_OK):
                raise OSError("%s is not readable - run with sudo" % where)
            tar_paths(out, [where])
        else:
            tar_from_container(out, where, docker_path, must_have)
        print("  Done.")
        prune(args.dest, "%s-config_*.tar.gz" % kind, args.keep)
        return True
    except (OSError, tarfile.TarError) as e:
        print("  !! Failed:", e)
        if os.path.exists(out + ".part"):
            os.remove(out + ".part")
        return False


#--- Daily schedule -------------------------------------------------------------
def timer_command(args):
    cmd = [sys.executable or "/usr/bin/python3", os.path.abspath(__file__),
           "--dest", os.path.abspath(args.dest), "--keep", str(args.keep), "--no-db"]
    if args.only:
        cmd += ["--only", args.only]
    return cmd


def install_timer(args):
    if os.geteuid() != 0:
        raise SystemExit("--install-timer needs root: run it with sudo.")
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", args.at)
    if not m:
        raise SystemExit("--at must be HH:MM (24 h), e.g. 03:00")
    hh, mm = int(m.group(1)), int(m.group(2))
    cmd = " ".join(shlex.quote(c) for c in timer_command(args))
    if os.path.isdir("/run/systemd/system") and shutil.which("systemctl"):
        with open("/etc/systemd/system/%s.service" % UNIT, "w") as f:
            f.write("""[Unit]
Description=Back up Pi-hole / Unbound / AdGuard Home config (managed_pihole backup_dbs.py)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
ExecStart=%s
""" % cmd)
        with open("/etc/systemd/system/%s.timer" % UNIT, "w") as f:
            f.write("""[Unit]
Description=Daily DNS config backup at %02d:%02d (keep %d)

[Timer]
OnCalendar=*-*-* %02d:%02d:00
# Missed (machine off at that time)? Run at the next boot.
Persistent=true

[Install]
WantedBy=timers.target
""" % (hh, mm, args.keep, hh, mm))
        if os.path.exists(CRON_FILE):
            os.remove(CRON_FILE)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "%s.timer" % UNIT], check=True)
        print("Installed systemd timer %s.timer: every day at %02d:%02d, keeps %d of each backup in %s"
              % (UNIT, hh, mm, args.keep, os.path.abspath(args.dest)))
        print("  Next run:   systemctl list-timers %s.timer" % UNIT)
        print("  Run now:    sudo systemctl start %s.service" % UNIT)
        print("  Log:        journalctl -u %s.service" % UNIT)
    elif os.path.isdir("/etc/cron.d"):
        with open(CRON_FILE, "w") as f:
            f.write("# managed_pihole: daily DNS config backup (backup_dbs.py --install-timer)\n"
                    "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                    "%d %d * * * root %s >> /var/log/managed-dns-backup.log 2>&1\n" % (mm, hh, cmd))
        os.chmod(CRON_FILE, 0o644)
        print("Installed %s: every day at %02d:%02d, keeps %d of each backup in %s"
              % (CRON_FILE, hh, mm, args.keep, os.path.abspath(args.dest)))
        print("  Log: /var/log/managed-dns-backup.log")
    else:
        raise SystemExit("No systemd and no /etc/cron.d - add this to root's crontab yourself:\n"
                         "%d %d * * * %s" % (mm, hh, cmd))


def remove_timer():
    if os.geteuid() != 0:
        raise SystemExit("--remove-timer needs root: run it with sudo.")
    if shutil.which("systemctl"):
        run(["systemctl", "disable", "--now", "%s.timer" % UNIT])
    removed = []
    for f in ("/etc/systemd/system/%s.timer" % UNIT, "/etc/systemd/system/%s.service" % UNIT, CRON_FILE):
        if os.path.exists(f):
            os.remove(f)
            removed.append(f)
    if shutil.which("systemctl"):
        run(["systemctl", "daemon-reload"])
    print("Removed: " + (", ".join(removed) if removed else "nothing (no schedule was installed)"))


#--- main -----------------------------------------------------------------------
def main():
    settings = load_settings()
    try:
        keep_default = int(settings.get("BACKUP_KEEP") or 4)
    except ValueError:
        keep_default = 4
    parser = argparse.ArgumentParser(description="Back up Pi-hole v6 / Unbound / AdGuard Home config")
    parser.add_argument("--dest", default=settings.get("BACKUP_DIR") or default_dest(), help="backup folder")
    parser.add_argument("--subdir", default="", help="put the backups in DEST/SUBDIR (own rotation)")
    parser.add_argument("--pihole-dir", default=settings.get("PIHOLE_DIR") or "/etc/pihole",
                        help="host path of Pi-hole's /etc/pihole (docker: your volume)")
    parser.add_argument("--keep", type=int, default=keep_default,
                        help="how many backups of each kind to keep (default %d)" % keep_default)
    parser.add_argument("--only", default="" if (settings.get("BACKUP_SERVICES") or "auto") == "auto"
                        else settings["BACKUP_SERVICES"],
                        help="comma list of pihole,unbound,adguardhome (default: all that are found)")
    parser.add_argument("--no-teleporter", action="store_true", help="skip the Pi-hole Teleporter archive")
    parser.add_argument("--no-db", action="store_true", help="skip the raw Pi-hole sqlite copies")
    parser.add_argument("--install-timer", action="store_true",
                        help="run this backup every day (systemd timer, or cron) and exit")
    parser.add_argument("--at", default=settings.get("BACKUP_TIME") or "03:00",
                        help="time of day for --install-timer, HH:MM (default 03:00)")
    parser.add_argument("--remove-timer", action="store_true", help="remove the daily backup job and exit")
    args = parser.parse_args()

    print("backup_dbs.py  Version:", Version, " Updated:", Updated)
    if args.keep < 1:
        parser.error("--keep must be 1 or more")
    only = [s.strip().lower() for s in args.only.split(",") if s.strip()]
    bad = [s for s in only if s not in SERVICES]
    if bad:
        parser.error("--only: unknown %s (use %s)" % (", ".join(bad), ",".join(SERVICES)))
    args.only = ",".join(only)
    if args.subdir:
        args.dest = os.path.join(args.dest, args.subdir)
    if args.remove_timer:
        return remove_timer()
    if args.install_timer:
        return install_timer(args)

    set_run_timeout(1800)
    os.umask(0o077)
    os.makedirs(args.dest, exist_ok=True)
    try:
        os.chmod(args.dest, 0o700)
    except OSError:   # e.g. a FAT USB stick
        pass
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    wanted = only or list(SERVICES)
    done, failed, missing = [], [], []

    for svc in wanted:
        if svc == "pihole":
            if not pihole_present(settings):
                missing.append("Pi-hole")
                continue
            (done if backup_pihole(args, settings, stamp) else failed).append("Pi-hole")
        elif svc == "unbound":
            src = unbound_source(settings)
            if not src:
                missing.append("Unbound")
                continue
            ok = backup_config(args, "unbound", "Unbound", src, "/etc/unbound", stamp, "unbound.conf")
            (done if ok else failed).append("Unbound")
        elif svc == "adguardhome":
            src = adguard_source(settings)
            if not src:
                missing.append("AdGuard Home")
                continue
            ok = backup_config(args, "adguardhome", "AdGuard Home", src, "/opt/adguardhome/conf", stamp,
                               "AdGuardHome.yaml")
            (done if ok else failed).append("AdGuard Home")

    print()
    if missing:
        print("Not found (skipped):", ", ".join(missing))
    if only and missing:   # asked for it by name, but it is not there
        failed += missing
    if done:
        print("Backed up:", ", ".join(done), "->", args.dest, "(keeping %d of each)" % args.keep)
    if failed:
        print("FAILED:", ", ".join(failed), "(see above)")
    elif not done:
        print("Nothing to back up: no Pi-hole, Unbound or AdGuard Home found.")
        sys.exit(1)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
