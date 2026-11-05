#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
Version = "1.0.0"
Updated = "11/5/2026"
#  Updated by: Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Adds ("upserts") this repo's lists into Pi-hole v6 - native OS install OR Docker.
#
#    cgray_blocklists.txt       -> Subscribed block lists       (Lists page)
#    blocklist_regexs_cg.txt    -> Regex DENY domains            (Default group)
#    allowlist_regexs_cg.txt    -> Regex ALLOW domains           (Default group)
#    allow_regex_social_cg.txt  -> Regex ALLOW domains, group "Allow_Social" ONLY
#                                  (assign the clients that may use social media to it)
#    pihole_exclude_list.txt    -> webserver.api.excludeDomains  (hidden from top lists /
#                                  query log; was API_EXCLUDE_DOMAINS in setupVars.conf)
#  then runs gravity.
#
#  Usage:
#    sudo ./upsert_lists.py                  # native install, uses /etc/pihole/cli_pw
#    ./upsert_lists.py                       # docker: reads cli_pw via `docker exec`
#    PIHOLE_API_URL=http://10.0.0.5:8080/api PIHOLE_PASSWORD=xxx ./upsert_lists.py
#    ./upsert_lists.py --dry-run             # show what would be sent, change nothing
#    ./upsert_lists.py --no-gravity          # skip the gravity update at the end
#    ./upsert_lists.py --no-prune            # never remove lists
#
#  ChangeLog:
#    1.0.0  11/5/2026  (Claude Code) Rewritten for Pi-hole v6:
#             - Uses the v6 REST API (pihole_api.py) instead of writing gravity.db with
#               sqlite3, so it works for Docker too and no longer stops pihole-FTL.
#             - FIX: regex allow entries were inserted with the type/enabled values
#               swapped (type=0 "exact allow", enabled=2), so they never worked as regex.
#               They are now real regex allow entries.
#             - FIX: allow_regex_social_cg.txt was applied to everyone; it now goes only
#               to the "Allow_Social" group, as that file's header says it should.
#             - FIX: `except Error` (NameError) and `quit` (no-op) on db connect failure.
#             - NEW: exclude-domain handling moved here from update_lists.sh. v6 wants
#               regexes, so "*.example.com" -> "(^|\.)example\.com$" and
#               "example.com" -> "^example\.com$". Saved via the API, or with
#               "pihole-FTL --config" when the session may not change config
#               (sessions made from the CLI password are not allowed to).
#             - Removed: "pihole -up" (update_lists.sh does it), log deletion (moved to
#               cleanup.sh), "pihole restartdns reload-lists" (gone in v6; gravity
#               reloads lists itself), "pihole -v -c" ("-c" is chronometer in v6).
#             - NEW: --dry-run, --no-gravity, --skip-exclude, --dir options.
#             - NEW: re-runs only send new entries. Block lists this tool added
#               (comment "managed_pihole...") that were removed from
#               cgray_blocklists.txt are deleted (turn off with --no-prune).
#               Your own lists are never touched.
#    0.0.43 12/26/2020 Last Pi-hole v5 version.
#
#  Sources:
#     https://docs.pi-hole.net/api/
#     https://docs.pi-hole.net/database/domain-database/
#     https://docs.pi-hole.net/ftldns/configfile/   (webserver.api.excludeDomains)
#-------------------------------------------------------------------------------
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pihole_api import PiholeAPI, PiholeAPIError, read_list_file  # noqa: E402

COMMENT = "managed_pihole (cg importer) v" + Version
SOCIAL_GROUP = "Allow_Social"

# file name, API path, groups ("default" or SOCIAL_GROUP), label
DOMAIN_FILES = [
    ("blocklist_regexs_cg.txt", "/domains/deny/regex", "default", "Regex deny"),
    ("allowlist_regexs_cg.txt", "/domains/allow/regex", "default", "Regex allow"),
    ("allow_regex_social_cg.txt", "/domains/allow/regex", SOCIAL_GROUP, "Regex allow (social)"),
]


def set_run_timeout(seconds):
    def alarm(*_):
        raise SystemExit("Timed out!")
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(seconds)


def report(label, status, data, skipped=0):
    """Print how many items were added / already present / failed."""
    processed = (data or {}).get("processed") or {}
    added = processed.get("success") or []
    errors = processed.get("errors") or []
    if not processed and status >= 400:
        print("  !! %s: HTTP %s %s" % (label, status, (data or {}).get("error", data)))
        return
    print("  %s: %d added, %d already present, %d failed" % (label, len(added), skipped, len(errors)))
    for e in errors:
        print("     FAILED: %s -> %s" % (e.get("item"), e.get("error")))


def existing_items(api, path, collection, key, params=None, full=False):
    status, data = api.request("GET", path, params=params)
    if status >= 400:
        raise PiholeAPIError("GET %s failed: HTTP %s %s" % (path, status, (data or {}).get("error", data)))
    rows = (data or {}).get(collection, [])
    return rows if full else {x.get(key) for x in rows}


def exclude_to_regex(entry):
    """Convert a v5-style exclude entry to the regex Pi-hole v6 expects."""
    entry = entry.strip().lower()
    if entry.startswith("*."):
        return r"(^|\.)" + entry[2:].replace(".", r"\.") + "$"
    return "^" + entry.replace(".", r"\.") + "$"


def set_config_with_ftl(settings, key, value):
    """Fallback for config changes: run `pihole-FTL --config <key> <json>` natively or in docker."""
    mode = settings.get("PIHOLE_MODE", "auto")
    if mode == "auto":
        mode = "native" if shutil.which("pihole-FTL") else ("docker" if shutil.which("docker") else "")
    cmd = ["pihole-FTL", "--config", key, json.dumps(value)]
    if mode == "docker":
        cmd = ["docker", "exec", settings.get("PIHOLE_CONTAINER", "pihole")] + cmd
    elif mode == "native":
        if os.geteuid() != 0 and shutil.which("sudo"):
            cmd = ["sudo", "-n"] + cmd
    else:
        return False
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        print("  pihole-FTL --config failed:", e)
        return False
    if out.returncode != 0:
        print("  pihole-FTL --config failed:", (out.stderr or out.stdout).strip()[:300])
    return out.returncode == 0


def group_id(api, name, dry_run):
    status, data = api.request("GET", "/groups")
    for g in (data or {}).get("groups", []):
        if g.get("name") == name:
            return g.get("id")
    if dry_run:
        print("  (dry-run) would create group", name)
        return None
    print("  Creating group '%s' (assign clients to it in the web UI: Group Management > Clients)" % name)
    api.request("POST", "/groups", {"name": name, "enabled": True,
                                    "comment": "managed_pihole: clients allowed to use social media"})
    status, data = api.request("GET", "/groups")
    for g in (data or {}).get("groups", []):
        if g.get("name") == name:
            return g.get("id")
    raise PiholeAPIError("Could not create group %s" % name)


def main():
    parser = argparse.ArgumentParser(description="Upsert managed_pihole lists into Pi-hole v6")
    parser.add_argument("--dir", default=os.path.dirname(os.path.abspath(__file__)),
                        help="folder that holds the list files (default: this script's folder)")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    parser.add_argument("--no-gravity", action="store_true", help="do not run gravity at the end")
    parser.add_argument("--skip-exclude", action="store_true", help="do not touch webserver.api.excludeDomains")
    parser.add_argument("--no-prune", action="store_true",
                        help="keep block lists this tool added earlier that are no longer in the file")
    args = parser.parse_args()

    print("upsert_lists.py  Version:", Version, " Updated:", Updated)
    set_run_timeout(3600)

    def path(name):
        return os.path.join(args.dir, name)

    try:
        with PiholeAPI() as api:
            # ---- Subscribed block lists ----
            lists = read_list_file(path("cgray_blocklists.txt"))
            print("\nBlock lists (%d in cgray_blocklists.txt)" % len(lists))
            rows = existing_items(api, "/lists", "lists", "address", params={"type": "block"}, full=True)
            have = {r.get("address") for r in rows}
            new_lists = [u for u in lists if u not in have]
            # Lists this tool added earlier (comment "managed_pihole...") that are no longer in the file
            stale = [r["address"] for r in rows if str(r.get("comment") or "").startswith("managed_pihole")
                     and r.get("address") not in lists]
            for u in ([] if args.no_prune else stale):
                if args.dry_run:
                    print("  (dry-run) would remove", u)
                    continue
                st, _ = api.request("DELETE", "/lists/" + urllib.parse.quote(u, safe=""), params={"type": "block"})
                print("  %s removed (no longer in cgray_blocklists.txt): %s" % ("-" if st < 300 else "!! NOT", u))
            if args.dry_run:
                print("  (dry-run) %d new, %d already present" % (len(new_lists), len(lists) - len(new_lists)))
                for u in new_lists:
                    print("     +", u)
            elif not new_lists:
                print("  Block lists: 0 added, %d already present" % len(lists))
            else:
                status, data = api.request("POST", "/lists",
                                           {"address": new_lists, "comment": COMMENT,
                                            "groups": [0], "enabled": True},
                                           params={"type": "block"}, timeout=120)
                report("Block lists", status, data, skipped=len(lists) - len(new_lists))

            # ---- Regex domains ----
            for fname, api_path, group, label in DOMAIN_FILES:
                if not os.path.exists(path(fname)):
                    print("\n%s: %s not found, skipping" % (label, fname))
                    continue
                entries = read_list_file(path(fname))
                print("\n%s (%d in %s)" % (label, len(entries), fname))
                groups = [0] if group == "default" else [group_id(api, group, args.dry_run)]
                have = existing_items(api, api_path, "domains", "domain")
                new_entries = [e for e in entries if e not in have]
                if args.dry_run:
                    print("  (dry-run) %d new, %d already present; would POST %s groups=%s"
                          % (len(new_entries), len(entries) - len(new_entries), api_path, groups))
                    for e in new_entries:
                        print("     +", e)
                    continue
                if not new_entries:
                    print("  %s: 0 added, %d already present" % (label, len(entries)))
                    continue
                status, data = api.request("POST", api_path,
                                           {"domain": new_entries, "comment": COMMENT,
                                            "groups": groups, "enabled": True}, timeout=120)
                report(label, status, data, skipped=len(entries) - len(new_entries))

            # ---- Excluded domains (top lists / query log) ----
            if not args.skip_exclude and os.path.exists(path("pihole_exclude_list.txt")):
                regexes = []
                for e in read_list_file(path("pihole_exclude_list.txt")):
                    r = exclude_to_regex(e)
                    if r not in regexes:
                        regexes.append(r)
                print("\nExcluded domains: %d -> webserver.api.excludeDomains" % len(regexes))
                if args.dry_run:
                    print("  (dry-run) first few:", regexes[:5])
                else:
                    status, data = api.request(
                        "PATCH", "/config",
                        {"config": {"webserver": {"api": {"excludeDomains": regexes}}}})
                    if status < 300:
                        print("  Saved (API).")
                    elif set_config_with_ftl(api.settings, "webserver.api.excludeDomains", regexes):
                        # CLI-password sessions may not change config through the API
                        print("  Saved (pihole-FTL --config).")
                    else:
                        print("  !! Could not save (HTTP %s): %s" % (status, (data or {}).get("error", data)))
                        print("  Fix: set PIHOLE_PASSWORD to your web password, or run as root.")
                        print("  If you run Docker and set FTLCONF_webserver_api_excludeDomains in your")
                        print("  compose file, that setting is read-only. Either remove it, or put this")
                        print("  value in the compose file instead (';' separated):")
                        print("    FTLCONF_webserver_api_excludeDomains: '" + ";".join(regexes) + "'")

            # ---- Gravity ----
            if args.dry_run or args.no_gravity:
                print("\nSkipping gravity update.")
            else:
                print("\nUpdating gravity (this can take a few minutes)...\n")
                api.stream("POST", "/action/gravity")
    except PiholeAPIError as e:
        print("\nERROR:", e)
        sys.exit(1)

    print("\nDONE!")


if __name__ == "__main__":
    main()
