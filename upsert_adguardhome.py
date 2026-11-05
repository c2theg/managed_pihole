#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
Version = "1.0.0"
Updated = "11/5/2026"
#  Updated by: Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Applies the managed_pihole lists to AdGuard Home (native install or Docker - the
#  AdGuard Home REST API is the same for both). Python standard library only.
#
#    cgray_blocklists.txt       -> Filters > DNS blocklists     (name "managed_pihole: ...")
#    blocklist_regexs_cg.txt    -> custom rule  /regex/
#    allowlist_regexs_cg.txt    -> custom rule  @@/regex/
#    allow_regex_social_cg.txt  -> custom rule  @@/regex/$client='name'|'name'
#                                  only with --social-clients (AdGuard Home has no
#                                  Pi-hole style groups; rules are tied to clients)
#    pihole_allowlist.sh        -> custom rule  @@|domain^     (exact allow)
#    doh_servers.txt            -> custom rule  ||domain^      (only with --block-doh)
#    pihole_exclude_list.txt    -> "ignored" domains for the query log and statistics
#
#  Custom rules are kept between "! managed_pihole BEGIN/END" markers. Rules you add
#  yourself outside the markers are never touched. Block lists named
#  "managed_pihole: ..." that are no longer in cgray_blocklists.txt are removed.
#
#  Usage:
#    ADGUARD_PASSWORD=xxx ./upsert_adguardhome.py
#    ./upsert_adguardhome.py --url http://192.168.1.2:3000 --user admin --dry-run
#    ./upsert_adguardhome.py --upstream 127.0.0.1:5335     # use local Unbound
#    ./upsert_adguardhome.py --social-clients "kid-laptop|192.168.0.50" --block-doh
#
#  Settings (env vars, or KEY=VALUE in /etc/managed_pihole.conf / ./managed_pihole.conf):
#    ADGUARD_URL             default: auto-detect http://127.0.0.1 ports 80, 3000, 8080
#    ADGUARD_USER            default: admin
#    ADGUARD_PASSWORD        required (the web UI password)
#    ADGUARD_SOCIAL_CLIENTS  same as --social-clients
#    UNBOUND_UPSTREAM        same as --upstream
#
#  ChangeLog:
#    1.0.0  11/5/2026  New file (Claude Code). AdGuard Home support.
#
#  Sources:
#    https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
#    https://adguard-dns.io/kb/general/dns-filtering-syntax/
#-------------------------------------------------------------------------------
import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pihole_api import load_settings, read_list_file  # noqa: E402

TAG = "managed_pihole"
BEGIN = "! ===== %s BEGIN - replaced by upsert_adguardhome.py, edit the repo files instead =====" % TAG
END = "! ===== %s END =====" % TAG
DOMAIN_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$")
DEFAULT_URLS = ["http://127.0.0.1", "http://127.0.0.1:3000", "http://127.0.0.1:8080"]


class AdGuardHome:
    def __init__(self, url, user, password):
        self.user, self.password = user, password
        self.url = (url or self._detect()).rstrip("/")

    def _req(self, method, path, body=None, timeout=60, base=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request((base or self.url) + "/control" + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        token = base64.b64encode(("%s:%s" % (self.user, self.password)).encode()).decode()
        req.add_header("Authorization", "Basic " + token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        try:
            return status, (json.loads(raw) if raw.strip() else None)
        except ValueError:
            return status, raw.decode("utf-8", "replace").strip()

    def _detect(self):
        # Probe without credentials so a wrong password cannot trigger the
        # login lock-out (5 bad attempts = 15 minutes) while we search.
        for base in DEFAULT_URLS:
            try:
                urllib.request.urlopen(base + "/control/status", timeout=3)
                return base
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return base
            except (urllib.error.URLError, OSError):
                continue
        sys.exit("ERROR: AdGuard Home not found on 127.0.0.1 (ports 80/3000/8080). Set ADGUARD_URL.")

    def call(self, method, path, body=None, timeout=60, ok=(200,)):
        status, data = self._req(method, path, body, timeout)
        if status not in ok:
            raise RuntimeError("%s %s -> HTTP %s %s" % (method, path, status, data))
        return data


def allowlist_domains(path):
    """Exact allow domains from pihole_allowlist.sh ('allow a b c' / 'pihole -w a b c' lines)."""
    out, seen = [], set()
    with open(path) as fp:
        for line in fp:
            m = re.match(r"^\s*(?:pihole\s+)?(?:-w|allow)\s+(.*)$", line)
            if not m:
                continue
            for word in m.group(1).split("#")[0].split():
                d = word.lower()
                if DOMAIN_RE.match(d) and d not in seen:
                    seen.add(d)
                    out.append(d)
    return out


def ignored_entry(entry):
    entry = entry.strip().lower()
    return "||%s^" % entry[2:] if entry.startswith("*.") else entry


def list_name(url):
    p = urllib.parse.urlparse(url)
    return ("%s: %s%s" % (TAG, p.netloc, p.path))[:120]


def main():
    s = load_settings()
    ap = argparse.ArgumentParser(description="Apply managed_pihole lists to AdGuard Home")
    ap.add_argument("--url", default=s.get("ADGUARD_URL"))
    ap.add_argument("--user", default=s.get("ADGUARD_USER", "admin"))
    ap.add_argument("--password", default=s.get("ADGUARD_PASSWORD"))
    ap.add_argument("--dir", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--social-clients", default=s.get("ADGUARD_SOCIAL_CLIENTS", ""),
                    help="'|' separated AdGuard Home client names/IPs allowed to use social media")
    ap.add_argument("--block-doh", action="store_true", help="block the DoH servers in doh_servers.txt")
    ap.add_argument("--upstream", default=s.get("UNBOUND_UPSTREAM", ""),
                    help="set upstream DNS, e.g. 127.0.0.1:5335 (Unbound). Space separated for several")
    ap.add_argument("--no-refresh", action="store_true", help="do not refresh (re-download) block lists")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not a.password:
        sys.exit("ERROR: set ADGUARD_PASSWORD (or --password).")
    f = lambda name: os.path.join(a.dir, name)  # noqa: E731

    print("upsert_adguardhome.py  Version:", Version, " Updated:", Updated)
    agh = AdGuardHome(a.url, a.user, a.password)
    status = agh.call("GET", "/status")
    print("Connected to AdGuard Home %s at %s" % (status.get("version"), agh.url))

    # ---------- upstream (e.g. Unbound) - first, lists are downloaded on add ----------
    if a.upstream:
        ups = a.upstream.split()
        print("\nUpstream DNS ->", ups)
        if not a.dry_run:
            agh.call("POST", "/dns_config", {"upstream_dns": ups})
            print("  Saved.")

    # ---------- block lists ----------
    want = read_list_file(f("cgray_blocklists.txt"))
    fs = agh.call("GET", "/filtering/status")
    have = {x["url"]: x for x in (fs.get("filters") or [])}
    add = [u for u in want if u not in have]
    remove = [u for u, x in have.items() if x.get("name", "").startswith(TAG + ":") and u not in want]
    print("\nBlock lists: %d in file, %d new, %d to remove" % (len(want), len(add), len(remove)))
    for u in add:
        if a.dry_run:
            print("  (dry-run) +", u)
            continue
        st, data = agh._req("POST", "/filtering/add_url",
                            {"name": list_name(u), "url": u, "whitelist": False}, timeout=180)
        print("  %s %s%s" % ("+" if st == 200 else "!! FAILED", u, "" if st == 200 else " -> %s" % data))
    for u in remove:
        if a.dry_run:
            print("  (dry-run) -", u)
            continue
        agh.call("POST", "/filtering/remove_url", {"url": u, "whitelist": False})
        print("  -", u)

    # ---------- custom rules ----------
    rules = []
    rules += ["/%s/" % r for r in read_list_file(f("blocklist_regexs_cg.txt"))]
    rules += ["@@/%s/" % r for r in read_list_file(f("allowlist_regexs_cg.txt"))]
    social = [c.strip() for c in a.social_clients.split("|") if c.strip()]
    if social and os.path.exists(f("allow_regex_social_cg.txt")):
        mod = "$client=" + "|".join("'%s'" % c.replace("'", "") for c in social)
        rules += ["@@/%s/%s" % (r, mod) for r in read_list_file(f("allow_regex_social_cg.txt"))]
    elif os.path.exists(f("allow_regex_social_cg.txt")):
        print("\nSocial allow regexes skipped (set --social-clients / ADGUARD_SOCIAL_CLIENTS to use them).")
    if os.path.exists(f("pihole_allowlist.sh")):
        rules += ["@@|%s^" % d for d in allowlist_domains(f("pihole_allowlist.sh"))]
    if a.block_doh and os.path.exists(f("doh_servers.txt")):
        rules += ["||%s^" % d for d in read_list_file(f("doh_servers.txt")) if DOMAIN_RE.match(d.lower())]
        rules.append("||use-application-dns.net^")
    rules = list(dict.fromkeys(rules))

    current = fs.get("user_rules") or []
    if BEGIN in current and END in current:
        b, e = current.index(BEGIN), current.index(END)
        keep = current[:b] + current[e + 1:]
    else:
        keep = current
    new_rules = keep + [BEGIN] + rules + [END]
    print("\nCustom rules: %d managed (%d of your own rules kept)" % (len(rules), len([r for r in keep if r.strip()])))
    if a.dry_run:
        for r in rules[:10]:
            print("  (dry-run)", r)
        print("  ...")
    else:
        agh.call("POST", "/filtering/set_rules", {"rules": new_rules})
        print("  Saved.")

    # ---------- ignored domains (query log + statistics) ----------
    if os.path.exists(f("pihole_exclude_list.txt")):
        ignored = list(dict.fromkeys(ignored_entry(x) for x in read_list_file(f("pihole_exclude_list.txt"))))
        print("\nIgnored domains (query log + stats): %d" % len(ignored))
        if not a.dry_run:
            for get_path, put_path in (("/querylog/config", "/querylog/config/update"),
                                       ("/stats/config", "/stats/config/update")):
                cfg = agh.call("GET", get_path)
                cfg.update({"ignored": ignored, "ignored_enabled": True})
                agh.call("PUT", put_path, cfg)
            print("  Saved.")

    # ---------- refresh ----------
    if not (a.dry_run or a.no_refresh):
        print("\nRefreshing block lists (can take a few minutes)...")
        data = agh.call("POST", "/filtering/refresh", {"whitelist": False}, timeout=900)
        print("  Updated lists:", (data or {}).get("updated", data))
    print("\nDONE!")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.exit("ERROR: %s" % e)
