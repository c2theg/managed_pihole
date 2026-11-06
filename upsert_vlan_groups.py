#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
#
#  upsert_vlan_groups.py  -  one Pi-hole v6 group per VLAN, each with its own lists
#
#  Version:       1.2.0
#  Last Updated:  11/6/2026
#  Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  For every VLAN "Name=subnet[@profile]":
#    - group "Name"                     (created if missing)
#    - client "subnet" -> Default + Name (every device in that VLAN)
#    - extra entries for that group only, from these files (all optional, lower-case name):
#        group_<name>_blocklists.txt     block-list URLs      (subscribed lists)
#        group_<name>_regex_deny.txt     regex deny
#        group_<name>_deny.txt           exact deny
#        group_<name>_allow.txt          exact allow          (unblock for this VLAN only)
#        group_<name>_regex_allow.txt    regex allow
#      plus your own additions in the same names ending in .local.txt
#      (never downloaded or overwritten).
#    - "@profile" (optional) also loads group_<profile>_*.txt, so several VLANs can share
#      a list set: "Cams=10.0.9.0/24@iot". Shipped profiles: iot, kids, guest.
#      "@none" = only group_<name>_*.txt. No @ = profile with the VLAN's own name.
#    - a VLAN can have several subnets: repeat it ("IoT=172.16.12.0/23@iot,IoT=fd13:1::/64@iot")
#    - --v6-from "IoT=vlan666,Users=ens18": also the IPv6 prefixes those interfaces have right
#      now (from router advertisements), so IPv6 devices land in their VLAN's group too.
#      Prefixes that went away (e.g. a new ISP prefix) are removed on the next run.
#  Default-group lists (cgray_blocklists.txt etc.) still apply to every VLAN; the group
#  files ADD to them. So "IoT blocks a lot more than Users" = group_iot_*.txt.
#
#  Idempotent: re-runs change only what differs. Entries it created carry the comment
#  "managed_pihole vlan" and are pruned when removed from the files. A list that is
#  already subscribed in Default is left alone (it already applies to that VLAN).
#  Runs gravity only when block lists were added.
#
#  Usage:
#    ./upsert_vlan_groups.py --vlans "Users=192.168.1.0/24,IoT=172.16.12.0/23,Kids=192.168.5.0/24@kids"
#    ./upsert_vlan_groups.py --vlans ... --fetch https://raw.githubusercontent.com/c2theg/managed_pihole/main
#    ./upsert_vlan_groups.py --vlans ... --v6-from "IoT=vlan666,Kids=vlan2"
#    ./upsert_vlan_groups.py --vlans ... --dry-run
#  Settings: PIHOLE_API_URL / PIHOLE_PASSWORD (see pihole_api.py). Needs the web
#  (admin) password: app passwords cannot change groups' lists.
#
#  ChangeLog:
#    1.2.0  11/6/2026  IPv6: several subnets per VLAN, --v6-from IFACE prefixes. (Claude Code)
#    1.1.0  11/5/2026  "@profile" per VLAN (shared list sets: iot, kids, guest); the name
#                      "Default" is refused (it is Pi-hole's built-in group). (Claude Code)
#    1.0.0  11/5/2026  New file (Claude Code). Used by deploy_multi_pi.sh.
#-------------------------------------------------------------------------------
import argparse
import ipaddress
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pihole_api import PiholeAPI, PiholeAPIError, read_list_file  # noqa: E402

__version__ = "1.2.0"
TAG = "managed_pihole vlan"
KINDS = [  # file suffix, API collection path, label
    ("blocklists", "/lists?type=block", "block lists"),
    ("regex_deny", "/domains/deny/regex", "regex deny"),
    ("deny", "/domains/deny/exact", "exact deny"),
    ("allow", "/domains/allow/exact", "exact allow"),
    ("regex_allow", "/domains/allow/regex", "regex allow"),
]


def parse_vlans(raw):
    """-> [(name, cidr, [file prefixes])]"""
    out = []
    for item in raw.replace(";", ",").split(","):
        if not item.strip():
            continue
        if "=" not in item:
            sys.exit("--vlans: expected Name=subnet[@profile], got %r" % item)
        name, rest = (x.strip() for x in item.split("=", 1))
        cidr, _, profile = rest.partition("@")
        if not name or any(c in name for c in " ,;=/@"):
            sys.exit("--vlans: bad group name %r" % name)
        if name.lower() == "default":
            sys.exit("--vlans: 'Default' is Pi-hole's built-in group (every client is in it); use another name")
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            sys.exit("--vlans: bad subnet %r" % cidr)
        profile = profile.strip().lower()
        if profile and not all(c.isalnum() or c in "_-" for c in profile):
            sys.exit("--vlans: bad profile %r" % profile)
        prefixes = [] if profile == "none" else [profile or name.lower()]
        if name.lower() not in prefixes:
            prefixes.append(name.lower())
        out.append((name, str(net), prefixes))
    return out


def v6_prefixes(iface):
    """Global IPv6 prefixes (ULA and GUA) on IFACE right now, e.g. ['fd13:26eb:b133:56dc::/64']."""
    try:
        out = subprocess.run(["ip", "-j", "-6", "addr", "show", "dev", iface, "scope", "global"],
                             capture_output=True, text=True, timeout=10).stdout
        data = json.loads(out or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    nets = []
    for a in data:
        for i in a.get("addr_info", []):
            if i.get("family") != "inet6" or i.get("deprecated") or i.get("tentative"):
                continue
            n = str(ipaddress.ip_network("%s/%s" % (i["local"], i.get("prefixlen", 64)), strict=False))
            if n not in nets:
                nets.append(n)
    return nets


def group_vlans(vlans, v6_from):
    """-> {name: ([cidrs], [file prefixes])} in order; adds the IPv6 prefixes of --v6-from."""
    out = {}
    for name, cidr, prefixes in vlans:
        key = next((k for k in out if k.lower() == name.lower()), name)
        cidrs, pf = out.setdefault(key, ([], prefixes))
        if cidr not in cidrs:
            cidrs.append(cidr)
    for item in (v6_from or "").replace(";", ",").split(","):
        if "=" not in item:
            continue
        name, iface = (x.strip() for x in item.split("=", 1))
        key = next((k for k in out if k.lower() == name.lower()), None)
        if key is None:
            sys.exit("--v6-from: %r is not in --vlans" % name)
        found = v6_prefixes(iface)
        print("  IPv6 on %-10s for %-12s %s" % (iface, key, ", ".join(found) or "none (no router advertisement yet?)"))
        for n in found:
            if n not in out[key][0]:
                out[key][0].append(n)
    return out


def fetch(base, dirpath, fname):
    url = base.rstrip("/") + "/" + fname
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "absent"
        return "failed (HTTP %s)" % e.code
    except (urllib.error.URLError, OSError) as e:
        return "failed (%s)" % e
    tmp = os.path.join(dirpath, fname + ".tmp")
    with open(tmp, "wb") as fp:
        fp.write(data.replace(b"\r", b""))
    os.replace(tmp, os.path.join(dirpath, fname))
    return "ok"


def wanted_entries(dirpath, prefixes, suffix):
    out = []
    for prefix in prefixes:
        base = "group_%s_%s" % (prefix, suffix)
        for f in (base + ".txt", base + ".local.txt"):
            p = os.path.join(dirpath, f)
            if os.path.exists(p):
                for e in read_list_file(p):
                    e = e.split()[0] if suffix == "blocklists" else e
                    if e not in out:
                        out.append(e)
    return out


class Sync:
    def __init__(self, api, dry):
        self.api, self.dry = api, dry
        self.changes = 0
        self.lists_added = 0

    def call(self, method, path, body=None, params=None, ok=(200, 201, 204)):
        if self.dry and method != "GET":
            print("    (dry-run) %s %s %s" % (method, path, "" if body is None else str(body)[:160]))
            return {}
        status, data = self.api.request(method, path, body, params=params, timeout=120)
        if status not in ok:
            raise PiholeAPIError("%s %s -> HTTP %s: %s" % (method, path, status, (data or {}).get("error", data)))
        errors = ((data or {}).get("processed") or {}).get("errors") or []
        if errors:
            print("    !! %s %s: %s" % (method, path, errors[:3]))
        if method != "GET":
            self.changes += 1
        return data or {}

    # ---- groups / clients ----
    def groups(self):
        return {g["name"]: g for g in self.call("GET", "/groups").get("groups", [])}

    def ensure_group(self, name, cidr):
        g = self.groups().get(name)
        comment = "%s: VLAN %s (%s)" % (TAG, name, cidr)
        if not g:
            print("  + group %s" % name)
            self.call("POST", "/groups", {"name": name, "comment": comment, "enabled": True})
            g = self.groups().get(name) or {"id": None}
        elif not g.get("enabled"):
            print("  ~ group %s was disabled, enabling" % name)
            self.call("PUT", "/groups/" + urllib.parse.quote(name, safe=""),
                      {"name": name, "comment": g.get("comment") or comment, "enabled": True})
        return g.get("id")

    def ensure_client(self, cidr, gid, name):
        clients = {c["client"]: c for c in self.call("GET", "/clients").get("clients", [])}
        want = sorted({0, gid}) if gid is not None else [0]
        c = clients.get(cidr)
        comment = "%s: %s" % (TAG, name)
        if not c:
            print("  + client %s -> Default + %s" % (cidr, name))
            self.call("POST", "/clients", {"client": cidr, "comment": comment, "groups": want})
        elif not set(want) <= set(c.get("groups") or []):
            groups = sorted(set(c.get("groups") or []) | set(want))
            print("  ~ client %s groups %s -> %s" % (cidr, c.get("groups"), groups))
            self.call("PUT", "/clients/" + urllib.parse.quote(cidr, safe=""),
                      {"comment": c.get("comment") or comment, "groups": groups})
        return clients

    # ---- lists / domains ----
    def sync_kind(self, path, label, want_by_gid, our_gids):
        """want_by_gid: {gid: [entries]} for one kind. Adds / re-groups / prunes our entries."""
        key = "address" if path.startswith("/lists") else "domain"
        coll = "lists" if key == "address" else "domains"
        base, _, query = path.partition("?")
        params = dict(urllib.parse.parse_qsl(query))
        rows = {r[key]: r for r in self.call("GET", base, params=params).get(coll, [])}
        desired = {}
        for gid, entries in want_by_gid.items():
            for e in entries:
                desired.setdefault(e, set()).add(gid)
        added = 0
        for entry, gids in desired.items():
            r = rows.get(entry)
            if r is None:
                print("  + %s [%s] %s" % (label, ",".join(str(g) for g in sorted(gids)), entry))
                self.call("POST", base, {key: entry, "comment": TAG, "groups": sorted(gids), "enabled": True},
                          params=params)
                added += 1
                continue
            mine = str(r.get("comment") or "").startswith(TAG)
            if not mine and 0 in (r.get("groups") or []) and r.get("enabled"):
                continue  # already applies to everyone via Default
            current = set(r.get("groups") or [])
            new = (current - our_gids) | gids if mine else current | gids
            if new != current or not r.get("enabled"):
                print("  ~ %s groups %s -> %s: %s" % (label, sorted(current), sorted(new), entry))
                self.call("PUT", base + "/" + urllib.parse.quote(entry, safe=""),
                          {"comment": r.get("comment") or TAG, "groups": sorted(new), "enabled": True},
                          params=params)
        for entry, r in rows.items():  # prune ours that no group wants any more
            if entry in desired or not str(r.get("comment") or "").startswith(TAG):
                continue
            rest = set(r.get("groups") or []) - our_gids
            if rest:
                print("  ~ %s no longer wanted by VLAN groups, keeping groups %s: %s" % (label, sorted(rest), entry))
                self.call("PUT", base + "/" + urllib.parse.quote(entry, safe=""),
                          {"comment": r.get("comment"), "groups": sorted(rest), "enabled": r.get("enabled", True)},
                          params=params)
            else:
                print("  - %s %s" % (label, entry))
                self.call("DELETE", base + "/" + urllib.parse.quote(entry, safe=""), params=params)
        return added


def main():
    ap = argparse.ArgumentParser(description="One Pi-hole v6 group per VLAN, each with its own lists")
    ap.add_argument("--vlans", required=True, help='"Users=192.168.1.0/24,IoT=172.16.12.0/23@iot"')
    ap.add_argument("--dir", default=os.path.dirname(os.path.abspath(__file__)), help="folder with group_*.txt")
    ap.add_argument("--fetch", metavar="BASE_URL", help="download group_<name>_*.txt from this repo URL first")
    ap.add_argument("--v6-from", metavar="NAME=IFACE,...",
                    help="add the IPv6 prefixes these interfaces have now to the VLAN groups")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--gravity", choices=["auto", "always", "never"], default="auto")
    args = ap.parse_args()
    vlans = parse_vlans(args.vlans)
    if args.v6_from:
        print("IPv6 prefixes")
    groups = group_vlans(vlans, args.v6_from)
    if args.fetch:
        print("Downloading group files from %s" % args.fetch)
        for prefix in sorted({p for _, _, ps in vlans for p in ps}):
            for suffix, _, _ in KINDS:
                fname = "group_%s_%s.txt" % (prefix, suffix)
                st = fetch(args.fetch, args.dir, fname)
                if st != "absent":
                    print("  %-40s %s" % (fname, st))
    try:
        with PiholeAPI(verbose=True) as api:
            s = Sync(api, args.dry_run)
            gids = {}
            print("\nGroups and VLAN subnets")
            for name, (cidrs, prefixes) in groups.items():
                print("  %s %s  (lists: %s)" % (name, " ".join(cidrs), ", ".join("group_%s_*" % p for p in prefixes)))
                gids[name] = s.ensure_group(name, cidrs[0])
                for cidr in cidrs:
                    s.ensure_client(cidr, gids[name], name)
            # subnet clients this tool created that are no longer a VLAN (subnet changed / VLAN removed)
            wanted = {c for cidrs, _ in groups.values() for c in cidrs}
            for c in s.call("GET", "/clients").get("clients", []):
                if str(c.get("comment") or "").startswith(TAG) and c.get("client") not in wanted:
                    print("  - client %s (no longer a VLAN subnet)" % c["client"])
                    s.call("DELETE", "/clients/" + urllib.parse.quote(c["client"], safe=""))
            # every group this tool manages (also VLANs removed from --vlans, so their entries get pruned)
            our_gids = {g["id"] for g in s.groups().values() if str(g.get("comment") or "").startswith(TAG)}
            our_gids |= {g for g in gids.values() if g is not None}
            for suffix, path, label in KINDS:
                want = {gids[n]: wanted_entries(args.dir, ps, suffix) for n, (_, ps) in groups.items()
                        if gids[n] is not None}
                total = sum(len(v) for v in want.values())
                print("\n%s: %s" % (label.capitalize(), ", ".join("%s %d" % (n, len(want.get(gids[n], [])))
                                                                 for n in groups) or "none"))
                added = s.sync_kind(path, label, want, our_gids)
                if suffix == "blocklists":
                    s.lists_added = added
                if not total and not added:
                    continue
            print("\n%d change(s)." % s.changes)
            run = args.gravity == "always" or (args.gravity == "auto" and s.lists_added)
            if args.dry_run or not run:
                print("Gravity: %s" % ("skipped (dry-run)" if args.dry_run else "not needed"))
            else:
                print("Gravity: downloading %d new list(s) ..." % s.lists_added)
                api.stream("POST", "/action/gravity")
    except PiholeAPIError as e:
        sys.exit("ERROR: %s" % e)


if __name__ == "__main__":
    main()
