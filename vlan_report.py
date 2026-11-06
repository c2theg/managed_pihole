#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
#
#  vlan_report.py  -  per-VLAN DNS activity and "bad traffic" detection (Pi-hole v6)
#
#  Version:       1.0.1
#  Last Updated:  11/5/2026
#  Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Answers "what is going on on each VLAN, and is a device misbehaving?":
#    - queries / blocked / % blocked per VLAN and per client
#    - per client: query rate, NXDOMAIN rate (malware DGA / beaconing / broken devices),
#      top domains, top blocked domains, hits on THREAT lists (malware, phishing, C2 ...),
#      DNS-bypass attempts (DoH / VPN / proxy lists), Pi-hole rate-limit events
#    - alerts when a client crosses a threshold, optionally sent to a webhook
#      (ntfy, Slack, Discord or any URL that accepts a POST)
#
#  VLANs come from Pi-hole itself: every client entry that is a subnet (e.g.
#  192.168.66.0/24) in a group is one VLAN, named after its group (deploy_multi_pi.sh
#  creates these). Or set MCP_VLANS="Users=192.168.1.0/24,IoT=192.168.66.0/24".
#  Without either, clients are grouped by /24.
#
#  Usage:
#    ./vlan_report.py                       # last 24 h, table
#    ./vlan_report.py --hours 1 --json
#    ./vlan_report.py --client 192.168.66.23 --hours 6
#    ./vlan_report.py --hours 1 --alert     # print alerts + send to ALERT_WEBHOOK (hourly timer)
#  Also used by mcp_server.py (tools pihole_vlan_report / pihole_client_report).
#
#  Settings (env, or KEY=VALUE in /etc/managed_pihole.conf, ./managed_pihole.conf,
#  ./managed_pihole.local.conf):
#    PIHOLE_API_URL / PIHOLE_PASSWORD     see pihole_api.py
#    MCP_VLANS                 optional VLAN map (see above)
#    ALERT_MIN_QUERIES   50    ignore % based checks below this many queries
#    ALERT_BLOCKED_PCT   40    a client with more blocked queries than this (%)
#    ALERT_NXDOMAIN_PCT  25    ... more NXDOMAIN replies than this (%)
#    ALERT_QUERIES_PER_HOUR 1500
#    ALERT_THREAT_HITS   1     ... this many queries blocked by a threat list
#    ALERT_BYPASS_HITS   5     ... this many DoH/VPN/proxy-bypass attempts
#    Any threshold can be set per VLAN: ALERT_BLOCKED_PCT_IOT=60, ALERT_QUERIES_PER_HOUR_USERS=5000
#    ALERT_VLANS               only alert for these VLANs (comma list; default: all)
#    ALERT_WEBHOOK             URL to POST alerts to (ntfy topic URL, Slack/Discord webhook ...)
#    ALERT_REPEAT_HOURS  6     do not repeat the same alert sooner than this
#    ALERT_STATE_FILE          default ~/.cache/managed_pihole_vlan_alerts.json
#    THREAT_LIST_KEYWORDS      list URL words that mark a THREAT list
#    BYPASS_LIST_KEYWORDS      list URL words that mark a DNS-bypass list
#
#  ChangeLog:
#    1.0.1  11/6/2026  VLAN name = the VLAN group even when the subnet is also in another
#                      group (e.g. Allow_Social); IPv6 prefixes count as the VLAN too. (Claude Code)
#    1.0.0  11/5/2026  New file (Claude Code).
#-------------------------------------------------------------------------------
import argparse
import collections
import ipaddress
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pihole_api import PiholeAPI, PiholeAPIError, load_settings  # noqa: E402

__version__ = "1.0.1"

BLOCKED = {"GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
           "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "EXTERNAL_BLOCKED_EDE15"}
DEFAULT_THREAT_WORDS = ("tif", "malware", "phishing", "threat", "scam", "ransom", "urlhaus", "abuse.ch",
                        "crypto", "fake", "dga", "botnet", "spam", "stalkerware", "hacked")
DEFAULT_BYPASS_WORDS = ("doh", "vpn", "proxy", "bypass", "tor")
THRESHOLDS = {"ALERT_MIN_QUERIES": 50, "ALERT_BLOCKED_PCT": 40, "ALERT_NXDOMAIN_PCT": 25,
              "ALERT_QUERIES_PER_HOUR": 1500, "ALERT_THREAT_HITS": 1, "ALERT_BYPASS_HITS": 5}


class ReportError(Exception):
    pass


def pct(part, whole):
    return round(100.0 * part / whole, 1) if whole else 0.0


def words(settings, key, default):
    raw = settings.get(key)
    return tuple(w.strip().lower() for w in raw.split(",") if w.strip()) if raw else default


# ---------------------------------------------------------------------------
# VLAN map
# ---------------------------------------------------------------------------
def parse_vlan_map(raw):
    """'Users=192.168.1.0/24,IoT=192.168.66.0/24' -> [(name, network), ...]"""
    out = []
    for item in (raw or "").replace(";", ",").split(","):
        if "=" not in item:
            continue
        name, cidr = item.split("=", 1)
        try:
            out.append((name.strip(), ipaddress.ip_network(cidr.split("@")[0].strip(), strict=False)))
        except ValueError:
            raise ReportError("MCP_VLANS: bad subnet %r" % cidr)
    return out


def vlans_from_pihole(get):
    """Subnet clients in a (non-Default) group = VLANs, named after the group."""
    rows = (get("/groups") or {}).get("groups", [])
    groups = {g["id"]: g["name"] for g in rows}
    # groups made by upsert_vlan_groups.py come first (a subnet can also be in e.g. Allow_Social)
    vlan_gids = {g["id"] for g in rows if str(g.get("comment") or "").startswith("managed_pihole vlan")}
    out = []
    for c in (get("/clients") or {}).get("clients", []):
        try:
            net = ipaddress.ip_network(c.get("client", ""), strict=False)
        except ValueError:
            continue
        if net.num_addresses <= 1:
            continue
        gids = sorted(c.get("groups", []), key=lambda g: g not in vlan_gids)
        names = [groups.get(g) for g in gids if g != 0 and groups.get(g)]
        out.append((names[0] if names else str(net), net))
    return out


def vlan_of(ip, vlans):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Other"
    best = None
    for name, net in vlans:  # most specific subnet wins
        if addr.version == net.version and addr in net and (best is None or net.prefixlen > best[1].prefixlen):
            best = (name, net)
    if best:
        return best[0]
    if not vlans:
        return str(ipaddress.ip_network("%s/%d" % (ip, 24 if addr.version == 4 else 64), strict=False))
    return "Other"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
class Reporter:
    def __init__(self, get, settings):
        self.get = get  # get(path, params=None) -> parsed JSON (raises on HTTP errors)
        self.s = settings
        self.threat_words = words(settings, "THREAT_LIST_KEYWORDS", DEFAULT_THREAT_WORDS)
        self.bypass_words = words(settings, "BYPASS_LIST_KEYWORDS", DEFAULT_BYPASS_WORDS)
        self._why = {}

    def threshold(self, key, vlan):
        for k in ("%s_%s" % (key, re.sub(r"\W", "_", vlan).upper()), key):
            if self.s.get(k) not in (None, ""):
                try:
                    return float(self.s[k])
                except ValueError:
                    pass
        return float(THRESHOLDS[key])

    def vlans(self):
        if self.s.get("MCP_VLANS"):
            return parse_vlan_map(self.s["MCP_VLANS"])
        try:
            return vlans_from_pihole(self.get)
        except Exception:
            return []

    def classify(self, domain):
        """Why is this domain blocked? -> (category, [list names])  category: threat|bypass|ads"""
        if domain in self._why:
            return self._why[domain]
        cat, names = "ads", []
        try:
            data = (self.get("/search/" + urllib.parse.quote(domain, safe=""),
                             {"partial": "false", "N": 20}) or {}).get("search", {})
            for g in data.get("gravity", []):
                if g.get("type") == "block":
                    names.append(g.get("address", ""))
            for d in data.get("domains", []):
                if d.get("type") == "deny":
                    names.append("%s %s: %s" % (d.get("kind"), d.get("type"), d.get("comment") or d.get("domain")))
        except Exception:
            pass
        low = " ".join(names).lower()
        if any(w in low for w in self.threat_words):
            cat = "threat"
        elif any(w in low for w in self.bypass_words):
            cat = "bypass"
        short = [re.sub(r"^https?://(raw\.githubusercontent\.com/|cdn\.jsdelivr\.net/gh/)?", "", n)[:80] for n in names[:4]]
        self._why[domain] = (cat, short)
        return self._why[domain]

    def client_queries(self, ip, t0, t1, sample):
        params = {"client_ip": ip, "from": t0, "until": t1, "length": sample}
        if t1 - t0 > 24 * 3600:
            params["disk"] = "true"
        data = self.get("/queries", params) or {}
        return data.get("queries", []), data.get("recordsFiltered") or 0

    def rate_limited(self, t0):
        hits = collections.Counter()
        try:
            for m in (self.get("/info/messages") or {}).get("messages", []):
                if m.get("type") == "RATE_LIMIT" and (m.get("timestamp") or 0) >= t0:
                    found = re.search(r"Rate-limiting (\S+)", m.get("plain", ""))
                    if found:
                        hits[found.group(1)] += 1
        except Exception:
            pass
        return hits

    def client_detail(self, ip, name, vlan, t0, t1, hours, sample, totals=None):
        qs, total_seen = self.client_queries(ip, t0, t1, sample)
        n = len(qs)
        blocked = [q for q in qs if q.get("status") in BLOCKED]
        nx = sum(1 for q in qs if (q.get("reply") or {}).get("type") == "NXDOMAIN")
        domains = collections.Counter(q.get("domain") for q in qs)
        blocked_domains = collections.Counter(q.get("domain") for q in blocked)
        top_blocked, threat_hits, bypass_hits, threat_domains = [], 0, 0, []
        for dom, cnt in blocked_domains.most_common(15):
            cat, lists = self.classify(dom)
            top_blocked.append({"domain": dom, "count": cnt, "category": cat, "lists": lists})
            if cat == "threat":
                threat_hits += cnt
                threat_domains.append(dom)
            elif cat == "bypass":
                bypass_hits += cnt
        queries = (totals or {}).get("queries", total_seen)
        blocked_n = (totals or {}).get("blocked", len(blocked) if n >= total_seen else round(total_seen * len(blocked) / max(n, 1)))
        row = {
            "ip": ip, "name": name or None, "vlan": vlan,
            "queries": queries, "blocked": blocked_n, "blocked_pct": pct(blocked_n, queries),
            "per_hour": (lambda r: round(r, 1) if r < 10 else round(r))(queries / max(hours, 1e-9)),
            "nxdomain_pct": pct(nx, n), "unique_domains": len(domains),
            "threat_hits": threat_hits, "bypass_hits": bypass_hits,
            "sampled": n if n < total_seen else None,
            "top_domains": [{"domain": d, "count": c} for d, c in domains.most_common(8)],
            "top_blocked": top_blocked,
            "flags": [],
        }
        row["_threat_domains"] = threat_domains
        return row

    def flag(self, row, rate_limits):
        v = row["vlan"]
        t = lambda key: self.threshold(key, v)  # noqa: E731
        enough = row["queries"] >= t("ALERT_MIN_QUERIES")
        flags = []
        if row["threat_hits"] >= t("ALERT_THREAT_HITS"):
            flags.append("threat: %d queries blocked by threat-intel lists (%s)"
                         % (row["threat_hits"], ", ".join(row["_threat_domains"][:4])))
        if row["bypass_hits"] >= t("ALERT_BYPASS_HITS"):
            flags.append("bypass: %d attempts to reach DoH/VPN/proxy endpoints" % row["bypass_hits"])
        if row["per_hour"] >= t("ALERT_QUERIES_PER_HOUR"):
            flags.append("volume: %d queries/hour" % row["per_hour"])
        if enough and row["nxdomain_pct"] >= t("ALERT_NXDOMAIN_PCT"):
            flags.append("nxdomain: %.0f%% of replies are NXDOMAIN (DGA malware / beaconing / misconfigured)"
                         % row["nxdomain_pct"])
        if enough and row["blocked_pct"] >= t("ALERT_BLOCKED_PCT"):
            flags.append("blocked: %.0f%% of queries blocked" % row["blocked_pct"])
        if rate_limits.get(row["ip"]):
            flags.append("rate-limited %d time(s) by Pi-hole (query flood)" % rate_limits[row["ip"]])
        row["flags"] = flags

    def vlan_report(self, hours=24, detail=5, sample=2000, only_vlan=None):
        t1 = int(time.time())
        t0 = t1 - int(hours * 3600)
        vlans = self.vlans()
        win = {"from": t0, "until": t1, "count": 1000}
        tot = (self.get("/stats/database/top_clients", dict(win, blocked="false")) or {}).get("clients", [])
        blk = (self.get("/stats/database/top_clients", dict(win, blocked="true")) or {}).get("clients", [])
        # The long-term endpoint counts PERMITTED queries for blocked=false (the live one counts
        # all), so total = permitted + blocked. A client can appear in only one of the two lists
        # (100 % blocked = most suspicious). Pi-hole lists an IP once per name it had: merge by IP.
        blocked_by_ip, merged = collections.Counter(), collections.OrderedDict()
        for c, is_blocked in [(c, False) for c in tot] + [(c, True) for c in blk]:
            m = merged.setdefault(c.get("ip"), {"name": None, "queries": 0})
            m["queries"] += c.get("count", 0)
            m["name"] = m["name"] or c.get("name") or None
            if is_blocked:
                blocked_by_ip[c.get("ip")] += c.get("count", 0)
        rate_limits = self.rate_limited(t0)
        per_vlan = collections.OrderedDict((name, []) for name, _ in vlans)
        for ip, m in merged.items():
            v = vlan_of(ip, vlans)
            per_vlan.setdefault(v, []).append({"ip": ip, "name": m["name"],
                                               "queries": m["queries"], "blocked": blocked_by_ip.get(ip, 0)})
        for ip in rate_limits:  # flooded clients may have few logged queries
            v = vlan_of(ip, vlans)
            if not any(r["ip"] == ip for r in per_vlan.get(v, [])):
                per_vlan.setdefault(v, []).append({"ip": ip, "name": None, "queries": 0, "blocked": 0})
        subnets = collections.defaultdict(list)
        for name, net in vlans:
            subnets[name].append(str(net))
        out, alerts = [], []
        for v, clients in per_vlan.items():
            if only_vlan and v.lower() != only_vlan.lower():
                continue
            q = sum(c["queries"] for c in clients)
            b = sum(c["blocked"] for c in clients)
            pick = {c["ip"] for c in sorted(clients, key=lambda c: -c["blocked"])[:detail]}
            pick |= {c["ip"] for c in sorted(clients, key=lambda c: -c["queries"])[:detail]}
            pick |= {ip for ip in rate_limits if vlan_of(ip, vlans) == v}
            rows = []
            for c in clients:
                if c["ip"] not in pick:
                    continue
                row = self.client_detail(c["ip"], c["name"], v, t0, t1, hours, sample,
                                         totals={"queries": c["queries"], "blocked": c["blocked"]})
                self.flag(row, rate_limits)
                rows.append(row)
            rows.sort(key=lambda r: (-len(r["flags"]), -r["threat_hits"], -r["blocked"]))
            for r in rows:
                for f in r["flags"]:
                    alerts.append({"vlan": v, "ip": r["ip"], "name": r["name"], "kind": f.split(":")[0].split(" ")[0],
                                   "text": "%s %s%s: %s" % (v, r["ip"], " (%s)" % r["name"] if r["name"] else "", f)})
                r.pop("_threat_domains", None)
            out.append({"vlan": v, "subnets": subnets.get(v, []), "clients_seen": len(clients),
                        "queries": q, "blocked": b, "blocked_pct": pct(b, q),
                        "threat_hits": sum(r["threat_hits"] for r in rows),
                        "clients": rows,
                        "other_clients": len(clients) - len(rows)})
        return {"window_hours": hours, "from": t0, "until": t1,
                "vlan_source": "MCP_VLANS" if self.s.get("MCP_VLANS") else ("pihole subnet clients" if vlans else "/24"),
                "note": "Counts come from Pi-hole's long-term database (written every minute). "
                        "Per-client rates are from up to %d most recent queries." % sample,
                "vlans": out, "alerts": alerts}

    def client_report(self, ip, hours=24, sample=5000):
        t1 = int(time.time())
        t0 = t1 - int(hours * 3600)
        vlans = self.vlans()
        row = self.client_detail(ip, None, vlan_of(ip, vlans), t0, t1, hours, sample)
        self.flag(row, self.rate_limited(t0))
        row.pop("_threat_domains", None)
        row["window_hours"] = hours
        return row


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
def send_alerts(alerts, settings, log=print):
    allowed = {v.strip().lower() for v in (settings.get("ALERT_VLANS") or "").split(",") if v.strip()}
    if allowed:
        alerts = [a for a in alerts if a["vlan"].lower() in allowed]
    state_file = settings.get("ALERT_STATE_FILE") or os.path.expanduser("~/.cache/managed_pihole_vlan_alerts.json")
    repeat = float(settings.get("ALERT_REPEAT_HOURS") or 6) * 3600
    try:
        with open(state_file) as fp:
            state = json.load(fp)
    except (OSError, ValueError):
        state = {}
    now = time.time()
    fresh = []
    for a in alerts:
        key = "%s|%s|%s" % (a["vlan"], a["ip"], a["kind"])
        if now - state.get(key, 0) >= repeat:
            fresh.append(a)
            state[key] = now
    state = {k: v for k, v in state.items() if now - v < 7 * 86400}
    try:
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
        with open(state_file, "w") as fp:
            json.dump(state, fp)
    except OSError as e:
        log("WARNING: cannot save alert state %s: %s" % (state_file, e))
    for a in fresh:
        log("ALERT " + a["text"])
    url = settings.get("ALERT_WEBHOOK")
    if fresh and url:
        text = "Pi-hole DNS alerts (%d):\n%s" % (len(fresh), "\n".join("- " + a["text"] for a in fresh))
        if "hooks.slack.com" in url:
            body, ctype = json.dumps({"text": text}).encode(), "application/json"
        elif "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
            body, ctype = json.dumps({"content": text[:1990]}).encode(), "application/json"
        else:  # ntfy and generic receivers take plain text
            body, ctype = text.encode(), "text/plain; charset=utf-8"
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": ctype, "Title": "Pi-hole DNS alert",
                                              "Tags": "warning", "User-Agent": "managed_pihole/" + __version__})
        try:
            urllib.request.urlopen(req, timeout=20).read()
            log("Sent %d alert(s) to webhook." % len(fresh))
        except Exception as e:
            log("WARNING: webhook failed: %s" % e)
    return fresh


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def api_getter(settings):
    api = PiholeAPI(settings=settings, verbose=False).login()

    def get(path, params=None):
        status, data = api.request("GET", path, params=params)
        if status != 200:
            raise ReportError("Pi-hole GET %s -> HTTP %s: %s" % (path, status, data))
        return data
    return api, get


def print_table(rep):
    print("DNS activity by VLAN - last %s h  (VLANs from %s)\n" % (rep["window_hours"], rep["vlan_source"]))
    print("  %-14s %8s %10s %10s %7s %7s" % ("VLAN", "clients", "queries", "blocked", "%blk", "threat"))
    for v in rep["vlans"]:
        print("  %-14s %8d %10d %10d %6.1f%% %7d" % (v["vlan"][:14], v["clients_seen"], v["queries"],
                                                      v["blocked"], v["blocked_pct"], v["threat_hits"]))
    for v in rep["vlans"]:
        if not v["clients"]:
            continue
        print("\n  %s  %s" % (v["vlan"], " ".join(v["subnets"])))
        for r in v["clients"]:
            print("    %s %-15s %-18s q=%-7d %5g/h  blk=%5.1f%%  NX=%5.1f%%  threat=%d%s" % (
                "!!" if r["flags"] else "  ", r["ip"], (r["name"] or "")[:18], r["queries"], r["per_hour"],
                r["blocked_pct"], r["nxdomain_pct"], r["threat_hits"],
                "  bypass=%d" % r["bypass_hits"] if r["bypass_hits"] else ""))
            for b in r["top_blocked"][:3]:
                if b["category"] != "ads" or r["flags"]:
                    print("         blocked %-40s x%-5d %s" % (b["domain"][:40], b["count"], b["category"]))
        if v["other_clients"]:
            print("    (+%d more clients with less traffic)" % v["other_clients"])
    print("\nAlerts: %d" % len(rep["alerts"]))
    for a in rep["alerts"]:
        print("  ! " + a["text"])


def main():
    ap = argparse.ArgumentParser(description="Per-VLAN DNS activity and bad-traffic alerts (Pi-hole v6)")
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--vlan", help="only this VLAN")
    ap.add_argument("--client", help="report one client IP instead")
    ap.add_argument("--detail", type=int, default=5, help="clients analysed per VLAN (by volume and by blocks)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--alert", action="store_true", help="print new alerts and send them to ALERT_WEBHOOK")
    ap.add_argument("--quiet", action="store_true", help="with --alert: print only alerts")
    args = ap.parse_args()
    settings = load_settings()
    try:
        api, get = api_getter(settings)
    except PiholeAPIError as e:
        sys.exit("ERROR: %s" % e)
    try:
        r = Reporter(get, settings)
        if args.client:
            rep = r.client_report(args.client, args.hours)
            print(json.dumps(rep, indent=1))
            return
        rep = r.vlan_report(args.hours, args.detail, only_vlan=args.vlan)
        if args.alert:
            fresh = send_alerts(rep["alerts"], settings)
            if not args.quiet:
                print_table(rep)
            elif not fresh:
                print("No new alerts (%d active, already reported)." % len(rep["alerts"]))
        elif args.json:
            print(json.dumps(rep, indent=1))
        else:
            print_table(rep)
    except ReportError as e:
        sys.exit("ERROR: %s" % e)
    finally:
        api.logout()


if __name__ == "__main__":
    main()
