#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
#
#  mcp_server.py  -  read-only MCP server for Pi-hole v6, AdGuard Home and Unbound
#
#  Version:       1.0.0
#  Last Updated:  11/5/2026
#  Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Lets an AI agent (Claude Code, Claude Desktop, or any MCP client) read DNS metrics
#  and stats. Python standard library only. It speaks MCP over stdio (JSON-RPC 2.0, one
#  message per line). Every tool is READ-ONLY: nothing here changes lists, settings
#  or blocking.
#
#    Pi-hole v6     REST API (/api/stats, /api/history, /api/queries, /api/info ...)
#    AdGuard Home   REST API (/control/stats, /control/querylog, /control/status ...)
#    Unbound        `unbound-control stats_noreset` (local, or `docker exec unbound ...`)
#
#  Run it on the DNS host, then have the agent start it over SSH:
#    claude mcp add dns -- ssh pi@pihole.local /opt/managed_pihole/mcp_server.py
#  Or run it locally against a remote Pi-hole / AdGuard Home (Unbound stats then need
#  UNBOUND_CONTROL to point at a working command, e.g. "ssh pi@host sudo unbound-control"):
#    claude mcp add dns -e PIHOLE_API_URL=http://192.168.1.2/api -e PIHOLE_PASSWORD=<app pw> \
#        -- python3 /path/to/mcp_server.py
#
#  Self-test (prints every tool's output, no MCP client needed):
#    ./mcp_server.py --test
#
#  Settings (env vars, or KEY=VALUE in /etc/managed_pihole.conf / ./managed_pihole.conf):
#    MCP_SERVICES       comma list of pihole, adguardhome, unbound
#                       (default: DNS_FILTER (pihole) + unbound)
#    PIHOLE_API_URL, PIHOLE_PASSWORD, PIHOLE_DIR, PIHOLE_MODE, PIHOLE_CONTAINER
#                       see pihole_api.py. Use an app password for a non-root user.
#    ADGUARD_URL, ADGUARD_USER, ADGUARD_PASSWORD
#                       see upsert_adguardhome.py
#    UNBOUND_CONTROL    command that runs unbound-control (default: auto -
#                       "unbound-control", else "docker exec <UNBOUND_CONTAINER> unbound-control")
#    UNBOUND_CONTAINER  default: unbound
#
#  ChangeLog:
#    1.0.0  11/5/2026  New file (Claude Code).
#
#  Sources:
#    https://modelcontextprotocol.io/specification/2025-06-18
#    https://docs.pi-hole.net/api/
#    https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
#    https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html
#-------------------------------------------------------------------------------
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pihole_api import PiholeAPI, PiholeAPIError, load_settings  # noqa: E402

__version__ = "1.0.0"
SERVER_NAME = "managed_pihole"
PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

# stdout carries the MCP protocol. Anything else that prints (library code, warnings)
# goes to stderr so it can never corrupt a message.
PROTO_OUT = sys.stdout
sys.stdout = sys.stderr


def log(*msg):
    print("[%s]" % SERVER_NAME, *msg, file=sys.stderr, flush=True)


class ToolError(Exception):
    """An error the agent should see as a tool result (isError: true)."""


def clamp(value, low, high, default):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def time_range(args):
    """(from, until) unix times for an 'hours' argument, or None if not given."""
    if args.get("hours") in (None, ""):
        return None
    hours = clamp(args.get("hours"), 1, 24 * 366, 24)
    until = int(time.time())
    return until - hours * 3600, until


# =============================================================================
# Pi-hole v6
# =============================================================================
class Pihole:
    def __init__(self, settings):
        self.settings = settings
        self.api = None

    def _connect(self):
        if self.api is None:
            api = PiholeAPI(settings=self.settings, verbose=False)
            api.login()
            self.api = api
        return self.api

    def get(self, path, params=None):
        """GET with one re-login if the session expired (sessions time out after 5 min idle)."""
        for attempt in (1, 2):
            try:
                api = self._connect()
                status, data = api.request("GET", path, params=params)
            except PiholeAPIError as e:
                self.api = None
                raise ToolError(str(e))
            if status == 401 and attempt == 1:
                self.api = None
                continue
            if status != 200:
                raise ToolError("Pi-hole GET %s -> HTTP %s: %s" % (path, status, data))
            return data
        raise ToolError("Pi-hole API: not authorized")

    def close(self):
        if self.api:
            self.api.logout()
            self.api = None

    # ---- tools ----
    def summary(self, args):
        rng = time_range(args)
        if rng:
            data = self.get("/stats/database/summary", {"from": rng[0], "until": rng[1]})
        else:
            data = self.get("/stats/summary")
        blocking = self.get("/dns/blocking")
        data.pop("took", None)
        for key in ("types", "status", "replies"):  # drop zero counters to keep it short
            group = (data.get("queries") or {}).get(key)
            if isinstance(group, dict):
                data["queries"][key] = {k: v for k, v in group.items() if v}
        data["blocking"] = {k: blocking.get(k) for k in ("blocking", "timer")}
        return data

    def top(self, args):
        count = clamp(args.get("count"), 1, 100, 10)
        kind = args.get("kind", "domains")
        blocked = bool(args.get("blocked", False))
        rng = time_range(args)
        prefix = "/stats/database" if rng else "/stats"
        params = {"count": count}
        if rng:
            params.update({"from": rng[0], "until": rng[1]})
        if kind == "domains":
            params["blocked"] = "true" if blocked else "false"
            data = self.get(prefix + "/top_domains", params)
        elif kind == "clients":
            params["blocked"] = "true" if blocked else "false"
            data = self.get(prefix + "/top_clients", params)
        elif kind == "upstreams":
            data = self.get(prefix + "/upstreams", params if rng else None)
        elif kind == "query_types":
            data = self.get(prefix + "/query_types", params if rng else None)
        else:
            raise ToolError("kind must be domains, clients, upstreams or query_types")
        data.pop("took", None)
        return data

    def history(self, args):
        rng = time_range(args)
        if rng:
            data = self.get("/history/database", {"from": rng[0], "until": rng[1]})
        else:
            data = self.get("/history")
        rows = data.get("history", [])
        return {"interval_seconds": 600 if not rng else None, "points": len(rows), "history": rows}

    def queries(self, args):
        params = {"length": clamp(args.get("count"), 1, 500, 50)}
        for key, api_key in (("domain", "domain"), ("client", "client_ip"), ("status", "status"),
                             ("type", "type"), ("upstream", "upstream")):
            if args.get(key):
                params[api_key] = args[key]
        rng = time_range(args)
        if rng:
            params.update({"from": rng[0], "until": rng[1]})
        data = self.get("/queries", params)
        out = []
        for q in data.get("queries", []):
            client = q.get("client") or {}
            reply = q.get("reply") or {}
            out.append({
                "time": q.get("time"),
                "domain": q.get("domain"),
                "type": q.get("type"),
                "status": q.get("status"),
                "client": client.get("name") or client.get("ip"),
                "client_ip": client.get("ip"),
                "reply": reply.get("type"),
                "reply_ms": round(reply.get("time", 0) * 1000, 2) if reply.get("time") is not None else None,
                "upstream": q.get("upstream"),
                "dnssec": q.get("dnssec"),
            })
        return {"recordsTotal": data.get("recordsTotal"), "recordsFiltered": data.get("recordsFiltered"),
                "returned": len(out), "queries": out}

    def search(self, args):
        domain = (args.get("domain") or "").strip()
        if not domain:
            raise ToolError("domain is required")
        data = self.get("/search/" + domain, {"partial": "true" if args.get("partial") else "false", "N": 20})
        data.pop("took", None)
        return data

    def system(self, args):
        out = {}
        for key, path in (("version", "/info/version"), ("ftl", "/info/ftl"),
                          ("system", "/info/system"), ("host", "/info/host"),
                          ("sensors", "/info/sensors"), ("messages", "/info/messages")):
            try:
                data = self.get(path)
                data.pop("took", None)
                out[key] = data
            except ToolError as e:
                out[key] = {"error": str(e)}
        return out

    def lists(self, args):
        data = self.get("/lists")
        rows = []
        for item in data.get("lists", []):
            rows.append({k: item.get(k) for k in ("address", "type", "enabled", "number",
                                                  "invalid_domains", "status", "date_updated", "groups")})
        return {"count": len(rows),
                "domains_total": sum((r.get("number") or 0) for r in rows if r.get("enabled")),
                "lists": rows}


# =============================================================================
# AdGuard Home
# =============================================================================
class AdGuard:
    def __init__(self, settings):
        self.settings = settings
        self.client = None

    def _connect(self):
        if self.client is None:
            if not self.settings.get("ADGUARD_PASSWORD"):
                raise ToolError("Set ADGUARD_PASSWORD (AdGuard Home web password) in "
                                "/etc/managed_pihole.conf or the environment.")
            from upsert_adguardhome import AdGuardHome  # noqa: E402
            try:
                self.client = AdGuardHome(self.settings.get("ADGUARD_URL"),
                                          self.settings.get("ADGUARD_USER") or "admin",
                                          self.settings["ADGUARD_PASSWORD"])
            except SystemExit as e:  # _detect() exits when nothing answers
                raise ToolError(str(e))
        return self.client

    def get(self, path, params=None):
        import urllib.parse
        if params:
            path += "?" + urllib.parse.urlencode(params)
        try:
            status, data = self._connect()._req("GET", path)
        except OSError as e:
            raise ToolError("AdGuard Home GET %s failed: %s" % (path, e))
        if status != 200:
            raise ToolError("AdGuard Home GET %s -> HTTP %s: %s" % (path, status, data))
        return data

    @staticmethod
    def _pairs(rows, limit, label="count", scale=1):
        """[{"a.com": 5}, ...] -> [{"name": "a.com", "count": 5}, ...]"""
        out = []
        for row in (rows or [])[:limit]:
            for k, v in row.items():
                out.append({"name": k, label: round(v * scale, 2) if scale != 1 else v})
        return out

    def summary(self, args):
        stats = self.get("/stats")
        status = self.get("/status")
        total = stats.get("num_dns_queries") or 0
        blocked = (stats.get("num_blocked_filtering") or 0)
        return {
            "time_units": stats.get("time_units"),
            "dns_queries": total,
            "blocked_filtering": blocked,
            "blocked_percent": round(100.0 * blocked / total, 2) if total else 0,
            "replaced_safebrowsing": stats.get("num_replaced_safebrowsing"),
            "replaced_parental": stats.get("num_replaced_parental"),
            "replaced_safesearch": stats.get("num_replaced_safesearch"),
            "avg_processing_time_ms": round((stats.get("avg_processing_time") or 0) * 1000, 2),
            "status": {k: status.get(k) for k in ("version", "running", "protection_enabled",
                                                  "protection_disabled_duration", "dns_port")},
        }

    def top(self, args):
        count = clamp(args.get("count"), 1, 100, 10)
        kind = args.get("kind", "domains")
        stats = self.get("/stats")
        if kind == "domains":
            key = "top_blocked_domains" if args.get("blocked") else "top_queried_domains"
            return {kind: self._pairs(stats.get(key), count), "blocked": bool(args.get("blocked"))}
        if kind == "clients":
            return {kind: self._pairs(stats.get("top_clients"), count)}
        if kind == "upstreams":
            return {"responses": self._pairs(stats.get("top_upstreams_responses"), count),
                    "avg_time": self._pairs(stats.get("top_upstreams_avg_time"), count, "ms", 1000)}
        raise ToolError("kind must be domains, clients or upstreams")

    def history(self, args):
        stats = self.get("/stats")
        return {"time_units": stats.get("time_units"),
                "note": "oldest first; one point per time unit",
                "dns_queries": stats.get("dns_queries"),
                "blocked_filtering": stats.get("blocked_filtering"),
                "replaced_safebrowsing": stats.get("replaced_safebrowsing"),
                "replaced_parental": stats.get("replaced_parental")}

    def queries(self, args):
        params = {"limit": clamp(args.get("count"), 1, 500, 50)}
        if args.get("search"):
            params["search"] = args["search"]
        if args.get("status"):
            params["response_status"] = args["status"]
        data = self.get("/querylog", params)
        out = []
        for q in data.get("data", []):
            question = q.get("question") or {}
            out.append({
                "time": q.get("time"),
                "domain": question.get("name"),
                "type": question.get("type"),
                "client": (q.get("client_info") or {}).get("name") or q.get("client"),
                "client_ip": q.get("client"),
                "reason": q.get("reason"),
                "status": q.get("status"),
                "rules": [r.get("text") for r in (q.get("rules") or [])],
                "upstream": q.get("upstream"),
                "elapsed_ms": q.get("elapsedMs"),
                "cached": q.get("cached"),
            })
        return {"returned": len(out), "oldest": data.get("oldest"), "queries": out}

    def search(self, args):
        domain = (args.get("domain") or "").strip()
        if not domain:
            raise ToolError("domain is required")
        params = {"name": domain}
        if args.get("client"):
            params["client"] = args["client"]
        return self.get("/filtering/check_host", params)

    def system(self, args):
        status = self.get("/status")
        out = {"status": status}
        for key, path in (("dns_info", "/dns_info"), ("stats_config", "/stats/config/get"),
                          ("querylog_config", "/querylog/config/get")):
            try:
                out[key] = self.get(path)
            except ToolError as e:
                out[key] = {"error": str(e)}
        return out

    def lists(self, args):
        data = self.get("/filtering/status")
        rows = []
        for kind in ("filters", "whitelist_filters"):
            for f in data.get(kind) or []:
                rows.append({"type": "block" if kind == "filters" else "allow",
                             "name": f.get("name"), "url": f.get("url"), "enabled": f.get("enabled"),
                             "rules_count": f.get("rules_count"), "last_updated": f.get("last_updated")})
        return {"filtering_enabled": data.get("enabled"),
                "interval_hours": data.get("interval"),
                "user_rules": len([r for r in (data.get("user_rules") or []) if r and not r.startswith("!")]),
                "count": len(rows),
                "rules_total": sum((r.get("rules_count") or 0) for r in rows if r.get("enabled")),
                "lists": rows}


# =============================================================================
# Unbound
# =============================================================================
class Unbound:
    def __init__(self, settings):
        self.settings = settings
        self._cmd = None

    def _command(self):
        if self._cmd:
            return self._cmd
        configured = self.settings.get("UNBOUND_CONTROL") or os.environ.get("UNBOUND_CONTROL")
        if configured and configured != "auto":
            self._cmd = shlex.split(configured)
        elif shutil.which("unbound-control"):
            self._cmd = ["unbound-control"]
        elif shutil.which("docker"):
            container = self.settings.get("UNBOUND_CONTAINER") or os.environ.get("UNBOUND_CONTAINER") or "unbound"
            self._cmd = ["docker", "exec", container, "unbound-control"]
        else:
            raise ToolError("unbound-control not found. Install Unbound here, or set UNBOUND_CONTROL "
                            "(e.g. 'docker exec unbound unbound-control' or 'ssh pi@host sudo unbound-control').")
        return self._cmd

    def run(self, *args):
        cmd = self._command() + list(args)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as e:
            raise ToolError("%s failed: %s" % (" ".join(cmd), e))
        if out.returncode != 0:
            raise ToolError(
                "%s failed (exit %s): %s\nunbound-control needs 'remote-control: control-enable: yes' "
                "in unbound.conf and usually root (or read access to the control socket/keys). "
                "setup_unbound.sh enables it on a unix socket."
                % (" ".join(cmd), out.returncode, (out.stderr or out.stdout).strip()[:500]))
        return out.stdout

    def raw_stats(self):
        stats = {}
        for line in self.run("stats_noreset").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                try:
                    stats[k.strip()] = float(v) if "." in v else int(v)
                except ValueError:
                    stats[k.strip()] = v.strip()
        return stats

    def stats(self, args):
        s = self.raw_stats()
        if args.get("raw"):
            return s
        q = s.get("total.num.queries", 0) or 0
        hits = s.get("total.num.cachehits", 0) or 0
        rcodes = {k.split(".")[-1]: v for k, v in s.items() if k.startswith("num.answer.rcode.")}
        qtypes = {k.split(".")[-1]: v for k, v in s.items() if k.startswith("num.query.type.") and v}
        return {
            "uptime_seconds": s.get("time.up"),
            "queries": q,
            "cache_hits": hits,
            "cache_misses": s.get("total.num.cachemiss"),
            "cache_hit_percent": round(100.0 * hits / q, 2) if q else 0,
            "prefetches": s.get("total.num.prefetch"),
            "expired_served": s.get("total.num.expired"),
            "recursive_replies": s.get("total.num.recursivereplies"),
            "recursion_avg_ms": round((s.get("total.recursion.time.avg") or 0) * 1000, 2),
            "recursion_median_ms": round((s.get("total.recursion.time.median") or 0) * 1000, 2),
            "requestlist_avg": s.get("total.requestlist.avg"),
            "requestlist_max": s.get("total.requestlist.max"),
            "requestlist_overwritten": s.get("total.requestlist.overwritten"),
            "requestlist_exceeded": s.get("total.requestlist.exceeded"),
            "answer_rcodes": rcodes or "enable 'extended-statistics: yes' for rcode/type counts",
            "query_types": qtypes or None,
            "dnssec_secure": s.get("num.answer.secure"),
            "dnssec_bogus": s.get("num.answer.bogus"),
            "rrset_bogus": s.get("num.rrset.bogus"),
            "unwanted_replies": s.get("unwanted.replies"),
            "memory_bytes": {k[len("mem."):]: v for k, v in s.items() if k.startswith("mem.")} or None,
            "cache_entries": {k.split(".")[0]: v for k, v in s.items()
                              if k in ("msg.cache.count", "rrset.cache.count",
                                       "infra.cache.count", "key.cache.count")} or None,
        }

    def status(self, args):
        return {"status": self.run("status").strip()}


# =============================================================================
# Tool registry
# =============================================================================
HOURS = {"type": "integer", "minimum": 1,
         "description": "Look back this many hours using the long-term database. Omit for the live (last 24 h) counters."}
COUNT = {"type": "integer", "minimum": 1, "maximum": 100, "default": 10}


def build_tools(services, settings):
    tools = {}

    def add(name, title, description, schema, fn):
        tools[name] = {
            "def": {"name": name, "title": title, "description": description,
                    "inputSchema": {"type": "object", "properties": schema, "additionalProperties": False},
                    "annotations": {"title": title, "readOnlyHint": True, "openWorldHint": False}},
            "fn": fn,
        }

    if "pihole" in services:
        p = Pihole(settings)
        add("pihole_summary", "Pi-hole summary",
            "Pi-hole v6 totals: queries, blocked, percent blocked, cached/forwarded, unique domains, "
            "active clients, gravity size and whether blocking is on.",
            {"hours": HOURS}, p.summary)
        add("pihole_top", "Pi-hole top items",
            "Top domains (allowed or blocked), top clients, upstream servers, or query types.",
            {"kind": {"type": "string", "enum": ["domains", "clients", "upstreams", "query_types"],
                      "default": "domains"},
             "blocked": {"type": "boolean", "default": False,
                         "description": "domains/clients: rank by blocked queries instead of allowed"},
             "count": COUNT, "hours": HOURS}, p.top)
        add("pihole_history", "Pi-hole query history",
            "Queries over time (total, cached, blocked, forwarded per interval). Live data is the last "
            "24 h in 10-minute buckets.",
            {"hours": HOURS}, p.history)
        add("pihole_queries", "Pi-hole query log",
            "Recent individual DNS queries, newest first, with optional filters.",
            {"count": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
             "domain": {"type": "string", "description": "domain (wildcards * allowed)"},
             "client": {"type": "string", "description": "client IP"},
             "status": {"type": "string", "description": "e.g. GRAVITY, FORWARDED, CACHE, REGEX, DENYLIST"},
             "type": {"type": "string", "description": "query type, e.g. A, AAAA, HTTPS"},
             "upstream": {"type": "string", "description": "upstream, or 'blocklist' / 'cache'"},
             "hours": HOURS}, p.queries)
        add("pihole_search", "Pi-hole domain search",
            "Which block lists, allow/deny entries and regexes match a domain (why is it blocked?).",
            {"domain": {"type": "string"}, "partial": {"type": "boolean", "default": False}}, p.search)
        add("pihole_system", "Pi-hole system info",
            "Pi-hole/FTL versions, FTL status, host CPU/memory/load, temperature sensors and "
            "diagnosis messages.", {}, p.system)
        add("pihole_lists", "Pi-hole subscribed lists",
            "Every subscribed allow/block list with domain count, status and last update.", {}, p.lists)

    if "adguardhome" in services:
        a = AdGuard(settings)
        add("adguard_summary", "AdGuard Home summary",
            "AdGuard Home totals for its statistics window: queries, blocked, percent blocked, "
            "safe-browsing/parental/safe-search replacements, average processing time, protection status.",
            {}, a.summary)
        add("adguard_top", "AdGuard Home top items",
            "Top queried or blocked domains, top clients, or upstream servers (responses and average time).",
            {"kind": {"type": "string", "enum": ["domains", "clients", "upstreams"], "default": "domains"},
             "blocked": {"type": "boolean", "default": False}, "count": COUNT}, a.top)
        add("adguard_history", "AdGuard Home query history",
            "Queries and blocks over time (per hour or per day, depending on the statistics window).",
            {}, a.history)
        add("adguard_queries", "AdGuard Home query log",
            "Recent individual DNS queries, newest first.",
            {"count": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
             "search": {"type": "string", "description": "domain or client to search for"},
             "status": {"type": "string",
                        "enum": ["all", "filtered", "blocked", "blocked_safebrowsing", "blocked_parental",
                                 "whitelisted", "rewritten", "safe_search", "processed"]}}, a.queries)
        add("adguard_search", "AdGuard Home domain check",
            "Check whether a domain is blocked or allowed and by which rule/list.",
            {"domain": {"type": "string"},
             "client": {"type": "string", "description": "optional client name or IP to check as"}}, a.search)
        add("adguard_system", "AdGuard Home system info",
            "AdGuard Home version and status, DNS settings (upstreams, cache, rate limit), "
            "statistics and query-log retention.", {}, a.system)
        add("adguard_lists", "AdGuard Home filter lists",
            "Every block/allow filter list with rule count and last update.", {}, a.lists)

    if "unbound" in services:
        u = Unbound(settings)
        add("unbound_stats", "Unbound statistics",
            "Unbound recursive resolver stats since start: queries, cache hit rate, prefetch, "
            "recursion time, request list, DNSSEC secure/bogus, answer rcodes, memory. Not reset.",
            {"raw": {"type": "boolean", "default": False,
                     "description": "return every unbound-control counter instead of the summary"}}, u.stats)
        add("unbound_status", "Unbound status",
            "unbound-control status: version, uptime, threads, modules.", {}, u.status)

    def overview(args):
        out = {}
        for name in ("pihole_summary", "adguard_summary", "unbound_stats"):
            if name in tools:
                try:
                    out[name.split("_")[0]] = tools[name]["fn"]({})
                except Exception as e:  # one service down must not hide the others
                    out[name.split("_")[0]] = {"error": str(e)}
        return out

    add("dns_overview", "DNS overview",
        "One call: the summary of every configured service (Pi-hole / AdGuard Home and Unbound). "
        "Start here.", {}, overview)
    return tools


# =============================================================================
# MCP over stdio
# =============================================================================
def send(msg):
    PROTO_OUT.write(json.dumps(msg, separators=(",", ":"), default=str) + "\n")
    PROTO_OUT.flush()


def handle(msg, tools, services):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:  # notification (initialized, cancelled ...): never answered
        return None
    params = msg.get("params") or {}
    if method == "initialize":
        asked = params.get("protocolVersion")
        result = {
            "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[1],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "title": "managed_pihole DNS stats", "version": __version__},
            "instructions": ("Read-only DNS metrics for: %s. Call dns_overview first. Pi-hole times are "
                             "unix seconds, AdGuard Home times are ISO 8601. Nothing here changes settings." % ", ".join(services)),
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [t["def"] for t in tools.values()]}
    elif method == "tools/call":
        name = params.get("name")
        if name not in tools:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "Unknown tool: %s" % name}}
        try:
            data = tools[name]["fn"](params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": json.dumps(data, separators=(",", ":"), default=str)}],
                      "isError": False}
        except ToolError as e:
            result = {"content": [{"type": "text", "text": "ERROR: %s" % e}], "isError": True}
        except Exception as e:
            log("tool %s crashed:\n%s" % (name, traceback.format_exc()))
            result = {"content": [{"type": "text", "text": "ERROR: %s: %s" % (type(e).__name__, e)}],
                      "isError": True}
    elif method in ("resources/list", "prompts/list"):
        result = {method.split("/")[0]: []}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found: %s" % method}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def get_services(settings):
    raw = settings.get("MCP_SERVICES") or os.environ.get("MCP_SERVICES")
    if raw:
        services = [s.strip().lower() for s in raw.split(",") if s.strip()]
    else:
        services = [(settings.get("DNS_FILTER") or "pihole").lower(), "unbound"]
    bad = [s for s in services if s not in ("pihole", "adguardhome", "unbound")]
    if bad:
        sys.exit("MCP_SERVICES: unknown service(s) %s (use pihole, adguardhome, unbound)" % ", ".join(bad))
    return services


def self_test(tools):
    for name, tool in tools.items():
        print("=" * 20, name, file=PROTO_OUT)
        try:
            print(json.dumps(tool["fn"]({}), indent=1, default=str)[:1500], file=PROTO_OUT)
        except Exception as e:
            print("ERROR:", e, file=PROTO_OUT)


def close_sessions(tools):
    for t in tools.values():
        owner = getattr(t["fn"], "__self__", None)
        if isinstance(owner, Pihole):
            owner.close()  # frees the Pi-hole API seat (webserver.api.max_sessions)
            return


def serve(tools, services):
    log("v%s ready (stdio), services: %s" % (__version__, ", ".join(services)))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        if isinstance(msg, list):  # JSON-RPC batch (protocol 2025-03-26)
            replies = [r for r in (handle(m, tools, services) for m in msg if isinstance(m, dict)) if r]
            if replies:
                send(replies)
        elif isinstance(msg, dict):
            reply = handle(msg, tools, services)
            if reply:
                send(reply)


def main():
    if "--version" in sys.argv:
        print(__version__, file=PROTO_OUT)
        return
    settings = load_settings()
    services = get_services(settings)
    tools = build_tools(services, settings)
    # MCP clients stop the server with SIGTERM (or by closing stdin): log out cleanly.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        if "--test" in sys.argv:
            self_test(tools)
        else:
            serve(tools, services)
    except KeyboardInterrupt:
        pass
    finally:
        close_sessions(tools)


if __name__ == "__main__":
    main()
