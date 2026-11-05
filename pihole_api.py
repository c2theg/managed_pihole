#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
#
#  pihole_api.py  -  tiny Pi-hole v6 REST API client (Python standard library only)
#
#  Version:       1.1.0
#  Last Updated:  11/5/2026
#  Updated by:    Claude Code (Anthropic) - model: Claude Opus 5.5 (claude-opus-5-5)
#
#  Why this exists:
#    Pi-hole v6 ships a REST API (http://<pihole>/api). Using it, instead of writing to
#    /etc/pihole/gravity.db directly, works the same way for:
#      - native installs (Raspberry Pi OS / Debian / Ubuntu / Fedora ...)
#      - the official Docker image (which has no Python, so these tools run on the host)
#    and it does not need pihole-FTL to be stopped.
#
#  Settings (environment variables win; otherwise KEY=VALUE lines are read from
#  /etc/managed_pihole.conf and ./managed_pihole.conf next to this file):
#    PIHOLE_API_URL     e.g. http://127.0.0.1/api  or  http://127.0.0.1:8080/api
#                       (default: auto-detect on 127.0.0.1 ports 80, 8080, 443)
#    PIHOLE_PASSWORD    web password or an "app password" (Settings > Web interface / API)
#    PIHOLE_DIR         host path of Pi-hole's /etc/pihole (used to read cli_pw)
#    PIHOLE_MODE        auto | native | docker
#    PIHOLE_CONTAINER   docker container name (default: pihole)
#
#    If no password is given, the local CLI password file (/etc/pihole/cli_pw) is used.
#    This file is created by Pi-hole v6 (webserver.api.cli_pw = true, the default) and
#    needs root (native) or `docker exec` access (docker).
#
#  Sources:
#    https://docs.pi-hole.net/api/
#    https://docs.pi-hole.net/api/auth/
#    https://github.com/pi-hole/FTL/tree/master/src/api/docs/content/specs
#
#  ChangeLog:
#    1.1.0  11/5/2026  load_settings(): also ./managed_pihole.local.conf, and ALERT_* / MCP_* /
#                      THREAT_* / BYPASS_* environment variables (vlan_report.py).
#    1.0.1  11/5/2026  load_settings() also reads UNBOUND_CONTROL, UNBOUND_CONTAINER and
#                      MCP_SERVICES (used by mcp_server.py).
#    1.0.0  11/5/2026  New file (Claude Code). Shared API client used by
#                      upsert_lists.py and backup_dbs.py. load_settings() and
#                      read_list_file() are also used by upsert_adguardhome.py.
#-------------------------------------------------------------------------------
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Later files win. managed_pihole.local.conf holds site extras (e.g. written by
# deploy_multi_pi.sh) that must survive regeneration of managed_pihole.conf.
CONFIG_FILES = ["/etc/managed_pihole.conf", os.path.join(SCRIPT_DIR, "managed_pihole.conf"),
                os.path.join(SCRIPT_DIR, "managed_pihole.local.conf")]
DEFAULT_URLS = [
    "http://127.0.0.1/api",
    "http://127.0.0.1:8080/api",
    "https://127.0.0.1/api",
]


def load_settings():
    """Merge config-file values with environment variables (environment wins)."""
    settings = {}
    for path in CONFIG_FILES:
        try:
            with open(path, "r") as fp:
                for line in fp:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    if key.startswith("export "):
                        key = key[len("export "):].strip()
                    settings[key] = value.strip().strip('"').strip("'")
        except OSError:
            pass
    for key in ("PIHOLE_API_URL", "PIHOLE_PASSWORD", "PIHOLE_DIR", "PIHOLE_MODE", "PIHOLE_CONTAINER",
                "DNS_FILTER", "ADGUARD_URL", "ADGUARD_USER", "ADGUARD_PASSWORD", "ADGUARD_SOCIAL_CLIENTS",
                "UNBOUND_UPSTREAM", "UNBOUND_CONTROL", "UNBOUND_CONTAINER", "MCP_SERVICES"):
        if os.environ.get(key):
            settings[key] = os.environ[key]
    for key, value in os.environ.items():  # report / alert / MCP settings
        if value and key.startswith(("ALERT_", "MCP_", "THREAT_", "BYPASS_")):
            settings[key] = value
    settings.setdefault("PIHOLE_MODE", "auto")
    settings.setdefault("PIHOLE_CONTAINER", "pihole")
    return settings


class PiholeAPIError(Exception):
    pass


class PiholeAPI:
    def __init__(self, url=None, password=None, settings=None, verbose=True):
        self.settings = settings or load_settings()
        self.verbose = verbose
        self.sid = None
        # Pi-hole's own certificate is self-signed, so don't verify it on this local tool.
        self._ssl = ssl.create_default_context()
        self._ssl.check_hostname = False
        self._ssl.verify_mode = ssl.CERT_NONE
        self.url = (url or self.settings.get("PIHOLE_API_URL") or self._detect_url()).rstrip("/")
        self._password = password if password is not None else self._find_password()

    # ---------- helpers ----------
    def log(self, *msg):
        if self.verbose:
            print(*msg)

    def _raw(self, method, url, body=None, headers=None, timeout=30):
        data = None
        hdrs = {"Accept": "application/json", "User-Agent": "managed_pihole/" + __version__}
        if headers:
            hdrs.update(headers)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        ctx = self._ssl if url.startswith("https") else None
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)

    def _detect_url(self):
        for candidate in DEFAULT_URLS:
            try:
                with self._raw("GET", candidate + "/auth", timeout=3) as resp:
                    resp.read()
                return candidate
            except urllib.error.HTTPError as e:
                if e.code in (200, 401):  # API answered
                    return candidate
            except (urllib.error.URLError, OSError, ValueError):
                continue
        raise PiholeAPIError(
            "Could not reach the Pi-hole API on 127.0.0.1 (ports 80/8080/443). "
            "Set PIHOLE_API_URL, e.g. PIHOLE_API_URL=http://192.168.1.2:8080/api")

    def _find_password(self):
        if self.settings.get("PIHOLE_PASSWORD"):
            return self.settings["PIHOLE_PASSWORD"]
        # CLI password file written by Pi-hole v6
        candidates = []
        if self.settings.get("PIHOLE_DIR"):
            candidates.append(os.path.join(self.settings["PIHOLE_DIR"], "cli_pw"))
        candidates.append("/etc/pihole/cli_pw")
        for path in candidates:
            try:
                with open(path, "r") as fp:
                    pw = fp.read().strip()
                    if pw:
                        return pw
            except OSError:
                pass
        # Docker: read it from inside the container
        if self.settings.get("PIHOLE_MODE") in ("auto", "docker") and shutil.which("docker"):
            try:
                out = subprocess.run(
                    ["docker", "exec", self.settings["PIHOLE_CONTAINER"], "cat", "/etc/pihole/cli_pw"],
                    capture_output=True, text=True, timeout=15)
                if out.returncode == 0 and out.stdout.strip():
                    return out.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                pass
        return None

    # ---------- session ----------
    def login(self):
        if self._password:
            status, data = self.request("POST", "/auth", {"password": self._password}, auth=False)
        else:
            status, data = self.request("GET", "/auth", auth=False)
        session = (data or {}).get("session", {})
        if not session.get("valid"):
            raise PiholeAPIError(
                "Pi-hole API login failed (HTTP %s). Set PIHOLE_PASSWORD to your web password "
                "or an app password, or run as root so /etc/pihole/cli_pw can be read. Details: %s"
                % (status, (data or {}).get("error", data)))
        self.sid = session.get("sid")  # None when Pi-hole has no password set
        self.log("Logged in to Pi-hole API at", self.url)
        return self

    def logout(self):
        if self.sid:
            try:
                self.request("DELETE", "/auth")
            except Exception:
                pass
            self.sid = None

    def __enter__(self):
        return self.login()

    def __exit__(self, *exc):
        self.logout()

    # ---------- requests ----------
    def request(self, method, path, body=None, params=None, auth=True, timeout=60):
        """Returns (http_status, parsed_json_or_None). Never raises on HTTP 4xx/5xx."""
        url = self.url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"X-FTL-SID": self.sid} if (auth and self.sid) else None
        try:
            with self._raw(method, url, body=body, headers=headers, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw = e.read()
            status = e.code
        except (urllib.error.URLError, OSError) as e:
            raise PiholeAPIError("Request %s %s failed: %s" % (method, path, e))
        try:
            return status, (json.loads(raw) if raw else None)
        except ValueError:
            return status, {"raw": raw.decode("utf-8", "replace")}

    def download(self, path, dest_file, timeout=300):
        """Stream a binary response (e.g. /teleporter) to a file."""
        headers = {"X-FTL-SID": self.sid} if self.sid else None
        try:
            with self._raw("GET", self.url + path, headers=headers, timeout=timeout) as resp, \
                    open(dest_file, "wb") as out:
                shutil.copyfileobj(resp, out)
        except urllib.error.HTTPError as e:
            raise PiholeAPIError("GET %s failed: HTTP %s %s" % (path, e.code, e.read()[:300]))

    def stream(self, method, path, timeout=1800):
        """Print a streamed text response line by line (used for /action/gravity)."""
        headers = {"X-FTL-SID": self.sid} if self.sid else None
        try:
            with self._raw(method, self.url + path, headers=headers, timeout=timeout) as resp:
                for line in resp:
                    sys.stdout.write(line.decode("utf-8", "replace"))
                    sys.stdout.flush()
                return resp.status
        except urllib.error.HTTPError as e:
            print("HTTP %s: %s" % (e.code, e.read()[:500]))
            return e.code


def read_list_file(path):
    """Return the non-empty, non-comment lines of a list file (order kept, de-duplicated)."""
    entries, seen = [], set()
    with open(path, "r") as fp:
        for line in fp:
            item = line.strip()
            if not item or item.startswith("#"):
                continue
            if item not in seen:
                seen.add(item)
                entries.append(item)
    return entries
