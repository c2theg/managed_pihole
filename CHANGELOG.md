# Changelog

All notable changes to managed_pihole. Each file also carries its own version and
changelog in its header. Dates are M/D/YYYY.

## 1.7.1 (11/6/2026): fix netplan error with your own VLAN file
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **`deploy_multi_pi.sh` 1.2.0 → 1.2.1**:
  - Fixed `Error in network definition: vlan200: missing 'link' property`, which happened when your own netplan file sorts after `60-managed-pihole-vlans.yaml`. Netplan read our IPv6 settings for `vlan200` first. The VLAN's `id`/`link` are now repeated from your file. Tested with real `netplan generate`, your file before and after ours.
  - Warns when your file sets `accept-ra: false` on a VLAN, because then that VLAN gets no IPv6.
  - The "not defined in netplan" warning now actually shows.

## 1.7.0 (11/6/2026): DNS over IPv6 on every VLAN
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **`deploy_multi_pi.sh` 1.1.3 → 1.2.0**, IPv6 is on by default (`IPV6=auto`; `off` keeps the old behaviour):
  - On every VLAN the VM takes `<prefix>::53` (`IPV6_TOKEN`) from the prefixes your router advertises (SLAAC). This also applies to VLAN interfaces from your own netplan files: only `accept-ra` and the token are merged in, and your file is not edited.
  - Each VLAN's IPv6 prefixes (ULA and ISP) join its Pi-hole group, refreshed hourly (`multi-pi-v6-sync.timer`), so IoT devices on IPv6 get the IoT lists. Old prefixes are removed.
  - The dns-only firewall now covers IPv6 too (ip6tables: DNS, ICMPv6 and replies; everything else dropped). Before, IPv6 was switched off on those VLANs.
  - Re-runs `install_pihole.sh` with `SERVE_IPV6=true` when Docker's network has no IPv6.
  - The summary shows each VLAN's IPv6 DNS address (ULA first), or says the router sends no RA there.
- **`install_pihole.sh` 6.6.0 → 6.7.0**: new `SERVE_IPV6` (on by default with Docker ≥ 27) puts IPv6 on the Docker network. Without it, Docker relays IPv6 DNS queries, and Pi-hole sees them all as the Docker gateway: no per-device stats, and no VLAN group. Independent of `ENABLE_IPV6` (IPv6 upstreams).
- **`upsert_vlan_groups.py` 1.1.0 → 1.2.0**: several subnets per VLAN; `--v6-from NAME=IFACE` adds that interface's current IPv6 prefixes.
- **`vlan_report.py` 1.0.0 → 1.0.1**: a subnet that is also in another group (e.g. `Allow_Social`) is still reported under its VLAN.
- **Tested**:
  - Docker 29: with IPv6 on the Docker network, the container sees the client's own IPv6 address. Without it, it sees the Docker gateway.
  - Lab shaped like a real VM, with a stand-in router (radvd) advertising ULA and ISP-style prefixes:
    - `::53` addresses on the untagged VLAN, the existing `vlan200` and the new VLANs; a clear message on a VLAN without RA
    - `netplan generate` with the merge into your own file
    - IPv6 firewall on dns-only VLANs: DNS and ping allowed, web UI blocked; open on full VLANs
  - Live Pi-hole: IPv6 prefix clients in the right groups, a changed ISP prefix pruned, 0 changes on re-run.

## 1.6.0 (11/6/2026): daily config backups for Pi-hole, Unbound and AdGuard Home
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **`backup_dbs.py` 1.0.0 → 2.0.0**:
  - Also backs up **Unbound** (`/etc/unbound`) and **AdGuard Home** (`AdGuardHome.yaml`), native or Docker (`docker cp`, bind mounts included). Each is found automatically and skipped when not installed; `--only` / `BACKUP_SERVICES` to choose.
  - New `--install-timer [--at HH:MM]`: a daily job (systemd timer, or `/etc/cron.d` without systemd), 03:00 by default. `--remove-timer` removes it.
  - `--keep` default 7 → 4 (`BACKUP_KEEP`). Files are mode 600 in a mode 700 folder and are written to a temp name first, so a failed run never leaves half a backup.
  - Pi-hole is skipped, not an error, when it is not installed.
- **`install_pihole.sh` 6.5.0 → 6.6.0**: new `pihole-maint.sh backup` and `pihole-maint-backup.timer` (03:00, keep 4, `/opt/pihole/backups`): the Teleporter archive or `AdGuardHome.yaml`, plus Unbound's config. New `BACKUP_TIME`, `BACKUP_KEEP`, `BACKUP_DIR`.
- **`update_lists.sh` 1.0.1 → 1.0.2**: the pre-update backup covers AdGuard Home and Unbound too, and goes to `<backup folder>/pre-update` (newest 1), apart from the daily rotation.
- **`pihole_api.py` 1.1.0 → 1.1.1**: `load_settings()` also takes `BACKUP_*`, `ADGUARD_CONF`, `ADGUARD_CONTAINER` from the environment.
- **`managed_pihole.conf.example` 1.4.0**: backup settings. **`.gitignore`**: the new backup files.

## 1.5.0 (11/6/2026): password command, clearer install summary
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **`install_pihole.sh` → 6.5.0**: new `sudo /opt/pihole/pihole-maint.sh password` changes the admin password.
  - Pi-hole: writes `secrets/pihole_password.txt` and restarts the container.
  - AdGuard Home: also writes a new bcrypt hash into `AdGuardHome.yaml`.
  - Tested on both. `pihole setpassword` has no effect with this setup, because the container takes its password from the secrets file.
- The install summary now shows:
  - every admin URL (all host addresses, e.g. Tailscale)
  - how to show the password again and how to change it
  - that Unbound has no web UI, and how to read its stats
- **`deploy_multi_pi.sh` → 1.1.3**: the same password and Unbound hints in its summary.

## 1.4.2 (11/6/2026): installer prompts no longer quit on a typo; wizard re-runs fixed
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **`install_pihole.sh` 6.4.0 → 6.4.2**: if WireGuard fails to start, the install no longer stops there (which also stopped `deploy_multi_pi.sh`); it warns and shows the cause from the journal.
  Also: an invalid social-media device list or NextDNS ID is explained and asked again instead of ending the install. `SOCIAL_CLIENTS` accepts commas or semicolons (`10.11.1.0/24,10.13.1.0/24`).
- **`deploy_multi_pi.sh` 1.1.0 → 1.1.2**:
  - Saves your VLAN setup before running `install_pihole.sh`, so a failed or interrupted install keeps your answers for the re-run.
  - Fixed: re-running the wizard failed on the VLANs the script had added ("not on this VM yet"), and would have dropped the untagged address it had added. They are now kept and still managed by the script.

## 1.4.1 (11/5/2026): many VLANs, any subnet size, list profiles
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **`deploy_multi_pi.sh` 1.0.0 → 1.1.0**:
  - Finds the trunk behind a VLAN default route (`vlan200@ens18` → `ens18`). VLAN interfaces that already exist are offered and kept as is.
  - The untagged VLAN can get a new address when the VM has none there. Any number of new tagged VLANs.
  - Any prefix from /8 to /30, with clear errors for a network or broadcast address, overlaps, and VLANs that already exist. Warns when a subnet overlaps another route (e.g. Docker).
  - List profile per VLAN (`none`/`iot`/`kids`/`guest`/own). `dns-only` is refused only on the management interface (default route / SSH session). `Default` is refused as a name.
  - Fixed: the questions for existing VLANs read the interface list instead of your answers.
- **`upsert_vlan_groups.py` 1.0.0 → 1.1.0**: `Name=subnet@profile`, so several VLANs can share a list set. Refuses `Default`.
- **New `group_kids_blocklists.txt`, `group_guest_blocklists.txt` 0.1.0** (HaGeZi, checked for HTTP 200).
- **Tested**: Ubuntu 24.04 test VM shaped like a real one (trunk with no IPv4, existing `vlan200` management VLAN, 5 VLANs including a /23). Covered the wizard with bad answers, `netplan generate`, apply and re-run. On live Pi-hole v6: 5 groups; shared lists applied to IoT, Kids and Guest; 0 changes on re-run.

## 1.4.0 (11/5/2026): one Pi-hole for several VLANs
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **New `deploy_multi_pi.sh` 1.0.0**: one Pi-hole serving every VLAN of a trunk (Proxmox or VMware VM).
  - Asks for the trunk NIC and each VLAN (ID, name, this VM's IP/prefix, `dns-only`/`full`, router) and the alert webhook. Re-runs offer the saved setup. `VLANS=...` skips the questions; `DRY_RUN=true` previews.
  - Detects the hypervisor and prints the Proxmox or VMware settings.
  - Adds netplan VLAN interfaces, and re-applies when an interface is missing. Then runs `install_pihole.sh` and creates a group per VLAN.
  - `dns-only` firewall (INPUT and DOCKER-USER chains, IPv6 off) for restricted VLANs.
  - Per-VLAN reverse lookups, so reports show device names.
  - `dns-vlan-report`, alerts every 15 minutes (journal + webhook), daily group re-sync.
- **New `upsert_vlan_groups.py` 1.0.0**: group + subnet client per VLAN, and per-group lists from `group_<name>_*.txt` (+ `.local.txt`).
  - Idempotent; prunes only its own entries and clients. Skips lists already in Default.
  - Runs gravity only when lists were added.
- **New `vlan_report.py` 1.0.0**: per-VLAN and per-device report and alerts. It covers threat-list and bypass hits (classified via `/api/search`), NXDOMAIN rate, query rate, blocked % and rate-limit events.
  - Per-VLAN thresholds; alerts are not repeated within 6 hours.
  - Handles a quirk of Pi-hole's long-term `top_clients` endpoint: with `blocked=false` it counts permitted queries only.
- **New `group_iot_blocklists.txt` / `group_iot_regex_deny.txt` 0.1.0**: 16 HaGeZi lists (all checked for HTTP 200, 647k domains in total) plus 4 regexes, for the IoT group only.
- **`mcp_server.py` 1.0.0 → 1.1.0**: new tools `pihole_vlan_report`, `pihole_client_report` and `pihole_groups`. `pihole_top` notes the permitted-only quirk.
- **`pihole_api.py` → 1.1.0**: also reads `managed_pihole.local.conf`, and `ALERT_*` / `MCP_*` / `THREAT_*` / `BYPASS_*` environment variables.
- **`install_pihole.sh`**: MCP files include `vlan_report.py`. **`update_lists.sh`**: downloads the new files. **CI**: `deploy_multi_pi.sh` syntax check.
- **Tested**:
  - Pi-hole v6 with two subnets as VLANs: IoT-only blocks applied to IoT only, and a per-VLAN allow worked. The second run made 0 changes; prune worked.
  - Ubuntu 24.04 test VM, real `netplan generate` and iptables, live Pi-hole: interactive setup, a trunk with a tagged VLAN 666 device and an untagged device. From the IoT VLAN, DNS and ping work and TCP is dropped; from Users everything works. Re-runs were idempotent.

## 1.3.0 (11/5/2026): MCP server for AI agents
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **New `mcp_server.py` 1.0.0**: a read-only MCP server (stdio, Python standard library only) with 17 tools for Pi-hole v6, AdGuard Home and Unbound metrics.
  - Covers summary, top domains/clients/upstreams, history, query log, "why is this blocked", system info and lists.
  - Pi-hole long-term stats via `hours`.
  - Reuses `pihole_api.py` and the `upsert_adguardhome.py` client. Logs out of Pi-hole on exit (including SIGTERM), so no API sessions leak.
  - Tested against Pi-hole v6 (core 6.5 / FTL 6.8), AdGuard Home v0.107.80 and Unbound 1.26.2 (klutchell/unbound image and Debian package).
- **`install_pihole.sh` 6.3.0 → 6.4.0**: sets up the MCP server automatically (`ENABLE_MCP=true` by default).
  - Creates a locked system user `dnsmcp`. Its SSH keys can only start `mcp_server.py` (forced command plus `restrict`).
  - Pi-hole gets its own app password, which cannot change settings. Re-runs keep it.
  - Sudo rule for exactly `docker exec unbound unbound-control stats_noreset` / `status`.
  - New `pihole-maint.sh mcp` and `mcp-add-key KEY|FILE`. The daily job refreshes the MCP files.
  - Tested end to end on Ubuntu 24.04 with a live Pi-hole: an SSH forced-command session returned stats, and a requested shell command was ignored. `dnsmcp` cannot read secrets or run other sudo commands. The app password gets HTTP 403 on config changes. No API sessions leak across re-runs.
- **`setup_unbound.sh` 1.0.0 → 1.1.0**: `extended-statistics: yes`. `unbound-control` on `/run/unbound.ctl` unless remote-control is already enabled; Debian's package already does it.
- **`install_pihole.sh` 6.2.0 → 6.3.0**: Unbound container gets `extended-statistics` and `unbound-control` on 127.0.0.1 inside the container. No port is published.
- **`pihole_api.py`**: `load_settings()` also reads `UNBOUND_CONTROL`, `UNBOUND_CONTAINER`, `MCP_SERVICES`.
- **`update_lists.sh`**: also downloads `mcp_server.py`.
- **`managed_pihole.conf.example` 1.3.0**: MCP settings.

## 1.2.0 (11/5/2026): import everything automatically + repo housekeeping
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **`install_pihole.sh` 6.1.0 → 6.2.0**: imports and configures **all** managed lists automatically.
  - No more prompt (`IMPORT_LISTS=false` to skip).
  - Pi-hole now also gets the excluded domains (`webserver.api.excludeDomains`).
  - Social regexes are now enabled and assigned only to group `Allow_Social`.
  - New `SOCIAL_CLIENTS` setting. Pi-hole adds those devices to Default + `Allow_Social`; AdGuard Home gets `--social-clients`.
  - Tested against a live Pi-hole v6 container: 70 lists, 173 exact allow, 14 DoH deny, 28 regex deny, 15 regex allow (11 in `Allow_Social`), 181 excluded domains.
- **`cgray_blocklists.txt` 0.6.0 → 0.6.1**: also subscribes `url_general_blocklist.txt`, `cgray_religion_school.txt` and `toolz_adblock_test.txt` from this repo.
- **New repo files**:
  - `.gitignore`: keeps secrets, backups, exports and installer data out of git.
  - `.gitattributes`: forces LF endings, since CRLF breaks the scripts.
  - `.editorconfig`.
  - `managed_pihole.conf.example`.
  - `CHANGELOG.md`: moved here from the README.
  - `CONTRIBUTING.md` and `SECURITY.md`.
  - `.github/workflows/lint.yml`: gitleaks secret scan (full history), shell and Python syntax, ShellCheck, CRLF and list-URL checks.
  - `.gitleaks.toml`: secret-scanner config. It allowlists only DNSCrypt's public minisign key.
  - Secret audit before going public: no passwords, keys or tokens in the working tree or in any of the 134 commits (gitleaks + manual scan).

## 1.1.0 (11/5/2026): AdGuard Home + Unbound
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

- **New `upsert_adguardhome.py`**: applies all managed lists to AdGuard Home through its REST API, natively or in Docker. It handles block lists (pruning ones removed from the file), the regex/exact rules in a marked block, client-scoped social rules, optional DoH blocking, ignored domains, an optional upstream, and filter refresh. Tested against AdGuard Home v0.107.80.
- **New `setup_unbound.sh`**: native Unbound following the Pi-hole guide (port 5335, DNSSEC trust anchor, Debian resolvconf fix, rmem_max), then sets the Pi-hole or AdGuard Home upstream.
- **`install_pihole.sh` 6.0.0 → 6.1.0**:
  - New `DNS_FILTER=pihole|adguardhome`: AdGuard Home runs behind the same Unbound/dnscrypt-proxy, its wizard is completed automatically, and the daily sync uses `upsert_adguardhome.py`.
  - Fixed: the exact-allowlist sync now reads the v6 `allow …` lines.
  - The Pi-hole output is unchanged (rendered compose file identical).
- **`update_lists.sh`**: `DNS_FILTER=adguardhome` path. Also downloads the new files.
- **`upsert_lists.py`**:
  - Re-runs only send new entries.
  - Lists it added that were removed from the file are now deleted (`--no-prune` to keep them).
  - Excluded domains fall back to `pihole-FTL --config` when an API session is not allowed to change config.
- **`cgray_blocklists.txt`**: URLhaus disabled too (HTTP 410 in gravity).

## 1.0.0 (11/5/2026): Pi-hole v6 + Docker support
Updated by **Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)**.

**General**
- All scripts work with Pi-hole v6 on a native install **and** in Docker (new `pihole_common.sh`, new `pihole_api.py`).
- List management uses the Pi-hole v6 REST API instead of writing `gravity.db` directly, so pihole-FTL no longer has to be stopped.
- Every file now has a version, date, "Updated by" line and changelog.
- `initial_setup.sh` / `initial_setup.py` are no longer referenced (removed from the repo). They relied on v5-only features: `setupVars.conf`, `pihole -a`.

**update_lists.sh** (0.5.11 → 1.0.0)
- Fixed: the script deleted and re-downloaded itself while running. Downloads now go to a temp folder and are moved into place only if they succeed.
- Fixed: the backup only ran if the backup folder already existed, and copied v5-only files. It now runs `backup_dbs.py`.
- Replaced the `API_EXCLUDE_DOMAINS` edit of `setupVars.conf` (gone in v6) with `webserver.api.excludeDomains`, set by `upsert_lists.py`.
- Docker: updates by pulling the image (`PIHOLE_COMPOSE_DIR`), never with `pihole -up`.
- Removed copies into `/root`, `chown pihole:www-data` (no lighttpd in v6), and downloads of the deleted initial_setup files.
- Internet check falls back to HTTPS when ping is blocked. Uses `printf` instead of `echo "\r\n"`. Only clears the screen when interactive. Added `SKIP_*` switches.

**upsert_lists.py** (0.0.43 → 1.0.0)
- Rewritten to use the v6 API.
- Fixed: regex allow entries were stored with type and enabled swapped (type 0 = exact allow), so they never matched.
- Fixed: social-media regexes were applied to everyone. They now apply only to group `Allow_Social`.
- Fixed: `except Error` NameError and a no-op `quit` on database errors.
- New: converts excluded domains to v6 regex format and saves them. New options `--dry-run`, `--no-gravity`, `--skip-exclude`, `--dir`.
- Removed: `pihole -up`, log deletion (moved to `cleanup.sh`), `pihole restartdns reload-lists` (gone in v6), `pihole -v -c` (`-c` is now chronometer).

**pihole_allowlist.sh** (0.0.41 → 1.0.0)
- `pihole -w` (removed in v6) replaced by `pihole allow` through an `allow()` helper that also handles Docker and adds a comment to each entry.
- Fixed: three Windows Defender domains were bare lines that the shell tried to run as commands.

**backup_dbs.py** (0.0.1 → 1.0.0)
- Fixed: it could not run at all (syntax error, missing `import shutil`).
- New: Teleporter export through the API. Consistent SQLite online backups. Timestamps, `--keep`, `--dest`, `--pihole-dir`.

**export_custom_lists.sh** (0.0.1 → 1.0.0)
- Docker support. Opens the database read-only. Also exports subscribed block and allow lists. Optional output folder.

**cleanup.sh** (0.0.1 → 1.0.0)
- Fixed: a blank first line broke the `#!/bin/sh` shebang.
- Uses the v6 log paths (`/var/log/pihole/`). `pihole -v -c` changed to `pihole -v`. Removed `pihole -up` and the needless FTL start. Docker support.

**cgray_blocklists.txt** (0.5.5 → 0.6.0)
- Added the 6 missing Firebog "ticked" lists (https://v.firebog.net/hosts/lists.php?type=tick): KADhosts, w3kbl, Admiral, Prigent-Crypto, stalkerware-indicators, cyberhost malware. The other 19 were already present.
- Disabled lists that no longer download: CoinBlockerLists ×2 (HTTP 403) and osint.digitalside.it (no response).

**Other list files**
- `allowlist_regexs_cg.txt`, `allow_regex_social_cg.txt`, `blocklist_regexs_cg.txt`: headers and changelog added. No regex changes; they are now imported correctly (see upsert_lists.py).
- `pihole_exclude_list.txt`: header added (comments are now allowed). Fixed typo `*.playlstation.net` → `*.playstation.net`.
- `cgray_chat/games/social/religion_school.txt`, `url_general_blocklist.txt`, `doh_servers.txt`, `toolz_adblock_test.txt`: reviewed for v6. Version and changelog headers added. No domain changes.
