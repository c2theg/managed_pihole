# managed_pihole

Managed block/allow lists and maintenance scripts for **Pi-hole v6** or **AdGuard Home**, with **Unbound** as the recursive, DNSSEC-validating upstream. Each one works on a **native OS install** or in **Docker**.

- **Version:** 1.2.0
- **Last updated:** 11/5/2026
- **Updated by:** Claude Code (Anthropic), model Claude Opus 5.5 (`claude-opus-5-5`)
- **Pi-hole docs:** https://docs.pi-hole.net/main/post-install/

> Version 1.0.0 needs Pi-hole v6 (released Feb 2025). Pi-hole v5 is no longer supported by these scripts. The last v5 versions are in git history.

---

## What's here

| File | Version | What it does |
|---|---|---|
| `update_lists.sh` | 1.0.0 | Main job: OS update → backup → download latest files → update Pi-hole → allow list → block lists + gravity |
| `upsert_lists.py` | 1.0.0 | Adds block lists, regex allow/deny, excluded domains through the v6 API, then runs gravity |
| `pihole_allowlist.sh` | 1.0.0 | Exact **allow** domains (`pihole allow …`) |
| `backup_dbs.py` | 1.0.0 | Teleporter backup (.zip) + gzip'd copies of `gravity.db` / `pihole-FTL.db` |
| `export_custom_lists.sh` | 1.0.0 | Exports your custom domains and subscribed lists to text files |
| `cleanup.sh` | 1.0.0 | Deletes rotated logs, flushes the query log |
| `pihole_common.sh` | 1.0.0 | *New.* Shared shell helpers: detects native vs Docker |
| `pihole_api.py` | 1.0.0 | *New.* Small Pi-hole v6 REST API client (Python standard library only) |
| `upsert_adguardhome.py` | 1.0.0 | *New.* Applies the same lists to **AdGuard Home** through its API (native or Docker) |
| `setup_unbound.sh` | 1.0.0 | *New.* Native **Unbound** on 127.0.0.1:5335 (Pi-hole guide), then points Pi-hole or AdGuard Home at it |
| `install_pihole.sh` | 6.2.0 | Docker stack installer: Pi-hole **or** AdGuard Home → Unbound → dnscrypt-proxy (+ WireGuard), with daily list sync |
| `cgray_blocklists.txt` | 0.6.1 | Subscribed block-list URLs: all Firebog "ticked" lists plus every list in this repo |
| `blocklist_regexs_cg.txt` | 0.1.0 | Regex deny |
| `allowlist_regexs_cg.txt` | 0.1.0 | Regex allow (everyone) |
| `allow_regex_social_cg.txt` | 0.1.0 | Regex allow for social media, **only** for clients in group `Allow_Social` |
| `pihole_exclude_list.txt` | 0.1.0 | Domains hidden from dashboard top lists / query log |
| `cgray_chat.txt`, `cgray_games.txt`, `cgray_social.txt`, `cgray_religion_school.txt` | — | Personal block lists, subscribed by raw GitHub URL |
| `url_general_blocklist.txt`, `toolz_adblock_test.txt` | 0.1.0 | Extra block lists (subscribed via `cgray_blocklists.txt`) |
| `doh_servers.txt` | 0.1.0 | Public DoH servers (blocked by `install_pihole.sh` / `--block-doh`) |
| `managed_pihole.conf.example` | 1.2.0 | Settings template, copy to `/etc/managed_pihole.conf` |

Every script and list file has a header with its version, date, the AI agent that updated it, and a changelog.

---

## Install Pi-hole v6

### Option A: native OS install (Raspberry Pi OS, Debian, Ubuntu, Fedora …)

```sh
sudo raspi-config                 # Raspberry Pi only: set locale, hostname, etc.
curl -sSL https://install.pi-hole.net | bash
sudo pihole setpassword           # set the web / API password
```

### Option B: Docker

`docker-compose.yml` (from https://docs.pi-hole.net/docker/):

```yaml
services:
  pihole:
    container_name: pihole
    image: pihole/pihole:latest
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "8080:80/tcp"        # web UI + API -> http://<host>:8080/admin
      - "8443:443/tcp"
    environment:
      TZ: 'America/New_York'
      FTLCONF_webserver_api_password: 'change me'
      FTLCONF_dns_listeningMode: 'ALL'
    volumes:
      - './etc-pihole:/etc/pihole'
    restart: unless-stopped
```

```sh
docker compose up -d
```

> Any setting you put in the compose file as `FTLCONF_…` becomes **read-only** in Pi-hole. If you set `FTLCONF_webserver_api_excludeDomains` there, `upsert_lists.py` cannot change it. It prints the value to paste into your compose file instead.

---

### Option C: Docker stack with Unbound (Pi-hole or AdGuard Home)

`install_pihole.sh` (Ubuntu) builds the whole stack in `/opt/pihole`: filter → Unbound (DNSSEC, cache) → dnscrypt-proxy (DoH/ODoH), optional WireGuard, plus systemd timers for the daily list sync and weekly updates.

```sh
sudo bash install_pihole.sh                              # asks: Pi-hole or AdGuard Home
sudo DNS_FILTER=adguardhome bash install_pihole.sh
sudo SOCIAL_CLIENTS="192.168.0.50 kid-laptop" bash install_pihole.sh   # who may use social media
sudo /opt/pihole/pihole-maint.sh status
```

All managed lists are imported and configured automatically, with no prompt (`IMPORT_LISTS=false` to skip), and re-synced every day. This covers block lists, regex deny/allow, exact allows, excluded domains, DoH-bypass blocking, and the `Allow_Social` group with `SOCIAL_CLIENTS`.

For AdGuard Home, the installer completes the first-run wizard for you. It logs in as user `admin` with the generated password in `/opt/pihole/secrets/pihole_password.txt`, and sets Unbound as the upstream.

### Unbound on a native install

```sh
sudo ./setup_unbound.sh                                  # finds Pi-hole / AdGuard Home
sudo DNS_FILTER=adguardhome ADGUARD_PASSWORD=xxx ./setup_unbound.sh
```

Unbound listens on `127.0.0.1:5335`. Pi-hole is set to `dns.upstreams = ["127.0.0.1#5335"]`, with DNSSEC validation left to Unbound. AdGuard Home's upstream is set to `127.0.0.1:5335`.

### AdGuard Home (native or Docker)

Install AdGuard Home (https://github.com/AdguardTeam/AdGuardHome#getting-started) and finish its setup wizard. Then:

```sh
ADGUARD_URL=http://127.0.0.1 ADGUARD_PASSWORD=xxx ./upsert_adguardhome.py --dry-run
ADGUARD_PASSWORD=xxx ./upsert_adguardhome.py --upstream 127.0.0.1:5335   # + use Unbound
```

Or put `DNS_FILTER=adguardhome`, `ADGUARD_URL`, `ADGUARD_USER` and `ADGUARD_PASSWORD` in `/etc/managed_pihole.conf` and use `update_lists.sh` / cron as below.

How the lists map to AdGuard Home:

| managed file | Pi-hole v6 | AdGuard Home |
|---|---|---|
| `cgray_blocklists.txt` | Lists (block) | Filters › DNS blocklists (`managed_pihole: …`) |
| `blocklist_regexs_cg.txt` | Regex deny | custom rule `/regex/` |
| `allowlist_regexs_cg.txt` | Regex allow | custom rule `@@/regex/` |
| `allow_regex_social_cg.txt` | Regex allow, group `Allow_Social` | `@@/regex/$client='…'`, only with `--social-clients "name\|ip"` |
| `pihole_allowlist.sh` | Exact allow | custom rule `@@\|domain^` |
| `doh_servers.txt` | (installer: deny) | `\|\|domain^` with `--block-doh` |
| `pihole_exclude_list.txt` | `webserver.api.excludeDomains` | Query log + statistics "ignored" |

Custom rules go between `! managed_pihole BEGIN/END` markers. Rules you add yourself are kept.

---

## Install managed_pihole

The Python tools run on the **host**, because the Pi-hole Docker image has no Python. You need `python3`, which is already present on Raspberry Pi OS, Debian and Ubuntu.

```sh
sudo mkdir -p /opt/managed_pihole && cd /opt/managed_pihole
for f in update_lists.sh pihole_common.sh pihole_api.py; do
  sudo wget -q https://raw.githubusercontent.com/c2theg/managed_pihole/main/$f
done
sudo chmod +x *.sh *.py
sudo ./update_lists.sh            # downloads everything else and applies it
```

You can `git clone https://github.com/c2theg/managed_pihole.git /opt/managed_pihole` instead. In that case run `SKIP_DOWNLOAD=1 ./update_lists.sh` and update with `git pull`.

### Settings

Copy [`managed_pihole.conf.example`](managed_pihole.conf.example) to `/etc/managed_pihole.conf` (it's in `.gitignore` if kept in the repo folder). Settings are optional on a native install. Docker installs usually need some. Put them in `/etc/managed_pihole.conf` (or `managed_pihole.conf` next to the scripts), or export them as environment variables:

```sh
# /etc/managed_pihole.conf
PIHOLE_MODE=docker                       # auto (default) | native | docker
PIHOLE_CONTAINER=pihole                  # docker container name
PIHOLE_COMPOSE_DIR=/opt/pihole           # folder with docker-compose.yml (to upgrade the image)
PIHOLE_API_URL=http://127.0.0.1:8080/api # default: auto-detect on ports 80, 8080, 443
PIHOLE_DIR=/opt/pihole/etc-pihole        # host path of /etc/pihole (docker volume), for backups
#PIHOLE_PASSWORD=xxxxx                   # web password or an app password
```

How the tools sign in to the v6 API, in order:

1. `PIHOLE_PASSWORD`
2. Pi-hole's CLI password file `/etc/pihole/cli_pw` (native, as root)
3. The same file read with `docker exec` (Docker)

For a remote Pi-hole, create an **app password** in the web UI (Settings › Web interface / API) and use it as `PIHOLE_PASSWORD`.

Other switches for `update_lists.sh`: `SKIP_OS_UPDATE=1`, `SKIP_DOWNLOAD=1`, `SKIP_PIHOLE_UPDATE=1`, `MANAGED_PIHOLE_REPO=<raw url>`.

---

## Usage

```sh
sudo /opt/managed_pihole/update_lists.sh            # everything
sudo /opt/managed_pihole/upsert_lists.py --dry-run  # preview list changes
sudo /opt/managed_pihole/upsert_lists.py --no-gravity
sudo /opt/managed_pihole/backup_dbs.py --dest /mnt/usb/pihole --keep 14
/opt/managed_pihole/export_custom_lists.sh ./export
sudo /opt/managed_pihole/cleanup.sh
```

**Social media group:** the regexes in `allow_regex_social_cg.txt` are added to a group called `Allow_Social`, which is created automatically. In the web UI go to **Group Management › Clients** and add the devices that may use social media to that group.

### Pi-hole v6 command cheat-sheet (v5 → v6)

| v5 | v6 |
|---|---|
| `pihole -w example.com` | `pihole allow example.com` |
| `pihole -b example.com` | `pihole deny example.com` |
| `pihole --white-regex '…'` | `pihole --allow-regex '…'` |
| `pihole --white-wild example.com` | `pihole --allow-wild example.com` |
| `pihole restartdns reload-lists` | `pihole reloadlists` |
| `pihole -a …` | removed; use the web UI, `pihole-FTL --config …`, or the API |
| `/etc/pihole/setupVars.conf` | `/etc/pihole/pihole.toml` (`pihole-FTL --config <key> <value>`) |
| `/var/log/pihole.log`, `/var/log/pihole-FTL.log` | `/var/log/pihole/pihole.log`, `/var/log/pihole/FTL.log` |

On Docker, prefix commands with `docker exec pihole`, e.g. `docker exec pihole pihole allow example.com`. Don't run `pihole -up` inside the container. Update by pulling the new image: `docker compose pull && docker compose up -d`.

---

## Cron

Native install (`sudo crontab -e`):

```cron
# Full managed update every day at 04:20
20 4 * * * /opt/managed_pihole/update_lists.sh > /var/log/update_lists.log 2>&1

# Update gravity 5 min past every hour
5 * * * * pihole -g

# ...or only during business hours (07:05-19:05, Mon-Fri)
5 7-19 * * 1-5 pihole -g

# Weekly log cleanup, Sunday 03:30
30 3 * * 0 /opt/managed_pihole/cleanup.sh > /var/log/pihole_cleanup.log 2>&1
```

Docker host: use the same `update_lists.sh` line (with `/etc/managed_pihole.conf` set up). For gravity use `docker exec pihole pihole -g`.

Pi-hole v6 also updates gravity by itself once a week (native: `/etc/cron.d/pihole`).

---

## Other setup (external scripts, not part of this repo and not reviewed for v6)

- Static IP: https://raw.githubusercontent.com/c2theg/srvBuilds/master/configs/01-netcfg.yaml → `/etc/netplan/00-installer-config.yaml`
- DoH on Pi-hole: https://raw.githubusercontent.com/c2theg/srvBuilds/master/install_doh_pihole.sh
- OpenDNS account, linux updater: https://raw.githubusercontent.com/c2theg/srvBuilds/master/raspi/install_opendns.sh

---

## Contributing, security, license

- Changes and version history: [CHANGELOG.md](CHANGELOG.md)
- How to add lists or change scripts: [CONTRIBUTING.md](CONTRIBUTING.md)
- Reporting a security problem: [SECURITY.md](SECURITY.md)
- License: [LICENSE](LICENSE)
