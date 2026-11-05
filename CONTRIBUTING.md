# Contributing to managed_pihole

Thanks for helping. A few rules keep the lists and scripts working for everyone,
on Pi-hole v6 and AdGuard Home, native installs and Docker.

## Adding or removing lists

| To… | Edit | Format |
|---|---|---|
| subscribe a block list | `cgray_blocklists.txt` | one `https://` URL per line |
| block domains by pattern | `blocklist_regexs_cg.txt` | one regex per line (Pi-hole POSIX ERE, also valid in AdGuard Home) |
| allow domains by pattern | `allowlist_regexs_cg.txt` | one regex per line |
| allow social media for selected clients | `allow_regex_social_cg.txt` | one regex per line |
| allow exact domains | `pihole_allowlist.sh` | `allow domain1 domain2 ...` |
| hide domains from dashboards | `pihole_exclude_list.txt` | `example.com` or `*.example.com` |

- Lines starting with `#` are comments, so explain *why* a domain is there.
- Before adding a URL, check that it downloads: `curl -fsSL -o /dev/null -w '%{http_code}\n' <url>`.
- Dead lists: comment them out with a dated note, e.g. `# DISABLED 11/5/2026 (HTTP 410): <url>`.

## Changing scripts

- Keep them dependency-free: POSIX `sh` / `bash`, and Python 3 **standard library only**. The Pi-hole Docker image has no Python, so the Python tools run on the host.
- Everything has to work on **native and Docker** installs. Use the helpers in `pihole_common.sh` (`ph`, `ph_ftl`, `ph_sh`) instead of calling `pihole` directly.
- Prefer the Pi-hole v6 / AdGuard Home **APIs** over editing databases or config files.
- Test with `--dry-run` first (`upsert_lists.py`, `upsert_adguardhome.py`). A throwaway container makes a good test target:
  ```sh
  docker run -d --name ph-test -p 18080:80 -e FTLCONF_webserver_api_password=test pihole/pihole:latest
  PIHOLE_MODE=docker PIHOLE_CONTAINER=ph-test PIHOLE_API_URL=http://127.0.0.1:18080/api ./upsert_lists.py --dry-run
  ```

## Versions and changelog

Every script and list file has a header with **Version**, **Last Updated**, **Updated by** and a **ChangeLog**. When you change a file:

1. Bump its version: patch = data/small fix, minor = new feature, major = breaking change.
2. Add a dated changelog line to the file header, naming the person or AI agent that made the change.
3. Add a summary to [CHANGELOG.md](CHANGELOG.md).

## Pull requests

- One topic per pull request. Say which filter / install type you tested (e.g. "Pi-hole v6.5 Docker").
- The `lint` GitHub Action must pass: shell and Python syntax, ShellCheck errors, LF line endings, list URL format.
- Never commit passwords, `managed_pihole.conf`, backups or Teleporter archives (see `.gitignore`). **This repo is public.**
- Check for secrets before you push. The `lint` workflow runs the same scan on every push:
  ```sh
  docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.18.4 detect --source /repo --config /repo/.gitleaks.toml --redact
  ```
- Use placeholders in docs and examples (`xxx`, `change me`), never real IPs, client names or passwords from your network.
