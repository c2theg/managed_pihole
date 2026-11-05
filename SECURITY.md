# Security

## Reporting a problem

Please **do not open a public issue** for security problems, such as a way to bypass filtering, leaked credentials, or a script that could run injected input.
Contact the maintainer through GitHub (https://github.com/c2theg) and include steps to reproduce.

## Safe use

- Keep `/etc/managed_pihole.conf` private (`chmod 600`). It can hold your Pi-hole / AdGuard Home password. Prefer a Pi-hole **app password** for remote use.
- The scripts download lists and their own updates from `raw.githubusercontent.com/c2theg/managed_pihole`. Point `MANAGED_PIHOLE_REPO` / `MANAGED_REPO_RAW` at your own fork if you want to review changes before they reach your network.
- Never expose port 53 or the web UI to the internet. Open resolvers get abused, and Docker port publishing bypasses `ufw`.
- Teleporter backups (`pihole-teleporter_*.zip`) contain password hashes. Store them like secrets.
