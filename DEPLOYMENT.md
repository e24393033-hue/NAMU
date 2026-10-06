# NAMU multi-branch deployment

This setup runs one Node process with a persistent SQLite volume behind a TLS reverse proxy. Keep one app instance: login sessions are held in process memory and SQLite is stored on the persistent volume. Do not scale replicas or put the data volume on a network filesystem.

## Requirements

- A Linux server with Docker Compose and a disk encrypted by the hosting provider
- A domain name whose DNS A/AAAA record points to that server
- A TLS reverse proxy such as Caddy on the host, and firewall rules that expose only ports 80 and 443 publicly
- A separate, encrypted off-site backup destination and a scheduled backup/restore process before entering real student information

## Start the app behind HTTPS

1. Copy `.env.example` to `.env` and set `NAMU_ALLOWED_HOSTS` to `localhost,127.0.0.1,your-real-domain.example`.
2. Change `Caddyfile.example` to use that exact domain, then configure it as the host Caddy site. Caddy must forward requests to `127.0.0.1:4173` and preserve the public `Host` header.
3. Run `docker compose up -d --build`. The SQLite file is in the named `namu-data` volume, not in the container layer.
4. Open `https://your-real-domain.example` and create the single owner account. Never publish `.env`, the `data` volume, database files, or `.namu` backups to GitHub.
5. Add branches in **Settings → Branch management**, then create each employee account and assign exactly one branch. Staff see only their assigned branch; the owner can switch among all active branches.

## Operations before live data

- Confirm TLS works and that HTTP redirects to HTTPS at the reverse proxy.
- Check that the provider retains the persistent volume across app rebuilds and restarts.
- Set up daily encrypted off-site backups with a retention policy. Downloading a `.namu` file in the app is a manual backup, not an automatic disaster-recovery plan.
- Perform a restore rehearsal using fictional data and document who can recover the system.
- Review collection purpose, retention/deletion, parent notices and consent handling, staff permissions, breach response, and provider data-processing terms before using student details.

This deployment is a controlled single-instance design for a small academy. It does not provide high availability, multi-factor authentication, automated off-site backups, or automated owner-account recovery. Add those controls and obtain a privacy/security review before treating the service as production-ready.
