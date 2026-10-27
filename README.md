# NOVA THEME Platform (starter release)

A Flask-based license portal and theme editor for Pterodactyl Panel 1.12.x + Blueprint.

## Included
- Customer registration/login and email verification (SMTP)
- Admin dashboard for issuing/revoking/renewing licenses; choose validity in days or an exact expiry date
- One-domain license binding and server-side validation
- Customer theme editor with live preview and saved settings
- Customer API-key manager (create/revoke; key shown once and stored hashed)
- Authenticated `GET /api/v1/me` and `GET /api/v1/theme` endpoints
- CLI installer that asks for email, license key and panel domain, validates with this website, downloads a generated Blueprint `.blueprint` package, then invokes Blueprint
- Starter Blueprint theme package template for client/admin CSS

## Compatibility notes
- Target is Pterodactyl Panel **1.12.x** and a Blueprint release compatible with 1.12.x. Blueprint's compatibility notice says v1.12.0 support was added in beta-2026-01; verify your installed Blueprint version before installing.
- This project generates a Blueprint package using `conf.yml` bindings for `dashboard.css` and `admin.css`. Blueprint packaging/export internals can vary by Blueprint release. Test on a staging panel and run `blueprint -remove novatheme` to roll back.
- This is a starter implementation, not a security-audited commercial license platform. Before selling licenses, add rate limiting, HTTPS, email provider configuration, backups, monitoring, and external security review.
- CSS can restyle existing panel components; it does not provide a full React component replacement for every dashboard feature. Login selectors and card selectors can vary by panel frontend build.

## 1. Deploy the website on Ubuntu VPS
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
mkdir -p /opt/nova-theme
# Upload/extract this folder into /opt/nova-theme
cd /opt/nova-theme
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
```
Set a long random `SECRET_KEY`, a strong `ADMIN_PASSWORD`, your real `BASE_URL`, and working SMTP credentials. `ADMIN_EMAIL` and `ADMIN_PASSWORD` create the first admin account only when the database is empty. Never expose this service over plain HTTP in production.

For a quick test:
```bash
set -a; . ./.env; set +a
python app.py
```
Production should run behind Nginx/Caddy with HTTPS and a process manager, e.g.:
```bash
gunicorn --workers 2 --bind 127.0.0.1:8080 app:app
```
Configure your reverse proxy to forward to `127.0.0.1:8080`. Do not expose port 8080 publicly.

## 2. Create a systemd service
Create `/etc/systemd/system/nova-theme.service`:
```ini
[Unit]
Description=NOVA Theme License Portal
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/nova-theme
EnvironmentFile=/opt/nova-theme/.env
ExecStart=/opt/nova-theme/.venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8080 app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```
Give `/opt/nova-theme` ownership to the service user (ensure the `.env` file remains private), then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nova-theme
sudo systemctl status nova-theme
```

## 3. Use the portal
- Open your HTTPS `BASE_URL`.
- Register a customer and verify their email from the email link.
- Log in with the bootstrap admin credentials and issue a license from Admin.
- Customers can edit their own theme settings; those settings are used when the installer downloads a package for that customer's license.
- Admin can choose an exact license expiry date; it overrides days and remains valid through 23:59:59 UTC on that date.
- Customers can create API keys in Dashboard → Bot API keys. Send `Authorization: Bearer <API_KEY>` to `/api/v1/me` or `/api/v1/theme`. Keys are stored as SHA-256 hashes and shown only once.
- API keys authenticate integrations to this website; they do not themselves run or host a Discord bot. Host the bot separately and keep the key in a server-side environment variable.

## 4. Install on the Pterodactyl host
First back up your panel files/database and verify Blueprint is installed and compatible. Do not run an installer from an untrusted host.
```bash
cd /var/www/pterodactyl
blueprint -v
```
Copy `installer/nova-install.py` to the panel server, then run:
```bash
python3 nova-install.py --api https://nova.example.com
```
The installer prompts for the verified account email, license key, and panel domain. It will validate the license, bind it to the first domain activation, download the generated `.blueprint` file, and run `blueprint -install` only after validation succeeds. Replace `https://nova.example.com` with your actual portal domain.
- Use the panel hostname only, e.g. `panel.example.com`, not `https://panel.example.com/path`.
- The install command needs privileges to write into the panel directory. Run it as the same privileged account you use for Blueprint, from a trusted copy of the installer.
- It never asks for your Pterodactyl admin password or API key.

## 5. Theme editing
In the portal, customers can edit the primary accent color, background, card radius, glow, animations, and cursor style. Use Preview before saving. A new install/download uses the saved settings. To apply changes to an already installed theme, download the updated package and run the Blueprint update/install workflow supported by your installed Blueprint release; safest fallback is remove then install after a backup.

## 6. API key example
```bash
curl -H 'Authorization: Bearer nova_sk_YOUR_KEY' https://nova.example.com/api/v1/me
curl -H 'Authorization: Bearer nova_sk_YOUR_KEY' https://nova.example.com/api/v1/theme
```
Never place API keys in browser JavaScript, public repositories, or Discord messages.

## 7. Security checklist before commercial use
- HTTPS only; use a valid certificate.
- Set SMTP credentials and `DEV_SHOW_VERIFICATION_LINKS=false`.
- Change bootstrap admin password immediately.
- Restrict admin access and add MFA before public launch.
- Add request rate limits and reverse-proxy limits before opening registrations.
- Back up the SQLite DB; migrate to PostgreSQL/MySQL for larger scale.
- Consider signed package manifests, revocation grace policy, license activation audit logs and support workflow.
- Do not put portal API secrets inside public theme assets.
