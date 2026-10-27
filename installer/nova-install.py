#!/usr/bin/env python3
"""NOVA THEME license-aware Blueprint installer for Pterodactyl Panel 1.12.x."""
import argparse, getpass, json, os, pathlib, re, subprocess, sys, tempfile, urllib.request, urllib.error, shutil

def request_json(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json","User-Agent":"NOVA-Theme-Installer/1.0"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()

def main():
    parser = argparse.ArgumentParser(description="Validate NOVA license and install theme with Blueprint.")
    parser.add_argument("--api", required=True, help="NOVA portal base URL, e.g. https://nova.example.com")
    parser.add_argument("--panel-dir", default="/var/www/pterodactyl", help="Pterodactyl panel root")
    args = parser.parse_args()
    api = args.api.rstrip("/")
    if not api.startswith("https://"):
        print("ERROR: Use HTTPS for the license portal.", file=sys.stderr); return 2
    panel_dir = pathlib.Path(args.panel_dir).resolve()
    if not (panel_dir / "artisan").is_file():
        print(f"ERROR: {panel_dir} does not look like a Pterodactyl panel root (artisan missing).", file=sys.stderr); return 2
    email = input("NOVA account email: ").strip().lower()
    license_key = getpass.getpass("NOVA license key (input hidden): ").strip()
    domain = input("Panel domain (e.g. panel.example.com): ").strip().lower()
    payload = {"email": email, "license": license_key, "domain": domain}
    status, headers, body = request_json(api + "/api/license/validate", payload)
    try: result = json.loads(body.decode())
    except Exception: result = {"ok": False, "error": f"Portal returned unexpected response (HTTP {status})."}
    if status != 200 or not result.get("ok"):
        print("LICENSE CHECK FAILED:", result.get("error", f"HTTP {status}")); return 3
    print("License verified. Downloading generated NOVA package…")
    status, headers, body = request_json(api + "/api/installer/package", payload)
    if status != 200 or not body.startswith(b"PK"):
        try: err = json.loads(body.decode()).get("error", "Package download failed.")
        except Exception: err = "Package download failed."
        print("ERROR:", err); return 4
    # Check for Blueprint CLI before writing/installing.
    bp = shutil.which("blueprint")
    if not bp:
        print("ERROR: Blueprint CLI not found in PATH. Install/configure Blueprint first."); return 5
    with tempfile.NamedTemporaryFile(prefix="novatheme-", suffix=".blueprint", dir="/tmp", delete=False) as f:
        f.write(body); package = pathlib.Path(f.name)
    try:
        print(f"Package downloaded ({len(body)} bytes).")
        print("A panel backup is strongly recommended before modifying the live theme.")
        confirm = input(f"Install NOVA THEME into {panel_dir}? [y/N] ").strip().lower()
        if confirm != "y":
            print("Cancelled; no panel changes made."); return 0
        proc = subprocess.run([bp, "-install", str(package)], cwd=str(panel_dir), check=False)
        if proc.returncode != 0:
            print("Blueprint install failed. Review the output above; no success is assumed.")
            return proc.returncode or 6
        print("Blueprint reported installation complete. Reload the panel and verify client/admin pages.")
        print("To remove the theme later: cd", panel_dir, "&& blueprint -remove novatheme")
        return 0
    finally:
        try: package.unlink()
        except OSError: pass

if __name__ == "__main__":
    raise SystemExit(main())
