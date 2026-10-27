import os, sqlite3, secrets, hashlib, hmac, smtplib, json, re, zipfile, io, time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, request, redirect, url_for, session, flash, render_template, jsonify, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "unsafe-dev-secret-change-me")
DB_PATH = os.environ.get("DATABASE_PATH", "./nova.sqlite3")
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
DEV_SHOW_LINKS = os.environ.get("DEV_SHOW_VERIFICATION_LINKS", "false").lower() == "true"
PRIMARY_DEFAULT = "#f02b43"
BG_DEFAULT = "#0b0b10"

def now():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.isoformat()

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0,
          is_admin INTEGER NOT NULL DEFAULT 0, verify_hash TEXT, verify_expires TEXT,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS licenses(
          id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL,
          key_hint TEXT NOT NULL, email TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
          expires_at TEXT, bound_domain TEXT, created_at TEXT NOT NULL, created_by INTEGER
        );
        CREATE TABLE IF NOT EXISTS themes(
          user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          settings_json TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activations(
          id INTEGER PRIMARY KEY AUTOINCREMENT, license_id INTEGER NOT NULL REFERENCES licenses(id),
          domain TEXT NOT NULL, activated_at TEXT NOT NULL, last_seen TEXT NOT NULL,
          UNIQUE(license_id, domain)
        );
        CREATE TABLE IF NOT EXISTS api_keys(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          key_hash TEXT UNIQUE NOT NULL, key_prefix TEXT NOT NULL, name TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, last_used_at TEXT
        );
        """)
        admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if admin_email and admin_password and not c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            c.execute("INSERT INTO users(email,password_hash,verified,is_admin,created_at) VALUES(?,?,?,?,?)",
                      (admin_email, generate_password_hash(admin_password), 1, 1, iso(now())))

def defaults():
    return {"accent": PRIMARY_DEFAULT, "background": BG_DEFAULT, "radius": 14,
            "glow": True, "animations": True, "cursor": "default"}

def safe_settings(raw):
    d = defaults()
    if isinstance(raw, dict):
        accent = raw.get("accent", d["accent"])
        background = raw.get("background", d["background"])
        if isinstance(accent, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", accent): d["accent"] = accent
        if isinstance(background, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", background): d["background"] = background
        try: d["radius"] = max(0, min(28, int(raw.get("radius", d["radius"]))))
        except (ValueError, TypeError): pass
        d["glow"] = bool(raw.get("glow", d["glow"]))
        d["animations"] = bool(raw.get("animations", d["animations"]))
        if raw.get("cursor") in ("default", "crosshair", "pointer"): d["cursor"] = raw["cursor"]
    return d

def current_user():
    uid = session.get("uid")
    if not uid: return None
    with db() as c: return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not current_user():
            flash("Please sign in first.", "error")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return inner

def admin_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        u = current_user()
        if not u or not u["is_admin"]:
            abort(403)
        return fn(*a, **kw)
    return inner

def send_verification(email, token):
    host = os.environ.get("SMTP_HOST", "").strip()
    link = f"{BASE_URL}/verify/{token}"
    if not host:
        if DEV_SHOW_LINKS:
            app.logger.warning("DEV verification link for %s: %s", email, link)
            return True
        return False
    msg = EmailMessage()
    msg["Subject"] = "Verify your NOVA THEME account"
    msg["From"] = os.environ.get("SMTP_FROM", "NOVA THEME <noreply@example.com>")
    msg["To"] = email
    msg.set_content(f"Welcome to NOVA THEME.\n\nVerify your email using this link (valid for 30 minutes):\n{link}\n")
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            if os.environ.get("SMTP_STARTTLS", "true").lower() == "true":
                s.starttls(); s.ehlo()
            username = os.environ.get("SMTP_USERNAME", "")
            password = os.environ.get("SMTP_PASSWORD", "")
            if username: s.login(username, password)
            s.send_message(msg)
        return True
    except Exception:
        app.logger.exception("Email delivery failed")
        return False

def key_hash(key):
    return hashlib.sha256(key.strip().upper().encode()).hexdigest()

def normalize_domain(value):
    value = (value or "").strip().lower()
    if "://" in value: value = urlparse(value).netloc
    value = value.split("/")[0].split(":")[0].rstrip(".")
    if not value or len(value) > 253 or not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", value):
        raise ValueError("Enter a valid panel hostname, e.g. panel.example.com")
    return value

def get_settings(user_id):
    with db() as c:
        row = c.execute("SELECT settings_json FROM themes WHERE user_id=?", (user_id,)).fetchone()
    return safe_settings(json.loads(row["settings_json"])) if row else defaults()

def api_key_digest(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def api_key_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    raw = header[7:].strip()
    if not raw:
        return None
    with db() as c:
        row = c.execute(
            "SELECT api_keys.id AS api_key_id, api_keys.user_id, users.email, users.verified "
            "FROM api_keys JOIN users ON users.id=api_keys.user_id "
            "WHERE api_keys.key_hash=? AND api_keys.status='active'",
            (api_key_digest(raw),)
        ).fetchone()
        if not row or not row["verified"]:
            return None
        c.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (iso(now()), row["api_key_id"]))
        return row

def css_for(settings, admin=False):
    s = safe_settings(settings)
    accent, bg, radius = s["accent"], s["background"], s["radius"]
    anim = "transform .2s ease, box-shadow .2s ease, border-color .2s ease" if s["animations"] else "none"
    glow = f"0 0 22px {accent}33" if s["glow"] else "none"
    cursor = s["cursor"]
    common = f"""
:root {{ --nova-accent:{accent}; --nova-bg:{bg}; --nova-radius:{radius}px; --nova-glow:{glow}; }}
html, body {{ cursor:{cursor}; }}
a, button, [role="button"] {{ cursor:pointer; }}
body {{ background-color:var(--nova-bg); }}
button, input, select, textarea {{ border-radius:var(--nova-radius); }}
a:focus-visible, button:focus-visible, input:focus-visible {{ outline:2px solid var(--nova-accent); outline-offset:2px; }}
"""
    if admin:
        return common + f"""
/* NOVA THEME admin panel styles */
.bg-neutral-900, .bg-gray-900 {{ background-color:var(--nova-bg)!important; }}
button[type=submit], .btn-primary {{ background:var(--nova-accent)!important; border-color:var(--nova-accent)!important; }}
a:hover {{ color:var(--nova-accent); }}
"""
    return common + f"""
/* NOVA THEME client styles */
nav a, aside a {{ transition:{anim}; }}
nav a:hover, aside a:hover {{ color:var(--nova-accent)!important; }}
button, [role="button"] {{ transition:{anim}; }}
button:hover, [role="button"]:hover {{ box-shadow:var(--nova-glow); }}
[class*="ServerRow"], [class*="server-card"], [class*="ServerCard"], .server-card {{
  border-radius:var(--nova-radius)!important; transition:{anim}; border-color:#ffffff16;
}}
[class*="ServerRow"]:hover, [class*="server-card"]:hover, [class*="ServerCard"]:hover, .server-card:hover {{
  border-color:var(--nova-accent)!important; box-shadow:var(--nova-glow); transform:translateY(-2px);
}}
input:focus, textarea:focus {{ border-color:var(--nova-accent)!important; box-shadow:0 0 0 2px {accent}30!important; }}
/* Login and auth screens: selectors intentionally broad for 1.x React builds */
form button[type=submit] {{ background:var(--nova-accent)!important; border-color:var(--nova-accent)!important; }}
@media (max-width:700px) {{
  main, [class*="container"] {{ max-width:100%; }}
  [class*="ServerRow"], [class*="server-card"], [class*="ServerCard"] {{ width:100%; }}
}}
"""

def make_blueprint(settings):
    """Build a ZIP archive with Blueprint's expected source layout.
    It is passed to the installed Blueprint CLI; test against your exact Blueprint build first."""
    s = safe_settings(settings)
    conf = """info:
  name: 'NOVA THEME'
  identifier: 'novatheme'
  description: 'NOVA THEME red edition: customer-configurable styling.'
  version: '1.0.0'
  target: 'beta-2026-01'
  author: 'NOVA THEME'
  website: 'https://example.com'
admin:
  view: 'views/admin.blade.php'
  css: 'assets/admin.css'
dashboard:
  css: 'assets/dashboard.css'
"""
    admin_view = """<div class="container">
  <h2>NOVA THEME</h2>
  <p>NOVA THEME styling is active. Change design options from your NOVA license portal, then reinstall/update the package.</p>
</div>
"""
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("conf.yml", conf)
        z.writestr("assets/dashboard.css", css_for(s, False))
        z.writestr("assets/admin.css", css_for(s, True))
        z.writestr("views/admin.blade.php", admin_view)
    memory.seek(0)
    return memory

@app.context_processor
def inject_user():
    return {"me": current_user(), "brand": "NOVA THEME", "now_date": now().date().isoformat()}

@app.route("/")
def home():
    if current_user(): return redirect(url_for("dashboard"))
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 10:
            flash("Use a valid email and a password with at least 10 characters.", "error")
            return render_template("register.html")
        token = secrets.token_urlsafe(32)
        with db() as c:
            try:
                c.execute("INSERT INTO users(email,password_hash,verify_hash,verify_expires,created_at) VALUES(?,?,?,?,?)",
                          (email, generate_password_hash(password), hashlib.sha256(token.encode()).hexdigest(),
                           iso(now()+timedelta(minutes=30)), iso(now())))
                uid = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
                c.execute("INSERT INTO themes(user_id,settings_json,updated_at) VALUES(?,?,?)",
                          (uid, json.dumps(defaults()), iso(now())))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")
                return render_template("register.html")
        if not send_verification(email, token):
            flash("Account created, but email delivery failed. Configure SMTP and contact the site administrator.", "error")
        else:
            flash("Check your email for a verification link. It expires in 30 minutes.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/verify/<token>")
def verify(token):
    digest = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row = c.execute("SELECT id,verify_expires FROM users WHERE verify_hash=?", (digest,)).fetchone()
        if not row or not row["verify_expires"] or datetime.fromisoformat(row["verify_expires"]) < now():
            flash("Verification link is invalid or expired. Register again or contact support.", "error")
        else:
            c.execute("UPDATE users SET verified=1,verify_hash=NULL,verify_expires=NULL WHERE id=?", (row["id"],))
            flash("Email verified. You can now sign in.", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with db() as c: u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not u or not check_password_hash(u["password_hash"], password):
            flash("Email or password is incorrect.", "error")
        elif not u["verified"]:
            flash("Verify your email before signing in.", "error")
        else:
            session.clear(); session["uid"] = u["id"]
            return redirect(url_for("admin") if u["is_admin"] else url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    with db() as c:
        licenses = c.execute("SELECT key_hint,status,expires_at,bound_domain,created_at FROM licenses WHERE email=? ORDER BY id DESC", (u["email"],)).fetchall()
        api_keys = c.execute("SELECT id,key_prefix,name,status,created_at,last_used_at FROM api_keys WHERE user_id=? ORDER BY id DESC", (u["id"],)).fetchall()
    new_api_key = session.pop("new_api_key_once", None)
    return render_template("dashboard.html", settings=get_settings(u["id"]), licenses=licenses, api_keys=api_keys, new_api_key=new_api_key)

@app.route("/editor", methods=["GET", "POST"])
@login_required
def editor():
    u = current_user()
    if request.method == "POST":
        s = safe_settings({
            "accent": request.form.get("accent"), "background": request.form.get("background"),
            "radius": request.form.get("radius"), "glow": request.form.get("glow") == "on",
            "animations": request.form.get("animations") == "on", "cursor": request.form.get("cursor")
        })
        with db() as c:
            c.execute("""INSERT INTO themes(user_id,settings_json,updated_at) VALUES(?,?,?)
              ON CONFLICT(user_id) DO UPDATE SET settings_json=excluded.settings_json,updated_at=excluded.updated_at""",
                      (u["id"], json.dumps(s), iso(now())))
        flash("Theme settings saved. New installer downloads will use these settings.", "success")
        return redirect(url_for("editor"))
    return render_template("editor.html", settings=get_settings(u["id"]))

@app.route("/preview.css")
@login_required
def preview_css():
    return app.response_class(css_for(get_settings(current_user()["id"])), mimetype="text/css")

@app.route("/admin")
@login_required
@admin_required
def admin():
    with db() as c:
        users = c.execute("SELECT id,email,verified,is_admin,created_at FROM users ORDER BY id DESC LIMIT 100").fetchall()
        licenses = c.execute("""SELECT l.*,u.email AS owner FROM licenses l LEFT JOIN users u ON u.email=l.email ORDER BY l.id DESC LIMIT 100""").fetchall()
    return render_template("admin.html", users=users, licenses=licenses)

@app.route("/admin/licenses", methods=["POST"])
@login_required
@admin_required
def create_license():
    email = request.form.get("email", "").strip().lower()
    days = request.form.get("days", "365")
    expiry_date = request.form.get("expiry_date", "").strip()
    try:
        days = max(1, min(3650, int(days)))
    except ValueError:
        days = 365
    if expiry_date:
        try:
            expires = datetime.strptime(expiry_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
            if expires <= now():
                flash("Expiry date must be in the future.", "error")
                return redirect(url_for("admin"))
        except ValueError:
            flash("Expiry date is invalid.", "error")
            return redirect(url_for("admin"))
    else:
        expires = now() + timedelta(days=days)
    with db() as c:
        user = c.execute("SELECT id FROM users WHERE email=? AND verified=1", (email,)).fetchone()
        if not user:
            flash("Customer email must belong to a verified account.", "error")
            return redirect(url_for("admin"))
        raw = "NOVA-" + "-".join(secrets.token_hex(2).upper() for _ in range(3)) + "-" + secrets.token_hex(2).upper()
        c.execute("INSERT INTO licenses(key_hash,key_hint,email,status,expires_at,created_at,created_by) VALUES(?,?,?,?,?,?,?)",
                  (key_hash(raw), raw[-4:], email, "active", iso(expires), iso(now()), current_user()["id"]))
    session["new_license_once"] = raw
    flash("License created. Copy the key from the one-time reveal below.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/license/<int:license_id>/revoke", methods=["POST"])
@login_required
@admin_required
def revoke_license(license_id):
    with db() as c: c.execute("UPDATE licenses SET status='revoked' WHERE id=?", (license_id,))
    flash("License revoked.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/license/<int:license_id>/renew", methods=["POST"])
@login_required
@admin_required
def renew_license(license_id):
    with db() as c:
        row = c.execute("SELECT expires_at FROM licenses WHERE id=?", (license_id,)).fetchone()
        if row:
            base_dt = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) > now() else now()
            c.execute("UPDATE licenses SET status='active',expires_at=? WHERE id=?", (iso(base_dt+timedelta(days=365)), license_id))
    flash("License renewed for 365 days.", "success")
    return redirect(url_for("admin"))

@app.route("/api/license/validate", methods=["POST"])
def api_validate():
    data = request.get_json(silent=True) or request.form
    email = str(data.get("email", "")).strip().lower()
    key = str(data.get("license", "")).strip().upper()
    try: domain = normalize_domain(str(data.get("domain", "")))
    except ValueError as e: return jsonify(ok=False, error=str(e)), 400
    if not email or not key: return jsonify(ok=False, error="Email and license are required."), 400
    with db() as c:
        user = c.execute("SELECT id,verified FROM users WHERE email=?", (email,)).fetchone()
        lic = c.execute("SELECT * FROM licenses WHERE key_hash=? AND email=?", (key_hash(key), email)).fetchone()
        if not user or not user["verified"] or not lic:
            return jsonify(ok=False, error="License/email mismatch or email not verified."), 403
        if lic["status"] != "active": return jsonify(ok=False, error="License is not active."), 403
        if lic["expires_at"] and datetime.fromisoformat(lic["expires_at"]) < now():
            c.execute("UPDATE licenses SET status='expired' WHERE id=?", (lic["id"],))
            return jsonify(ok=False, error="License expired."), 403
        if lic["bound_domain"] and lic["bound_domain"] != domain:
            return jsonify(ok=False, error="License is already bound to a different panel domain."), 403
        c.execute("UPDATE licenses SET bound_domain=COALESCE(bound_domain, ?) WHERE id=?", (domain, lic["id"]))
        c.execute("""INSERT INTO activations(license_id,domain,activated_at,last_seen) VALUES(?,?,?,?)
          ON CONFLICT(license_id,domain) DO UPDATE SET last_seen=excluded.last_seen""",
          (lic["id"], domain, iso(now()), iso(now())))
        return jsonify(ok=True, message="License valid.", domain=domain, expires_at=lic["expires_at"])

@app.route("/api/installer/package", methods=["POST"])
def installer_package():
    data = request.get_json(silent=True) or request.form
    email = str(data.get("email", "")).strip().lower()
    key = str(data.get("license", "")).strip().upper()
    try: domain = normalize_domain(str(data.get("domain", "")))
    except ValueError as e: return jsonify(ok=False, error=str(e)), 400
    # Reuse the same validation rules without trusting the client.
    with db() as c:
        user = c.execute("SELECT id,verified FROM users WHERE email=?", (email,)).fetchone()
        lic = c.execute("SELECT * FROM licenses WHERE key_hash=? AND email=?", (key_hash(key), email)).fetchone()
        if not user or not user["verified"] or not lic or lic["status"] != "active":
            return jsonify(ok=False, error="License invalid, inactive, or email not verified."), 403
        if lic["expires_at"] and datetime.fromisoformat(lic["expires_at"]) < now():
            c.execute("UPDATE licenses SET status='expired' WHERE id=?", (lic["id"],))
            return jsonify(ok=False, error="License expired."), 403
        if lic["bound_domain"] and lic["bound_domain"] != domain:
            return jsonify(ok=False, error="License is bound to another domain."), 403
        c.execute("UPDATE licenses SET bound_domain=COALESCE(bound_domain, ?) WHERE id=?", (domain, lic["id"]))
        c.execute("""INSERT INTO activations(license_id,domain,activated_at,last_seen) VALUES(?,?,?,?)
          ON CONFLICT(license_id,domain) DO UPDATE SET last_seen=excluded.last_seen""", (lic["id"],domain,iso(now()),iso(now())))
    settings = get_settings(user["id"])
    archive = make_blueprint(settings)
    return send_file(archive, mimetype="application/zip", as_attachment=True, download_name="novatheme.blueprint")

@app.route("/api-keys", methods=["POST"])
@login_required
def create_api_key():
    u = current_user()
    name = request.form.get("name", "").strip()[:60]
    if not name:
        flash("Give your API key a name, e.g. My Discord Bot.", "error")
        return redirect(url_for("dashboard"))
    raw = "nova_sk_" + secrets.token_urlsafe(32)
    with db() as c:
        c.execute("INSERT INTO api_keys(user_id,key_hash,key_prefix,name,status,created_at) VALUES(?,?,?,?,?,?)",
                  (u["id"], api_key_digest(raw), raw[:15], name, "active", iso(now())))
    session["new_api_key_once"] = raw
    flash("API key created. Copy it now; it cannot be shown again.", "success")
    return redirect(url_for("dashboard"))

@app.route("/api-keys/<int:key_id>/revoke", methods=["POST"])
@login_required
def revoke_api_key(key_id):
    u = current_user()
    with db() as c:
        c.execute("UPDATE api_keys SET status='revoked' WHERE id=? AND user_id=?", (key_id, u["id"]))
    flash("API key revoked.", "success")
    return redirect(url_for("dashboard"))

@app.route("/api/v1/me", methods=["GET"])
def api_v1_me():
    u = api_key_user()
    if not u:
        return jsonify(ok=False, error="Missing, invalid, or revoked Bearer API key."), 401
    with db() as c:
        licenses = c.execute("SELECT status,expires_at,bound_domain,key_hint FROM licenses WHERE email=? ORDER BY id DESC",
                             (u["email"],)).fetchall()
    return jsonify(ok=True, email=u["email"], api_key_id=u["api_key_id"],
        licenses=[{"status": x["status"], "expires_at": x["expires_at"],
                   "bound_domain": x["bound_domain"], "key_hint": x["key_hint"]} for x in licenses])

@app.route("/api/v1/theme", methods=["GET"])
def api_v1_theme():
    u = api_key_user()
    if not u:
        return jsonify(ok=False, error="Missing, invalid, or revoked Bearer API key."), 401
    return jsonify(ok=True, theme=get_settings(u["user_id"]))

@app.route("/health")
def health():
    return jsonify(ok=True, service="nova-theme-portal")

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
