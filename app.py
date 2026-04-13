"""
PICthermo — Flask app sécurisée.
Anti-DDoS, hachage IP, mots de passe scrypt, en-têtes HTTP renforcés.
Limite : 100 utilisateurs maximum.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import re
import sqlite3
import time
from functools import wraps

from flask import (
    Flask, flash, render_template, request,
    redirect, session, url_for, g, abort,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or "changez-moi-en-production-32chars!"

IP_HMAC_KEY = (os.environ.get("IP_HMAC_KEY") or "ip-hmac-secret-key-changez-moi").encode()

MAX_USERS = 100

def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def hash_ip(ip: str) -> str:
    return hmac.new(IP_HMAC_KEY, ip.encode(), hashlib.sha256).hexdigest()

# ---------------------------------------------------------------------------
# Blocklist IP en mémoire (anti-DDoS)
# ---------------------------------------------------------------------------

BLOCKED_IPS: dict[str, float] = {}
BLOCK_DURATION = 600

def is_blocked(ip: str) -> bool:
    unblock_time = BLOCKED_IPS.get(ip)
    if unblock_time is None:
        return False
    if time.time() > unblock_time:
        del BLOCKED_IPS[ip]
        return False
    return True

def block_ip(ip: str) -> None:
    BLOCKED_IPS[ip] = time.time() + BLOCK_DURATION

@app.before_request
def check_blocked_ip():
    ip = client_ip()
    if is_blocked(ip):
        abort(429)

# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

limiter = Limiter(
    key_func=client_ip,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
)

@app.errorhandler(429)
def too_many_requests(e):
    ip = client_ip()
    block_ip(ip)
    return render_template("429.html"), 429

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

PASSWORD_MIN_LEN = 8
USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,32}$")
CAPTCHA_SESSION_KEY = "reg_captcha"

ADMIN_USER          = (os.environ.get("ADMIN_USER") or "").strip()
ADMIN_PASSWORD      = os.environ.get("ADMIN_PASSWORD") or ""
ADMIN_PASSWORD_HASH = (os.environ.get("ADMIN_PASSWORD_HASH") or "").strip()


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    if len(password) < PASSWORD_MIN_LEN:
        return False, f"Le mot de passe doit contenir au moins {PASSWORD_MIN_LEN} caractères."
    if not re.search(r"[A-Za-zÀ-ÿ]", password):
        return False, "Le mot de passe doit contenir au moins une lettre."
    if not re.search(r"\d", password):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    return True, None


def validate_username(username: str) -> tuple[bool, str | None]:
    if not username:
        return False, "Veuillez indiquer un nom d'utilisateur."
    if not USERNAME_RE.match(username):
        return False, "Nom d'utilisateur : 3-32 caractères (lettres, chiffres, - ou _)."
    return True, None


def hash_password(plain: str) -> str:
    return generate_password_hash(plain, method="scrypt")

# ---------------------------------------------------------------------------
# Base de données
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS calculs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            x1         REAL,
            x2         REAL,
            P_bulle    REAL,
            y1         REAL,
            y2         REAL,
            user_ip    TEXT,
            user_id    INTEGER,
            created_at TEXT
        )
    """)

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    users_exists = cur.fetchone() is not None

    if users_exists:
        cur.execute("PRAGMA table_info(users)")
        cols = {row["name"] for row in cur.fetchall()}
        if "email" in cols and "username" not in cols:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users_new (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)
            cur.execute("INSERT INTO users_new (id, username, password_hash) SELECT id, email, password_hash FROM users")
            cur.execute("DROP TABLE users")
            cur.execute("ALTER TABLE users_new RENAME TO users")
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

    conn.close()


init_db()

# ---------------------------------------------------------------------------
# En-têtes de sécurité
# ---------------------------------------------------------------------------

@app.after_request
def security_headers(response):
    h = response.headers
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    h.setdefault("Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "base-uri 'self'; form-action 'self'"
    )
    return response

# ---------------------------------------------------------------------------
# Captcha
# ---------------------------------------------------------------------------

def new_register_captcha():
    session[CAPTCHA_SESSION_KEY] = {
        "a": random.randint(2, 15),
        "b": random.randint(2, 15),
    }
    return session[CAPTCHA_SESSION_KEY]

# ---------------------------------------------------------------------------
# Décorateurs
# ---------------------------------------------------------------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_username" not in session or session.get("user_id") is None:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped_view


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_ok"):
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)
    return wrapped_view


def normalize_username(value: str) -> str:
    return (value or "").strip().lower()

# ---------------------------------------------------------------------------
# Route : inscription
# ---------------------------------------------------------------------------

def get_user_count() -> int:
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    row = cur.fetchone()
    return row[0] if row else 0


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10/hour", exempt_when=lambda: request.method != "POST")
def register():
    error = None

    if get_user_count() >= MAX_USERS:
        return render_template("register.html",
            error=None, captcha_a=0, captcha_b=0,
            registration_closed=True, max_users=MAX_USERS
        )

    if request.method == "POST":
        if get_user_count() >= MAX_USERS:
            return render_template("register.html",
                error=None, captcha_a=0, captcha_b=0,
                registration_closed=True, max_users=MAX_USERS
            )

        cap = session.get(CAPTCHA_SESSION_KEY)
        captcha_ok = False
        if cap:
            try:
                ans = int((request.form.get("captcha_answer") or "").strip())
                captcha_ok = ans == cap["a"] + cap["b"]
            except ValueError:
                captcha_ok = False

        if not captcha_ok:
            error = "Vérification anti-robot incorrecte. Réessayez."
            c = new_register_captcha()
            return render_template("register.html", error=error, captcha_a=c["a"], captcha_b=c["b"], registration_closed=False)

        session.pop(CAPTCHA_SESSION_KEY, None)
        username         = normalize_username(request.form.get("username", ""))
        password         = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        ok_user, user_msg = validate_username(username)
        if not ok_user:
            error = user_msg
        elif password != password_confirm:
            error = "Les mots de passe ne correspondent pas."
        else:
            ok_pw, pw_msg = validate_password_strength(password)
            if not ok_pw:
                error = pw_msg
            else:
                db = get_db()
                cur = db.cursor()
                try:
                    cur.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, hash_password(password)),
                    )
                    db.commit()
                except sqlite3.IntegrityError:
                    db.rollback()
                    error = "Ce nom d'utilisateur est déjà pris."
                except Exception as e:
                    db.rollback()
                    error = f"Erreur : {e}"

                if not error:
                    flash("Compte créé. Vous pouvez vous connecter.", "ok")
                    return redirect(url_for("login"))

        c = new_register_captcha()
        return render_template("register.html", error=error, captcha_a=c["a"], captcha_b=c["b"], registration_closed=False)

    c = new_register_captcha()
    return render_template("register.html", error=None, captcha_a=c["a"], captcha_b=c["b"], registration_closed=False)

# ---------------------------------------------------------------------------
# Route : connexion
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute", exempt_when=lambda: request.method != "POST")
def login():
    error = None
    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        time.sleep(0.3)

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"]       = row["id"]
            session["user_username"] = username
            return redirect(url_for("home"))
        error = "Nom d'utilisateur ou mot de passe incorrect."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Route : calculateur principal
# ---------------------------------------------------------------------------

def validate_fractions(x1: float, x2: float) -> tuple[bool, str | None]:
    if x1 < 0 or x1 > 1 or x2 < 0 or x2 > 1:
        return False, "x1 et x2 doivent être compris entre 0 et 1."
    if abs(x1 + x2 - 1) > 0.01:
        return False, "La somme x1 + x2 doit être égale à 1."
    return True, None


@app.route("/", methods=["GET", "POST"])
@login_required
@limiter.limit("30/minute", exempt_when=lambda: request.method != "POST")
def home():
    result  = None
    error   = None
    details = None
    p1      = 101.3
    p2      = 40
    uid     = session["user_id"]
    ip_hash = hash_ip(client_ip())

    if request.method == "POST":
        try:
            x1 = float(request.form["x1"])
            x2 = float(request.form["x2"])
        except (ValueError, KeyError):
            error = "Valeurs invalides."
        else:
            ok_frac, frac_err = validate_fractions(x1, x2)
            if not ok_frac:
                error = frac_err
            else:
                P_bulle = (p1 * x1) + (p2 * x2)
                y1      = (x1 * p1) / P_bulle
                y2      = (x2 * p2) / P_bulle
                somme   = y1 + y2
                result  = (round(P_bulle,3), round(y1,3), round(y2,3), round(somme,3))
                details = {"application": [
                    f"P_bulle = {x1}×101.3 + {x2}×40 = {round(P_bulle,3)}",
                    f"y1 = ({x1}×101.3) / {round(P_bulle,3)} = {round(y1,3)}",
                    f"y2 = ({x2}×40) / {round(P_bulle,3)} = {round(y2,3)}",
                    f"{round(y1,3)} + {round(y2,3)} = {round(somme,3)}",
                ]}
                db = get_db()
                cur = db.cursor()
                cur.execute("""
                    INSERT INTO calculs (x1, x2, P_bulle, y1, y2, user_ip, user_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (x1, x2, P_bulle, y1, y2, ip_hash, uid))
                db.commit()

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, x1, x2, P_bulle, y1, y2, created_at
        FROM calculs WHERE user_id = ?
        ORDER BY id DESC LIMIT 10
    """, (uid,))
    historique = cur.fetchall()

    return render_template("index.html",
        result=result, error=error,
        historique=historique, details=details,
        user_email=session.get("user_username"),
    )


@app.route("/delete_history")
@login_required
def delete_history():
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM calculs WHERE user_id = ?", (session["user_id"],))
    db.commit()
    return redirect(url_for("home"))

# ---------------------------------------------------------------------------
# Routes : administration
# ---------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5/minute", exempt_when=lambda: request.method != "POST")
def admin_login():
    if not ADMIN_USER or (not ADMIN_PASSWORD and not ADMIN_PASSWORD_HASH):
        return render_template("admin_login.html",
            error="Compte admin non configuré.", disabled=True)

    error = None
    if request.method == "POST":
        time.sleep(0.5)
        u        = (request.form.get("username") or "").strip()
        p        = request.form.get("password") or ""
        admin_ok = u == ADMIN_USER
        if admin_ok and ADMIN_PASSWORD_HASH:
            admin_ok = check_password_hash(ADMIN_PASSWORD_HASH, p)
        elif admin_ok:
            admin_ok = p == ADMIN_PASSWORD
        if admin_ok:
            session["admin_ok"] = True
            return redirect(url_for("admin_dashboard"))
        error = "Identifiants administrateur incorrects."

    return render_template("admin_login.html", error=error, disabled=False)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_ok", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT c.id, c.x1, c.x2, c.P_bulle, c.y1, c.y2,
               c.user_ip, c.created_at, u.username
        FROM calculs c
        LEFT JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC LIMIT 500
    """)
    rows = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM calculs")
    total_calculs = cur.fetchone()[0]

    return render_template("admin_dashboard.html",
        rows=rows,
        total_users=total_users,
        total_calculs=total_calculs,
        max_users=MAX_USERS
    )

# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        from waitress import serve
        print("=" * 50)
        print("  PICthermo démarré avec Waitress (production)")
        print("  Lien : http://127.0.0.1:5000")
        print("  Appuyez sur CTRL+C pour arrêter")
        print("=" * 50)
        serve(app, host="0.0.0.0", port=5000)
    except ImportError:
        print("[AVERTISSEMENT] waitress non trouvé, utilisation du serveur Flask dev.")
        app.run(host="0.0.0.0", port=5000, debug=False)