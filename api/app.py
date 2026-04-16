import os
from functools import wraps

import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from werkzeug.security import generate_password_hash, check_password_hash

import re

BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
CONTACT_TO_EMAIL = os.environ.get("CONTACT_TO_EMAIL")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "IndLex Contact")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


AP90_BASE = "https://api.c-salt.uni-koeln.de/dicts/ap90/restful/entries"

DATABASE_URL = os.environ.get("DATABASE_URL")  # Render provides this when you attach a Postgres DB
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key")

# Comma-separated list of allowed origins. Example:
# FRONTEND_ORIGINS="https://your-frontend.onrender.com,http://localhost:8080"
FRONTEND_ORIGINS = os.environ.get("FRONTEND_ORIGINS", "http://localhost:8080")
ALLOWED_ORIGINS = [o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()]

PGSSLMODE = os.environ.get("PGSSLMODE", "require")  # Render Postgres usually needs require
APP_ENV = os.environ.get("APP_ENV", "production")   # set "local" for local testing


app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

# Cookies across different domains (static frontend -> API) need SameSite=None; Secure=True on HTTPS.
# For local dev over http://, Secure cookies won't work.
if APP_ENV == "local":
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False
else:
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True

CORS(
    app,
    supports_credentials=True,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
)

login_manager = LoginManager(app)


# ---------------------------
# Postgres connection pooling
# ---------------------------

_pool = None


def init_pool():
    global _pool
    if _pool is not None:
        return

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set (Render Postgres not attached?)")

    # connect_timeout avoids long hangs at boot
    _pool = SimpleConnectionPool(
        1,
        10,
        dsn=DATABASE_URL,
        sslmode=PGSSLMODE,
        connect_timeout=10,
    )


def get_conn():
    init_pool()
    conn = _pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
    except psycopg2.OperationalError:
        # Connection is dead; discard and open a new one
        pool.putconn(conn, close=True)
        conn = psycopg2.connect(dsn=DATABASE_URL)
    return conn


def put_conn(conn):
    if _pool and conn:
        _pool.putconn(conn)


# ---------------------------
# DB init (tables + seed)
# ---------------------------

_INIT_DONE = False
_INIT_ERROR = None


def init_db():
    """
    Create tables (idempotent) and seed roles + default admin if needed.
    """
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id SERIAL PRIMARY KEY,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              is_active BOOLEAN NOT NULL DEFAULT TRUE
            );
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS roles (
              id SERIAL PRIMARY KEY,
              name TEXT UNIQUE NOT NULL
            );
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_roles (
              user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
              PRIMARY KEY (user_id, role_id)
            );
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS lookups (
              id SERIAL PRIMARY KEY,
              root TEXT NOT NULL,
              meaning TEXT,
              best_headword TEXT,
              similarity_score DOUBLE PRECISION,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              language TEXT,
              distance_to_root INTEGER,
              created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )

        # Seed roles
        cur.execute("INSERT INTO roles (name) VALUES (%s) ON CONFLICT (name) DO NOTHING", ("admin",))
        cur.execute("INSERT INTO roles (name) VALUES (%s) ON CONFLICT (name) DO NOTHING", ("editor",))

        # Seed default admin if there are no users
        cur.execute("SELECT COUNT(*) AS c FROM users;")
        users_count = cur.fetchone()[0]
        if users_count == 0:
            pw_hash = generate_password_hash("admin123")
            cur.execute(
                "INSERT INTO users (username, password_hash, is_active) VALUES (%s, %s, TRUE) RETURNING id",
                ("admin", pw_hash),
            )
            admin_user_id = cur.fetchone()[0]

            cur.execute("SELECT id FROM roles WHERE name=%s", ("admin",))
            admin_role_id = cur.fetchone()[0]

            cur.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (admin_user_id, admin_role_id),
            )

        conn.commit()

    finally:
        if conn:
            put_conn(conn)


@app.before_request
def ensure_db_ready():
    """
    Lazy-init so Gunicorn can start even if DB is slow for a moment.
    """
    global _INIT_DONE, _INIT_ERROR
    if _INIT_DONE:
        return
    try:
        init_db()
        _INIT_DONE = True
        _INIT_ERROR = None
    except Exception as e:
        _INIT_ERROR = str(e)
        # Let healthz work; block API calls until DB is ready
        if request.path.startswith("/api/") and request.path != "/api/healthz":
            return jsonify({"error": "db_not_ready", "detail": _INIT_ERROR}), 503


# ---------------------------
# Helpers / RBAC
# ---------------------------

class User(UserMixin):
    def __init__(self, user_id, username, is_active=True):
        self.id = int(user_id)
        self.username = username
        self._is_active = bool(is_active)

    def is_active(self):
        return self._is_active


@login_manager.user_loader
def load_user(user_id):
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username, is_active FROM users WHERE id=%s", (int(user_id),))
        row = cur.fetchone()
        if not row:
            return None
        return User(row["id"], row["username"], row["is_active"])
    finally:
        if conn:
            put_conn(conn)


def get_user_roles(user_id: int):
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """
            SELECT r.name
            FROM roles r
            JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = %s
            """,
            (int(user_id),),
        )
        return [r["name"] for r in cur.fetchall()]
    finally:
        if conn:
            put_conn(conn)


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user_roles = set(get_user_roles(current_user.id))
            if not any(r in user_roles for r in roles):
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def password_policy_ok(pw: str):
    if not isinstance(pw, str) or len(pw) < 8:
        return False, "Password must be at least 8 characters"
    return True, None


def admin_count(conn) -> int:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COUNT(DISTINCT u.id) AS c
        FROM users u
        JOIN user_roles ur ON ur.user_id = u.id
        JOIN roles r ON r.id = ur.role_id
        WHERE r.name='admin' AND u.is_active=TRUE
        """
    )
    return int(cur.fetchone()[0])


def set_user_roles(conn, user_id: int, roles: list):
    if not isinstance(roles, list):
        roles = []
    roles = [r.strip() for r in roles if isinstance(r, str) and r.strip()]

    cur = conn.cursor()
    cur.execute("DELETE FROM user_roles WHERE user_id=%s", (int(user_id),))

    for role_name in roles:
        cur.execute("SELECT id FROM roles WHERE name=%s", (role_name,))
        rr = cur.fetchone()
        if not rr:
            continue
        role_id = rr[0]
        cur.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (int(user_id), int(role_id)),
        )


def can_modify_lookup(created_by_user_id) -> bool:
    if not current_user.is_authenticated:
        return False
    roles = set(get_user_roles(current_user.id))
    if "admin" in roles:
        return True
    if "editor" in roles:
        return created_by_user_id is not None and int(created_by_user_id) == int(current_user.id)
    return False


# ---------------------------
# Health
# ---------------------------

@app.route("/api/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "db_initialized": _INIT_DONE, "db_error": _INIT_ERROR}), 200


# ---------------------------
# Auth + password endpoints
# ---------------------------

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT id, username, password_hash, is_active FROM users WHERE username=%s",
            (username,),
        )
        row = cur.fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            return jsonify({"error": "invalid credentials"}), 401
        if not row["is_active"]:
            return jsonify({"error": "user inactive"}), 403

        user = User(row["id"], row["username"], row["is_active"])
        login_user(user)

        roles = get_user_roles(user.id)
        return jsonify({"status": "logged_in", "user_id": user.id, "username": user.username, "roles": roles}), 200
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"status": "logged_out"}), 200


@app.route("/api/me", methods=["GET"])
def me():
    if not current_user.is_authenticated:
        return jsonify({"authenticated": False}), 200
    roles = get_user_roles(current_user.id)
    return jsonify({"authenticated": True, "user_id": current_user.id, "username": current_user.username, "roles": roles}), 200


@app.route("/api/change_password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(force=True, silent=True) or {}
    old_pw = data.get("oldPassword") or ""
    new_pw = data.get("newPassword") or ""

    if not old_pw or not new_pw:
        return jsonify({"error": "oldPassword and newPassword required"}), 400

    ok, msg = password_policy_ok(new_pw)
    if not ok:
        return jsonify({"error": msg}), 400

    if old_pw == new_pw:
        return jsonify({"error": "newPassword must be different"}), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT password_hash FROM users WHERE id=%s", (int(current_user.id),))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "user not found"}), 404
        if not check_password_hash(row["password_hash"], old_pw):
            return jsonify({"error": "invalid old password"}), 401

        cur2 = conn.cursor()
        cur2.execute(
            "UPDATE users SET password_hash=%s WHERE id=%s",
            (generate_password_hash(new_pw), int(current_user.id)),
        )
        conn.commit()
        return jsonify({"status": "password_updated"}), 200
    finally:
        if conn:
            put_conn(conn)


# ---------------------------
# Admin password management
# ---------------------------

@app.route("/api/admin/users", methods=["GET"])
@roles_required("admin")
def admin_list_users():
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username, is_active FROM users ORDER BY username ASC")
        users = cur.fetchall()

        for u in users:
            u["roles"] = get_user_roles(u["id"])
        return jsonify(users), 200
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/admin/users", methods=["POST"])
@roles_required("admin")
def admin_create_user():
    payload = request.get_json(force=True, silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    roles = payload.get("roles") or []
    is_active = bool(payload.get("isActive", True))

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    ok, msg = password_policy_ok(password)
    if not ok:
        return jsonify({"error": msg}), 400

    if not isinstance(roles, list):
        return jsonify({"error": "roles must be a list"}), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_active) VALUES (%s, %s, %s) RETURNING id",
                (username, generate_password_hash(password), is_active),
            )
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return jsonify({"error": "username already exists"}), 409

        user_id = cur.fetchone()[0]
        set_user_roles(conn, user_id, roles)
        conn.commit()
        return jsonify({"status": "user_created", "user_id": user_id, "username": username}), 201
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/admin/set_password", methods=["POST"])
@roles_required("admin")
def admin_set_password_by_username():
    payload = request.get_json(force=True, silent=True) or {}
    username = (payload.get("username") or "").strip()
    new_pw = payload.get("newPassword") or ""

    if not username or not new_pw:
        return jsonify({"error": "username and newPassword required"}), 400

    ok, msg = password_policy_ok(new_pw)
    if not ok:
        return jsonify({"error": msg}), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "user not found"}), 404

        cur2 = conn.cursor()
        cur2.execute(
            "UPDATE users SET password_hash=%s WHERE username=%s",
            (generate_password_hash(new_pw), username),
        )
        conn.commit()
        return jsonify({"status": "password_set", "username": username}), 200
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/admin/users/<int:user_id>/active", methods=["PUT"])
@roles_required("admin")
def admin_set_active(user_id: int):
    payload = request.get_json(force=True, silent=True) or {}
    is_active = payload.get("isActive")
    if is_active not in (True, False, 0, 1):
        return jsonify({"error": "isActive must be true/false"}), 400

    is_active_bool = bool(is_active)

    if int(user_id) == int(current_user.id) and not is_active_bool:
        return jsonify({"error": "cannot deactivate yourself"}), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE id=%s", (int(user_id),))
        if not cur.fetchone():
            return jsonify({"error": "user not found"}), 404

        # Prevent deactivating the last active admin
        target_roles = set(get_user_roles(user_id))
        if (not is_active_bool) and ("admin" in target_roles):
            if admin_count(conn) <= 1:
                return jsonify({"error": "cannot deactivate the last active admin"}), 400

        cur2 = conn.cursor()
        cur2.execute("UPDATE users SET is_active=%s WHERE id=%s", (is_active_bool, int(user_id)))
        conn.commit()
        return jsonify({"status": "active_updated", "user_id": user_id, "is_active": is_active_bool}), 200
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/admin/users/<int:user_id>/roles", methods=["PUT"])
@roles_required("admin")
def admin_set_roles(user_id: int):
    payload = request.get_json(force=True, silent=True) or {}
    roles = payload.get("roles")
    if not isinstance(roles, list):
        return jsonify({"error": "roles must be a list"}), 400

    roles_clean = [r.strip() for r in roles if isinstance(r, str) and r.strip()]

    if int(user_id) == int(current_user.id) and ("admin" not in set(roles_clean)):
        return jsonify({"error": "cannot remove your own admin role"}), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE id=%s", (int(user_id),))
        if not cur.fetchone():
            return jsonify({"error": "user not found"}), 404

        current_roles = set(get_user_roles(user_id))
        new_roles = set(roles_clean)

        if ("admin" in current_roles) and ("admin" not in new_roles):
            if admin_count(conn) <= 1:
                return jsonify({"error": "cannot remove the last active admin"}), 400

        set_user_roles(conn, user_id, list(new_roles))
        conn.commit()
        return jsonify({"status": "roles_updated", "user_id": user_id, "roles": list(new_roles)}), 200
    finally:
        if conn:
            put_conn(conn)


# ---------------------------
# Business routes (ported)
# ---------------------------
### updated on 4/15/2026 ###
@app.route("/api/lookup_or_history", methods=["GET"])
def lookup_or_history():
    root = (request.args.get("root") or "").strip()
    meaning = (request.args.get("meaning") or "").strip()
    language = (request.args.get("language") or "").strip()

    if not root:
        return jsonify(error="missing root parameter"), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        if language:
            cur.execute(
                """
                SELECT id, root, meaning, best_headword, similarity_score,
                       distance_to_root, created_at, language, created_by_user_id
                FROM lookups
                WHERE root = %s AND (language = %s OR language IS NULL)
                ORDER BY createdat DESC
                LIMIT 1
                """,
                (root, language),
            )
        else:
            cur.execute(
                """
                SELECT id, root, meaning, bestheadword, similarityscore,
                       distance_to_root, created_at, language, created_by_user_id
                FROM lookups
                WHERE root = %s
                ORDER BY createdat DESC
                LIMIT 1
                """,
                (root,),
            )

        row = cur.fetchone()
    except Exception as e:
        print("DB error in lookup_or_history:", repr(e))
        return jsonify(error="db_error", detail=str(e)), 502
    finally:
        if conn:
            put_conn(conn)

    if row:
        row["source"] = "db"
        return jsonify(row), 200

    if not meaning:
        return jsonify(error="no DB record and missing meaning to query AP90"), 400

    try:
        resp = requests.get(
            AP90BASE,
            params={
                "field": "xml",
                "query": meaning,
                "querytype": "term",
                "size": 100,
            },
            headers={"Accept": "application/json"},
            timeout=15,
        )
    except Exception as e:
        print("AP90 request failed:", repr(e))
        return jsonify(error="upstream_error", detail=str(e)), 502

    if not resp.ok:
        print("AP90 non-200:", resp.status_code, resp.text[:500])
        return jsonify(
            error="ap90_error",
            status=resp.status_code,
            body=resp.text[:500]
        ), 502

    try:
        data = resp.json()
    except ValueError:
        print("AP90 non-JSON:", resp.text[:500])
        return jsonify(
            error="ap90_not_json",
            status=resp.status_code,
            body=resp.text[:500]
        ), 502

    return jsonify(source="ap90", raw=data), 200

##older working route prior to 4/15/2026##
# @app.route("/api/lookup_or_history", methods=["GET"])
# def lookup_or_history():
#     root = (request.args.get("root") or "").strip()
#     meaning = (request.args.get("meaning") or "").strip()
#     language = (request.args.get("language") or "").strip()

#     if not root:
#         return jsonify({"error": "missing root parameter"}), 400

#     conn = None
#     try:
#         conn = get_conn()
#         cur = conn.cursor(cursor_factory=RealDictCursor)

#         if language:
#             cur.execute(
#                 """
#                 SELECT id, root, meaning, best_headword, similarity_score,
#                        distance_to_root, created_at, language, created_by_user_id
#                 FROM lookups
#                 WHERE root=%s AND (language=%s OR language IS NULL)
#                 ORDER BY created_at DESC
#                 LIMIT 1
#                 """,
#                 (root, language),
#             )
#         else:
#             cur.execute(
#                 """
#                 SELECT id, root, meaning, best_headword, similarity_score,
#                        distance_to_root, created_at, language, created_by_user_id
#                 FROM lookups
#                 WHERE root=%s
#                 ORDER BY created_at DESC
#                 LIMIT 1
#                 """,
#                 (root,),
#             )

#         row = cur.fetchone()
#         if row:
#             row["source"] = "db"
#             return jsonify(row), 200

#     finally:
#         if conn:
#             put_conn(conn)

#     # No DB record: call AP90
#     if not meaning:
#         return jsonify({"error": "no DB record and missing meaning to query AP90"}), 400

#     try:
#         resp = requests.get(
#             AP90_BASE,
#             params={"field": "xml", "query": meaning, "query_type": "term", "size": 100},
#             headers={"Accept": "application/json"},
#             timeout=10,
#         )
#     except Exception as e:
#         return jsonify({"error": "upstream error", "detail": str(e)}), 502

#     try:
#         data = resp.json()
#     except ValueError:
#         return resp.text, resp.status_code, {"Content-Type": "text/plain; charset=utf-8"}

#     return jsonify({"source": "ap90", "raw": data}), resp.status_code


@app.route("/api/saveLookup", methods=["POST"])
@roles_required("admin", "editor")
def save_lookup():
    payload = request.get_json(force=True, silent=True) or {}
    root = (payload.get("root") or "").strip()
    meaning = (payload.get("meaning") or "").strip()
    best_headword = (payload.get("bestHeadword") or "").strip()
    similarity_score = payload.get("similarityScore")
    language = (payload.get("language") or "").strip() or None
    distance_to_root = payload.get("distanceToRoot")

    if not root:
        return jsonify({"error": "root is required"}), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO lookups (
              root, meaning, best_headword, similarity_score,
              language, distance_to_root, created_by_user_id
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
            """,
            (root, meaning, best_headword, similarity_score, language, distance_to_root, int(current_user.id)),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({"status": "ok", "id": new_id}), 201
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/history", methods=["GET"])
def history():
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """
            SELECT
              l.id, l.root, l.meaning, l.best_headword, l.similarity_score,
              l.distance_to_root, l.language, l.created_at,
              l.created_by_user_id,
              u.username AS inserted_by
            FROM lookups l
            LEFT JOIN users u ON u.id = l.created_by_user_id
            ORDER BY l.created_at DESC
            LIMIT 100
            """
        )
        return jsonify(cur.fetchall()), 200
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/lookup/<int:lookup_id>", methods=["PUT"])
@roles_required("admin", "editor")
def update_lookup(lookup_id: int):
    payload = request.get_json(force=True, silent=True) or {}
    meaning = (payload.get("meaning") or "").strip()
    best_headword = (payload.get("bestHeadword") or "").strip()
    similarity_score = payload.get("similarityScore")
    language = (payload.get("language") or "").strip() or None
    distance_to_root = payload.get("distanceToRoot")

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT created_by_user_id FROM lookups WHERE id=%s", (int(lookup_id),))
        owner_row = cur.fetchone()
        if not owner_row:
            return jsonify({"error": "lookup not found"}), 404

        if not can_modify_lookup(owner_row["created_by_user_id"]):
            return jsonify({"error": "forbidden"}), 403

        cur2 = conn.cursor()
        cur2.execute(
            """
            UPDATE lookups
            SET meaning=%s, best_headword=%s, similarity_score=%s,
                language=%s, distance_to_root=%s
            WHERE id=%s
            """,
            (meaning, best_headword, similarity_score, language, distance_to_root, int(lookup_id)),
        )
        conn.commit()
        return jsonify({"status": "updated"}), 200
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/lookup/<int:lookup_id>", methods=["DELETE"])
@roles_required("admin", "editor")
def delete_lookup(lookup_id: int):
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT created_by_user_id FROM lookups WHERE id=%s", (int(lookup_id),))
        owner_row = cur.fetchone()
        if not owner_row:
            return jsonify({"error": "lookup not found"}), 404

        if not can_modify_lookup(owner_row["created_by_user_id"]):
            return jsonify({"error": "forbidden"}), 403

        cur2 = conn.cursor()
        cur2.execute("DELETE FROM lookups WHERE id=%s", (int(lookup_id),))
        conn.commit()
        return jsonify({"status": "deleted"}), 200
    finally:
        if conn:
            put_conn(conn)


@app.route("/api/stats", methods=["GET"])
def stats():
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute(
            """
            SELECT
              COUNT(*) AS total_lookups,
              COUNT(DISTINCT root) AS distinct_roots,
              SUM(CASE WHEN similarity_score IS NOT NULL THEN 1 ELSE 0 END) AS scored_count,
              SUM(COALESCE(similarity_score, 0)) AS total_similarity_score,
              AVG(similarity_score) AS avg_similarity_score
            FROM lookups
            """
        )
        row = cur.fetchone()

        cur.execute(
            """
            SELECT
              COALESCE(language, 'Unknown') AS language,
              COUNT(*) AS total_roots,
              SUM(COALESCE(similarity_score, 0)) AS total_similarity_score,
              CASE
                WHEN COUNT(*) = 0 THEN 0
                ELSE (SUM(COALESCE(similarity_score, 0)) * 100.0 / COUNT(*))
              END AS percent_sanskrit
            FROM lookups
            GROUP BY COALESCE(language, 'Unknown')
            ORDER BY total_roots DESC
            """
        )
        by_lang = cur.fetchall()

        return jsonify(
            {
                **row,
                "by_language": by_lang,
            }
        ), 200
    finally:
        if conn:
            put_conn(conn)


# ---------------------------
# Contact -> email (Brevo)
# ---------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.route("/api/contact", methods=["POST"])
def contact():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    message = (data.get("message") or "").strip()

    if not name or not email or not message:
        return jsonify({"error": "name, email, message required"}), 400
    if len(name) > 120 or len(email) > 200 or len(message) > 5000:
        return jsonify({"error": "field too long"}), 400
    if not _EMAIL_RE.match(email):
        return jsonify({"error": "invalid email"}), 400

    if not (BREVO_API_KEY and CONTACT_TO_EMAIL and BREVO_SENDER_EMAIL):
        return jsonify({"error": "email_not_configured"}), 500

    brevo_payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": CONTACT_TO_EMAIL}],
        "replyTo": {"email": email, "name": name},
        "subject": f"IndLex contact from {name}",
        "textContent": f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}\n",
    }

    try:
        r = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": BREVO_API_KEY,
                "content-type": "application/json",
            },
            json=brevo_payload,
            timeout=15,
        )
    except Exception as e:
        return jsonify({"error": "send_failed", "detail": str(e)}), 502

    if not (200 <= r.status_code < 300):
        return jsonify({"error": "send_failed", "status": r.status_code, "detail": r.text}), 502

    return jsonify({"status": "sent"}), 200



if __name__ == "__main__":
    # Local dev only
    os.environ.setdefault("APP_ENV", "local")
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="127.0.0.1", port=port, debug=True)
