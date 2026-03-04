# app.py (Postgres + Flask-Login + CORS; static frontend calls this API)
import os
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor

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
import requests

AP90_BASE = "https://api.c-salt.uni-koeln.de/dicts/ap90/restful/entries"

DATABASE_URL = os.environ.get("DATABASE_URL")  # Render sets this for Postgres
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:8080")
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

# Cross-site cookies (static site on a different domain calling API with credentials)
# If you don't use cookie auth, you can drop these.
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True

CORS(
    app,
    supports_credentials=True,
    resources={r"/api/*": {"origins": [FRONTEND_ORIGIN]}},
)

login_manager = LoginManager(app)


def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "Set it to your Postgres connection string (Render Postgres)."
        )
    # sslmode=prefer works for most hosted Postgres; you can override via env if needed
    sslmode = os.environ.get("PGSSLMODE", "prefer")
    conn = psycopg2.connect(DATABASE_URL, sslmode=sslmode, cursor_factory=RealDictCursor)
    return conn


# ----- DB INIT -----


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
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
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, role_id),
            CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
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
            language TEXT,
            distance_to_root INTEGER,
            created_by_user_id INTEGER,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT fk_created_by FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    # Seed roles
    cur.execute(
        "INSERT INTO roles (name) VALUES (%s) ON CONFLICT (name) DO NOTHING;",
        ("admin",),
    )
    cur.execute(
        "INSERT INTO roles (name) VALUES (%s) ON CONFLICT (name) DO NOTHING;",
        ("editor",),
    )

    # Seed default admin user if no users exist
    cur.execute("SELECT COUNT(*) AS c FROM users;")
    users_count = cur.fetchone()["c"]

    if users_count == 0:
        password_hash = generate_password_hash("admin123")
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id;",
            ("admin", password_hash),
        )
        admin_user_id = cur.fetchone()["id"]

        cur.execute("SELECT id FROM roles WHERE name = %s;", ("admin",))
        admin_role_id = cur.fetchone()["id"]

        cur.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (admin_user_id, admin_role_id),
        )

    conn.commit()
    conn.close()


# ----- USER CLASS & HELPERS -----


class User(UserMixin):
    def __init__(self, user_id, username, is_active=True):
        self.id = user_id
        self.username = username
        self._is_active = bool(is_active)

    def is_active(self):
        return self._is_active


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, is_active FROM users WHERE id = %s;", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return User(row["id"], row["username"], row["is_active"])


def get_user_roles(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = %s
        """,
        (user_id,),
    )
    roles = [r["name"] for r in cur.fetchall()]
    conn.close()
    return roles


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user_roles = get_user_roles(current_user.id)
            if not any(r in user_roles for r in roles):
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def can_modify_lookup(created_by_user_id) -> bool:
    if not current_user.is_authenticated:
        return False

    roles = get_user_roles(current_user.id)

    if "admin" in roles:
        return True

    if "editor" in roles:
        return created_by_user_id is not None and int(created_by_user_id) == int(
            current_user.id
        )

    return False


# ----- AUTH ROUTES -----


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password_hash, is_active FROM users WHERE username = %s;",
        (username,),
    )
    row = cur.fetchone()
    conn.close()

    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    if not row["is_active"]:
        return jsonify({"error": "user inactive"}), 403

    user = User(row["id"], row["username"], row["is_active"])
    login_user(user)

    roles = get_user_roles(user.id)
    return jsonify(
        {
            "status": "logged_in",
            "user_id": user.id,
            "username": user.username,
            "roles": roles,
        }
    ), 200


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
    return jsonify(
        {
            "authenticated": True,
            "user_id": current_user.id,
            "username": current_user.username,
            "roles": roles,
        }
    ), 200


# --- NEW: Password management ---


@app.route("/api/change_password", methods=["POST"])
@login_required
def change_password():
    """
    Logged-in user changes their own password.
    Body: { "oldPassword": "...", "newPassword": "..." }
    """
    data = request.get_json(force=True, silent=True) or {}
    old_pw = data.get("oldPassword") or ""
    new_pw = data.get("newPassword") or ""

    if not old_pw or not new_pw:
        return jsonify({"error": "oldPassword and newPassword required"}), 400

    # Basic guardrails (adjust as you like)
    if len(new_pw) < 8:
        return jsonify({"error": "newPassword must be at least 8 characters"}), 400
    if old_pw == new_pw:
        return jsonify({"error": "newPassword must be different"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = %s;", (current_user.id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "user not found"}), 404

    if not check_password_hash(row["password_hash"], old_pw):
        conn.close()
        return jsonify({"error": "invalid old password"}), 401

    cur.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s;",
        (generate_password_hash(new_pw), current_user.id),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "password_updated"}), 200


@app.route("/api/admin/set_password", methods=["POST"])
@roles_required("admin")
def admin_set_password():
    """
    Admin sets password for any user (admin/editor/etc).
    Body: { "username": "editor1", "newPassword": "..." }
    """
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    new_pw = data.get("newPassword") or ""

    if not username or not new_pw:
        return jsonify({"error": "username and newPassword required"}), 400

    if len(new_pw) < 8:
        return jsonify({"error": "newPassword must be at least 8 characters"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s;", (username,))
    target = cur.fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "user not found"}), 404

    cur.execute(
        "UPDATE users SET password_hash = %s WHERE username = %s;",
        (generate_password_hash(new_pw), username),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "password_set", "username": username}), 200


# ----- BUSINESS ROUTES -----


@app.route("/api/lookup_or_history", methods=["GET"])
def lookup_or_history():
    root = (request.args.get("root") or "").strip()
    meaning = (request.args.get("meaning") or "").strip()
    language = (request.args.get("language") or "").strip()

    if not root:
        return jsonify({"error": "missing root parameter"}), 400

    conn = get_db()
    cur = conn.cursor()

    if language:
        cur.execute(
            """
            SELECT id, root, meaning, best_headword, similarity_score,
                   distance_to_root, created_at, language, created_by_user_id
            FROM lookups
            WHERE root = %s AND (language = %s OR language IS NULL)
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (root, language),
        )
    else:
        cur.execute(
            """
            SELECT id, root, meaning, best_headword, similarity_score,
                   distance_to_root, created_at, language, created_by_user_id
            FROM lookups
            WHERE root = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (root,),
        )

    row = cur.fetchone()
    conn.close()

    if row:
        return jsonify(
            {
                "source": "db",
                "id": row["id"],
                "root": row["root"],
                "meaning": row["meaning"],
                "best_headword": row["best_headword"],
                "similarity_score": row["similarity_score"],
                "distance_to_root": row["distance_to_root"],
                "created_at": row["created_at"],
                "language": row["language"],
                "created_by_user_id": row["created_by_user_id"],
            }
        ), 200

    if not meaning:
        return jsonify({"error": "no DB record and missing meaning to query AP90"}), 400

    try:
        resp = requests.get(
            AP90_BASE,
            params={
                "field": "xml",
                "query": meaning,
                "query_type": "term",
                "size": 100,
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return jsonify({"error": "upstream error", "detail": str(e)}), 502

    try:
        data = resp.json()
    except ValueError:
        return resp.text, resp.status_code, {"Content-Type": "text/plain; charset=utf-8"}

    return jsonify({"source": "ap90", "raw": data}), resp.status_code


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

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO lookups (
            root, meaning, best_headword, similarity_score,
            language, distance_to_root, created_by_user_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            root,
            meaning,
            best_headword,
            similarity_score,
            language,
            distance_to_root,
            current_user.id,
        ),
    )
    new_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "id": new_id}), 201


@app.route("/api/history", methods=["GET"])
def history():
    conn = get_db()
    cur = conn.cursor()
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
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows), 200


@app.route("/api/lookup/<int:lookup_id>", methods=["PUT"])
@roles_required("admin", "editor")
def update_lookup(lookup_id: int):
    payload = request.get_json(force=True, silent=True) or {}
    meaning = (payload.get("meaning") or "").strip()
    best_headword = (payload.get("bestHeadword") or "").strip()
    similarity_score = payload.get("similarityScore")
    language = (payload.get("language") or "").strip() or None
    distance_to_root = payload.get("distanceToRoot")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT created_by_user_id FROM lookups WHERE id = %s;", (lookup_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "lookup not found"}), 404
    if not can_modify_lookup(existing["created_by_user_id"]):
        conn.close()
        return jsonify({"error": "forbidden"}), 403

    cur.execute(
        """
        UPDATE lookups
        SET meaning = %s, best_headword = %s, similarity_score = %s,
            language = %s, distance_to_root = %s
        WHERE id = %s
        """,
        (meaning, best_headword, similarity_score, language, distance_to_root, lookup_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "updated"}), 200


@app.route("/api/lookup/<int:lookup_id>", methods=["DELETE"])
@roles_required("admin", "editor")
def delete_lookup(lookup_id: int):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT created_by_user_id FROM lookups WHERE id = %s;", (lookup_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "lookup not found"}), 404
    if not can_modify_lookup(existing["created_by_user_id"]):
        conn.close()
        return jsonify({"error": "forbidden"}), 403

    cur.execute("DELETE FROM lookups WHERE id = %s;", (lookup_id,))
    conn.commit()
    conn.close()

    return jsonify({"status": "deleted"}), 200


@app.route("/api/stats", methods=["GET"])
def stats():
    conn = get_db()
    cur = conn.cursor()

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
    conn.close()

    return jsonify(
        {
            "total_lookups": row["total_lookups"],
            "distinct_roots": row["distinct_roots"],
            "scored_count": row["scored_count"],
            "total_similarity_score": row["total_similarity_score"],
            "avg_similarity_score": row["avg_similarity_score"],
            "by_language": by_lang,
        }
    ), 200


# Run DB init on startup (Gunicorn import-time)
# This is safe because all CREATE TABLE/INSERT ... ON CONFLICT are idempotent.
init_db()

if __name__ == "__main__":
    # Local dev only (Render uses gunicorn)
    app.config["SESSION_COOKIE_SECURE"] = False
    app.run(host="127.0.0.1", port=5001, debug=True)
