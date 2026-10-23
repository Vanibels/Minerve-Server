"""Serveur de supervision réseau : API des agents + interface web (Flask, Neon, Vercel)."""

import hashlib
import hmac
import math
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from functools import wraps

import psycopg
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from psycopg.rows import dict_row
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

ON_VERCEL = bool(os.environ.get("VERCEL"))
if ON_VERCEL and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY doit être défini dans les variables d'environnement Vercel.")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_VERCEL,
    MAX_CONTENT_LENGTH=1_000_000,
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
STATUSES = {"online", "offline", "interface_unavailable"}
MIN_AGENTS_PER_OPERATOR = 3      # en dessous, pas de comparaison ni d'incident d'opérateur
OPERATOR_SHARE = 0.5             # part d'agents en incident pour parler d'incident d'opérateur


# --- Base de données (Neon) ------------------------------------------------
def db():
    if "db" not in g:
        g.db = psycopg.connect(os.environ["DATABASE_URL"], autocommit=True, row_factory=dict_row)
    return g.db


@app.teardown_appcontext
def close_db(_error):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# --- Utilitaires -----------------------------------------------------------
def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_equal(a, b):
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def public_url():
    return os.environ.get("PUBLIC_URL") or request.host_url.rstrip("/")


def parse_ts(value):
    moment = datetime.fromisoformat(str(value))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def num(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def text(value, limit=200):
    return None if value is None else str(value)[:limit]


def truncate_ip(ip):
    """Minimisation : on ne garde pas l'adresse publique complète."""
    if not ip:
        return None
    ip = str(ip)[:60]
    if "." in ip:
        return ".".join(ip.split(".")[:3] + ["0"])
    return ":".join(ip.split(":")[:3]) + "::"


@app.template_filter("duration")
def duration_filter(seconds):
    if seconds is None:
        return "en cours"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min {secs} s" if minutes else f"{secs} s"


# --- Sécurité des formulaires web -----------------------------------------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def web_guards():
    g.user = None
    if request.path.startswith("/api/"):
        return
    if request.method == "POST":
        expected = session.get("csrf")
        if not expected or not safe_equal(request.form.get("csrf", ""), expected):
            abort(400)
    if session.get("user_id"):
        g.user = db().execute(
            "SELECT id, email FROM users WHERE id = %s", (session["user_id"],)
        ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def start_session(user_id):
    pending = session.get("claim")
    session.clear()
    session["user_id"] = user_id
    if pending:
        session["claim"] = pending


def link_pending_claim(user_id):
    """Lie à ce compte l'agent dont le code de liaison est en attente dans la session."""
    code = session.pop("claim", None)
    if not code:
        return None
    row = db().execute(
        "UPDATE agents SET user_id = %s, claim_hash = NULL "
        "WHERE claim_hash = %s AND user_id IS NULL RETURNING hostname",
        (user_id, sha(code)),
    ).fetchone()
    return (row["hostname"] or "Appareil") if row else None


# --- Pages : comptes -------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if session.get("user_id") else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:200]
        password = request.form.get("password", "")
        if not EMAIL_RE.match(email):
            flash("Adresse e-mail invalide.", "error")
        elif len(password) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères.", "error")
        else:
            try:
                row = db().execute(
                    "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
                    (email, generate_password_hash(password)),
                ).fetchone()
            except psycopg.errors.UniqueViolation:
                flash("Un compte existe déjà avec cet e-mail.", "error")
            else:
                start_session(row["id"])
                host = link_pending_claim(row["id"])
                flash(f"Compte créé. « {host} » est lié à ton compte." if host else "Compte créé.", "ok")
                return redirect(url_for("dashboard"))
    return render_template("register.html", claim=bool(session.get("claim")))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db().execute(
            "SELECT id, password_hash FROM users WHERE email = %s", (email,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            start_session(user["id"])
            host = link_pending_claim(user["id"])
            if host:
                flash(f"« {host} » est lié à ton compte.", "ok")
            return redirect(url_for("dashboard"))
        flash("E-mail ou mot de passe incorrect.", "error")
    return render_template("login.html", claim=bool(session.get("claim")))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/link/<code>", methods=["GET", "POST"])
def link(code):
    """Page ouverte par l'agent à sa première connexion."""
    agent = db().execute(
        "SELECT hostname, os, interface, kind FROM agents WHERE claim_hash = %s AND user_id IS NULL",
        (sha(code),),
    ).fetchone()
    if agent is None:
        return render_template(
            "message.html", title="Lien invalide",
            text="Ce lien de liaison est invalide ou a déjà été utilisé. Relance l'agent avec --reset pour en obtenir un nouveau.",
        ), 404
    if g.user is None:
        session["claim"] = code
        flash(f"Crée un compte, ou connecte-toi, pour lier « {agent['hostname']} » à ton compte.", "ok")
        return redirect(url_for("register"))
    if request.method == "POST":
        session["claim"] = code
        host = link_pending_claim(g.user["id"])
        flash(f"« {host} » est lié à ton compte." if host else "Liaison impossible.", "ok" if host else "error")
        return redirect(url_for("dashboard"))
    return render_template("link.html", agent=agent)


# --- Page : tableau de bord ------------------------------------------------
def incident_scope(incident, user_id):
    """Portée d'un incident : appareil, foyer (compte) ou opérateur."""
    end = incident["ended_at"] or datetime.now(timezone.utc)
    if incident["asn"]:
        active = db().execute(
            "SELECT count(DISTINCT agent_uid) AS n FROM measures "
            "WHERE asn = %s AND ts > now() - interval '24 hours'", (incident["asn"],),
        ).fetchone()["n"]
        affected = db().execute(
            "SELECT count(DISTINCT agent_uid) AS n FROM incidents "
            "WHERE asn = %s AND started_at <= %s AND coalesce(ended_at, now()) >= %s",
            (incident["asn"], end, incident["started_at"]),
        ).fetchone()["n"]
        if active >= MIN_AGENTS_PER_OPERATOR and affected >= MIN_AGENTS_PER_OPERATOR \
                and affected / active >= OPERATOR_SHARE:
            return "opérateur"
    same_home = db().execute(
        "SELECT count(DISTINCT i.agent_uid) AS n FROM incidents i "
        "JOIN agents a ON a.uid = i.agent_uid "
        "WHERE a.user_id = %s AND i.agent_uid <> %s AND i.started_at <= %s "
        "AND coalesce(i.ended_at, now()) >= %s",
        (user_id, incident["agent_uid"], end, incident["started_at"]),
    ).fetchone()["n"]
    return "foyer" if same_home else "appareil"


def window_stats(where, params):
    row = db().execute(
        "SELECT count(*) AS total, count(*) FILTER (WHERE status = 'online') AS online, "
        "avg(latency_ms) FILTER (WHERE status = 'online') AS latency, "
        "count(DISTINCT agent_uid) AS agents "
        f"FROM measures WHERE ts > now() - interval '24 hours' AND {where}", params,
    ).fetchone()
    return {
        "availability": 100 * row["online"] / row["total"] if row["total"] else None,
        "latency": row["latency"],
        "agents": row["agents"],
    }


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = g.user["id"]
    devices = db().execute(
        "SELECT uid, hostname, os, interface, kind, last_seen FROM agents "
        "WHERE user_id = %s ORDER BY created_at", (user_id,),
    ).fetchall()

    operators = {}
    for device in devices:
        device.update(window_stats("agent_uid = %s", (device["uid"],)))
        last = db().execute(
            "SELECT status, latency_ms, fai, asn, ts FROM measures "
            "WHERE agent_uid = %s ORDER BY ts DESC LIMIT 1", (device["uid"],),
        ).fetchone()
        bandwidth = db().execute(
            "SELECT bandwidth_mbps FROM measures WHERE agent_uid = %s "
            "AND bandwidth_mbps IS NOT NULL ORDER BY ts DESC LIMIT 1", (device["uid"],),
        ).fetchone()
        device["last"] = last
        device["bandwidth"] = bandwidth["bandwidth_mbps"] if bandwidth else None
        fresh = last and (datetime.now(timezone.utc) - last["ts"]).total_seconds() < 900
        device["state"] = "inactif" if not fresh else ("en ligne" if last["status"] == "online" else "hors ligne")
        if last and last["asn"] and last["asn"] not in operators:
            stats = window_stats("asn = %s", (last["asn"],))
            stats["name"] = last["fai"] or last["asn"]
            stats["enough"] = stats["agents"] >= MIN_AGENTS_PER_OPERATOR
            operators[last["asn"]] = stats

    home = window_stats(
        "agent_uid IN (SELECT uid FROM agents WHERE user_id = %s)", (user_id,)
    ) if devices else None

    incidents = db().execute(
        "SELECT i.*, a.hostname FROM incidents i JOIN agents a ON a.uid = i.agent_uid "
        "WHERE a.user_id = %s ORDER BY i.started_at DESC LIMIT 20", (user_id,),
    ).fetchall()
    for incident in incidents:
        incident["scope"] = incident_scope(incident, user_id)

    return render_template("dashboard.html", devices=devices, home=home,
                           operators=list(operators.values()), incidents=incidents)


# --- API des agents --------------------------------------------------------
def agent_auth():
    uid = request.headers.get("X-Agent-UID", "")
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    if not uid or not token:
        return None
    agent = db().execute("SELECT uid, user_id, token_hash FROM agents WHERE uid = %s", (uid,)).fetchone()
    if agent and safe_equal(agent["token_hash"], sha(token)):
        return agent
    return None


@app.post("/api/agents/register")
def api_register():
    data = request.get_json(silent=True) or {}
    uid = str(data.get("uid", ""))
    try:
        uuid.UUID(uid)
    except ValueError:
        return jsonify(error="uid invalide"), 400
    token = secrets.token_urlsafe(32)
    claim = secrets.token_urlsafe(16)
    try:
        db().execute(
            "INSERT INTO agents (uid, token_hash, claim_hash, hostname, os, interface, kind) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (uid, sha(token), sha(claim), text(data.get("hostname")), text(data.get("os")),
             text(data.get("interface")), text(data.get("kind"))),
        )
    except psycopg.errors.UniqueViolation:
        return jsonify(error="agent déjà enregistré"), 409
    return jsonify(token=token, claim_url=f"{public_url()}/link/{claim}"), 201


@app.get("/api/agents/status")
def api_status():
    agent = agent_auth()
    if agent is None:
        return jsonify(error="non autorisé"), 401
    return jsonify(linked=agent["user_id"] is not None)


@app.post("/api/measures")
def api_measures():
    agent = agent_auth()
    if agent is None:
        return jsonify(error="non autorisé"), 401
    items = (request.get_json(silent=True) or {}).get("measures")
    if not isinstance(items, list) or len(items) > 500:
        return jsonify(error="format invalide"), 400

    rows = []
    for item in items:
        try:
            moment = parse_ts(item["timestamp"])
            status = item["status"]
        except (KeyError, ValueError, TypeError):
            continue
        if status not in STATUSES:
            continue
        rows.append((agent["uid"], moment, status, num(item.get("latency_ms")),
                     num(item.get("bandwidth_mbps")), truncate_ip(item.get("public_ip")),
                     text(item.get("fai")), text(item.get("asn")), text(item.get("interface"))))
    if rows:
        with db().transaction(), db().cursor() as cur:
            cur.executemany(
                "INSERT INTO measures (agent_uid, ts, status, latency_ms, bandwidth_mbps, "
                "public_ip, fai, asn, interface) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (agent_uid, ts) DO NOTHING", rows)
    db().execute("UPDATE agents SET last_seen = now() WHERE uid = %s", (agent["uid"],))
    return jsonify(stored=len(rows))


@app.post("/api/incidents")
def api_incidents():
    agent = agent_auth()
    if agent is None:
        return jsonify(error="non autorisé"), 401
    data = request.get_json(silent=True) or {}
    try:
        started = parse_ts(data["started_at"])
        ended = parse_ts(data["ended_at"]) if data.get("ended_at") else None
        kind = data["type"]
    except (KeyError, ValueError, TypeError):
        return jsonify(error="format invalide"), 400
    if kind not in ("outage_start", "outage_end"):
        return jsonify(error="type inconnu"), 400

    duration = data.get("duration_s")
    duration = int(duration) if isinstance(duration, (int, float)) and not isinstance(duration, bool) else None
    fai, asn, reason = text(data.get("fai")), text(data.get("asn")), text(data.get("reason"))

    if kind == "outage_end":
        updated = db().execute(
            "UPDATE incidents SET ended_at = %s, duration_s = %s WHERE agent_uid = %s AND started_at = %s",
            (ended, duration, agent["uid"], started),
        ).rowcount
        if updated:
            return jsonify(ok=True)
    db().execute(
        "INSERT INTO incidents (agent_uid, started_at, ended_at, duration_s, reason, fai, asn) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (agent_uid, started_at) DO NOTHING",
        (agent["uid"], started, ended, duration, reason, fai, asn),
    )
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=True)
