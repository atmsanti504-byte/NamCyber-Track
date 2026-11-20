"""NamCyber Track backend: public report intake + protected admin API (Flask + SQLite)."""
import os, json, sqlite3, secrets, time, hmac, csv, io, re, threading, urllib.request
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory, Response

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH", os.path.join(BASE, "reports.db"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(12)
    print(f"\n[!] ADMIN_PASSWORD not set. Temporary admin password: {ADMIN_PASSWORD}\n")
ALERT_WEBHOOK = os.environ.get("ALERT_WEBHOOK")  # Slack/Teams-style incoming webhook

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1", MAX_CONTENT_LENGTH=200_000)

SEVERITIES = ["Low", "Medium", "High", "Critical"]
STATUSES = ["New", "Triaged", "Investigating", "Escalated", "Resolved", "Closed"]


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS reports(
          id TEXT PRIMARY KEY, created TEXT, category TEXT, severity TEXT, status TEXT DEFAULT 'New',
          assignee TEXT DEFAULT '', notes TEXT DEFAULT '', country TEXT, region TEXT, city TEXT,
          lat REAL, lon REAL, loss REAL DEFAULT 0, currency TEXT, victims INTEGER DEFAULT 1,
          occurred TEXT, tlp TEXT, data TEXT);
        CREATE TABLE IF NOT EXISTS indicators(report_id TEXT, kind TEXT, value TEXT);
        CREATE INDEX IF NOT EXISTS ix_ind ON indicators(value);
        CREATE INDEX IF NOT EXISTS ix_rep ON reports(created);""")


init()
_hits = {}


def limited(key, n, window):
    now = time.time()
    h = [t for t in _hits.get(key, []) if now - t < window]
    _hits[key] = h
    if len(h) >= n:
        return True
    h.append(now)
    return False


def clean(v, n=2000):
    return str(v or "").strip()[:n]


def refang(v):
    return re.sub(r"\[\.\]|\(\.\)", ".", v.strip().lower().replace("hxxp", "http"))


def num(v, lo, hi):
    try:
        x = float(v)
        return x if lo <= x <= hi else None
    except (TypeError, ValueError):
        return None


def alert(r):
    if not (ALERT_WEBHOOK and r["severity"] == "Critical"):
        return
    msg = {"text": f"🚨 Critical report {r['id']}: {r['category']} in {r['city'] or ''} {r['country']}"}
    def send():
        try:
            req = urllib.request.Request(ALERT_WEBHOOK, json.dumps(msg).encode(), {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print("alert failed:", e)
    threading.Thread(target=send, daemon=True).start()


# ---------- public ----------
@app.get("/")
def index():
    return send_from_directory(os.path.join(BASE, "public"), "index.html")


@app.get("/admin")
def admin_page():
    return send_from_directory(os.path.join(BASE, "public"), "admin.html")


@app.post("/api/reports")
def submit():
    if limited("sub:" + request.remote_addr, 10, 3600):
        return jsonify(error="Too many submissions, try later."), 429
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="Invalid JSON"), 400
    inc, loc, imp = d.get("incident") or {}, d.get("location") or {}, d.get("impact") or {}
    rep, ind = d.get("reporter") or {}, d.get("indicators") or {}
    sev = inc.get("severity") if inc.get("severity") in SEVERITIES else "Medium"
    cat, desc, country, occ = clean(inc.get("category"), 100), clean(inc.get("description"), 5000), clean(loc.get("country"), 100), clean(inc.get("occurred"), 40)
    if not cat or len(desc) < 20 or not country or not occ:
        return jsonify(error="Missing required fields"), 400
    anon = bool(rep.get("anonymous"))
    stored = {"reporter": {"type": clean(rep.get("type"), 60), "org": clean(rep.get("org"), 200),
                           "email": "" if anon else clean(rep.get("email"), 200), "anonymous": anon},
              "incident": {"category": cat, "vector": clean(inc.get("vector"), 60), "severity": sev, "occurred": occ,
                           "detected": clean(inc.get("detected"), 40), "reported_status": clean(inc.get("status"), 40),
                           "description": desc, "actor": clean(inc.get("actor"), 200)},
              "location": {"country": country, "region": clean(loc.get("region"), 100), "city": clean(loc.get("city"), 100),
                           "timezone": clean(loc.get("timezone"), 60)},
              "impact": {"payment": clean(imp.get("payment"), 60), "affected": [clean(x, 60) for x in (imp.get("affected") or [])[:20]],
                         "actions": [clean(x, 60) for x in (imp.get("actions") or [])[:20]], "evidence": clean(imp.get("evidence"), 500)},
              "indicators": {}}
    rows = []
    for kind in ("urls", "ips", "senders", "hashes", "wallets"):
        vals = [clean(v, 500) for v in (ind.get(kind) or [])[:50] if clean(v, 500)]
        stored["indicators"][kind] = vals
        rows += [(kind, refang(v)) for v in vals]
    rid = "RS-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + secrets.token_hex(3).upper()
    rec = dict(id=rid, created=datetime.now(timezone.utc).isoformat(timespec="seconds"), category=cat, severity=sev,
               country=country, region=stored["location"]["region"], city=stored["location"]["city"],
               lat=num(loc.get("lat"), -90, 90), lon=num(loc.get("lon"), -180, 180), loss=num(imp.get("loss"), 0, 1e12) or 0,
               currency=clean(imp.get("currency"), 10), victims=int(num(imp.get("victims"), 1, 1e9) or 1),
               occurred=occ, tlp=clean(d.get("sharing"), 20), data=json.dumps(stored))
    with db() as c:
        c.execute("INSERT INTO reports(id,created,category,severity,country,region,city,lat,lon,loss,currency,victims,occurred,tlp,data) "
                  "VALUES(:id,:created,:category,:severity,:country,:region,:city,:lat,:lon,:loss,:currency,:victims,:occurred,:tlp,:data)", rec)
        c.executemany("INSERT INTO indicators VALUES(?,?,?)", [(rid, k, v) for k, v in rows])
    alert(rec)
    return jsonify(id=rid), 201


# ---------- admin ----------
def auth(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("admin"):
            return jsonify(error="Unauthorized"), 401
        if request.method != "GET" and not request.is_json and request.method != "POST":
            return jsonify(error="JSON required"), 415
        return f(*a, **k)
    return w


@app.post("/api/admin/login")
def login():
    if limited("login:" + request.remote_addr, 5, 900):
        return jsonify(error="Too many attempts. Wait 15 minutes."), 429
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if hmac.compare_digest(str(pw).encode(), ADMIN_PASSWORD.encode()):
        session["admin"] = True
        return jsonify(ok=True)
    return jsonify(error="Wrong password"), 401


@app.post("/api/admin/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/admin/session")
def sess():
    return jsonify(admin=bool(session.get("admin")))


def query_reports():
    q, args = "SELECT id,created,category,severity,status,assignee,country,city,lat,lon,loss,currency,victims,occurred,tlp FROM reports WHERE 1=1", []
    for f in ("status", "severity", "country", "category"):
        if request.args.get(f):
            q += f" AND {f}=?"
            args.append(request.args[f])
    s = request.args.get("q")
    if s:
        q += " AND (id LIKE ? OR data LIKE ? OR id IN (SELECT report_id FROM indicators WHERE value LIKE ?))"
        args += [f"%{s}%", f"%{s}%", f"%{refang(s)}%"]
    q += " ORDER BY created DESC LIMIT 1000"
    with db() as c:
        return [dict(r) for r in c.execute(q, args)]


@app.get("/api/admin/reports")
@auth
def list_reports():
    return jsonify(query_reports())


@app.get("/api/admin/reports/<rid>")
@auth
def one(rid):
    with db() as c:
        r = c.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not r:
            return jsonify(error="Not found"), 404
        rel = c.execute("""SELECT b.report_id AS id, r.category, r.severity, r.country, a.kind, a.value FROM indicators a
            JOIN indicators b ON a.value=b.value AND a.kind=b.kind AND b.report_id!=a.report_id
            JOIN reports r ON r.id=b.report_id WHERE a.report_id=? LIMIT 50""", (rid,)).fetchall()
    out = dict(r)
    out["data"] = json.loads(out["data"])
    out["related"] = [dict(x) for x in rel]
    return jsonify(out)


@app.patch("/api/admin/reports/<rid>")
@auth
def update(rid):
    d = request.get_json(silent=True) or {}
    sets, args = [], []
    if d.get("status") in STATUSES: sets.append("status=?"); args.append(d["status"])
    if d.get("severity") in SEVERITIES: sets.append("severity=?"); args.append(d["severity"])
    if "assignee" in d: sets.append("assignee=?"); args.append(clean(d["assignee"], 100))
    if "notes" in d: sets.append("notes=?"); args.append(clean(d["notes"], 5000))
    if not sets:
        return jsonify(error="Nothing to update"), 400
    with db() as c:
        c.execute(f"UPDATE reports SET {','.join(sets)} WHERE id=?", args + [rid])
    return jsonify(ok=True)


@app.delete("/api/admin/reports/<rid>")
@auth
def delete(rid):
    with db() as c:
        c.execute("DELETE FROM indicators WHERE report_id=?", (rid,))
        c.execute("DELETE FROM reports WHERE id=?", (rid,))
    return jsonify(ok=True)


@app.get("/api/admin/stats")
@auth
def stats():
    with db() as c:
        g = lambda col: [dict(r) for r in c.execute(f"SELECT {col} AS k, COUNT(*) AS n FROM reports GROUP BY {col} ORDER BY n DESC LIMIT 10")]
        daily = [dict(r) for r in c.execute("SELECT substr(created,1,10) AS k, COUNT(*) AS n FROM reports WHERE created>=date('now','-30 day') GROUP BY k ORDER BY k")]
        top = [dict(r) for r in c.execute("SELECT kind, value, COUNT(DISTINCT report_id) AS n FROM indicators GROUP BY kind,value HAVING n>1 ORDER BY n DESC LIMIT 10")]
        loss_cur = [dict(r) for r in c.execute("SELECT COALESCE(NULLIF(currency,''),'?') AS cur, SUM(loss) AS total, COUNT(*) AS n FROM reports WHERE loss>0 GROUP BY cur ORDER BY total DESC")]
        tot = c.execute("SELECT COUNT(*) n, COALESCE(SUM(loss),0) loss, COALESCE(SUM(victims),0) victims FROM reports").fetchone()
    return jsonify(total=tot["n"], loss=tot["loss"], loss_by_currency=loss_cur, victims=tot["victims"], status=g("status"), severity=g("severity"),
                   category=g("category"), country=g("country"), daily=daily, repeated_indicators=top)


@app.get("/api/admin/export.csv")
@auth
def export():
    rows = query_reports()
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else ["id"])
    w.writeheader()
    for r in rows:
        w.writerow({k: ("'" + str(v) if str(v)[:1] in "=+-@" else v) for k, v in r.items()})  # CSV-injection guard
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=reports.csv"})


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/admin") or request.path == "/admin":
        r.headers["Cache-Control"] = "no-store"
    return r


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
