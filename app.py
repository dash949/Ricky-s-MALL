import os, sqlite3, secrets, string, datetime, pathlib
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.utils import secure_filename
from werkzeug.security import safe_join
from dotenv import load_dotenv
import requests

load_dotenv()
app = Flask(__name__)
app.secret_key = "ricky-session-key-f21d13ad17048b6d5c364f38fb00264fd01da80d284600ab29046a808f091ebe"  # Keep this private; change it if the website is compromised.
OWNER_ID = os.getenv("OWNER_ID", "1565278113527496769")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "http://127.0.0.1:5000/auth/discord/callback")
DISCORD_SERVER_INVITE = os.getenv("DISCORD_SERVER_INVITE", "https://discord.gg/your-invite")
UPLOAD_DIR = pathlib.Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
DB = "ricky.db"
ALLOWED = {"zip", "rar", "7z"}

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT NOT NULL, avatar TEXT, custom_name TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS resources(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, boost_count INTEGER DEFAULT 0, file_name TEXT, preview_name TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, resource_id INTEGER, proof_name TEXT, status TEXT DEFAULT 'pending', submitted_at TEXT, reviewed_at TEXT);
        CREATE TABLE IF NOT EXISTS unlocks(user_id TEXT, resource_id INTEGER, unlocked_at TEXT, PRIMARY KEY(user_id, resource_id));
        CREATE TABLE IF NOT EXISTS codes(code TEXT PRIMARY KEY, resource_id INTEGER, use_limit INTEGER, uses INTEGER DEFAULT 0, expires_at TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS code_redemptions(code TEXT, user_id TEXT, redeemed_at TEXT, PRIMARY KEY(code,user_id));
        """)
init_db()

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    with db() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def is_owner():
    return session.get("user_id") == OWNER_ID

def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not current_user():
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapped

def owner_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not current_user(): return redirect(url_for("login"))
        if not is_owner(): abort(403)
        return f(*a, **kw)
    return wrapped

@app.context_processor
def common():
    return {"user": current_user(), "owner": is_owner(), "server_invite": DISCORD_SERVER_INVITE}

@app.route("/")
def home():
    with db() as c:
        resources = c.execute("SELECT * FROM resources ORDER BY id DESC").fetchall()
    return render_template("home.html", resources=resources)

@app.route("/resources")
def resources():
    with db() as c:
        items = c.execute("SELECT * FROM resources ORDER BY id DESC").fetchall()
    return render_template("resources.html", resources=items)

@app.route("/resource/<int:rid>")
def resource(rid):
    with db() as c:
        item = c.execute("SELECT * FROM resources WHERE id=?", (rid,)).fetchone()
        if not item: abort(404)
        unlocked = bool(session.get("user_id") and c.execute("SELECT 1 FROM unlocks WHERE user_id=? AND resource_id=?", (session["user_id"],rid)).fetchone())
        submitted = bool(session.get("user_id") and c.execute("SELECT 1 FROM submissions WHERE user_id=? AND resource_id=? AND status='pending'", (session["user_id"],rid)).fetchone())
    return render_template("resource.html", item=item, unlocked=unlocked, submitted=submitted)

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/auth/discord")
def discord_login():
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        flash("Discord OAuth is not configured yet. Follow the README setup steps.")
        return redirect(url_for("login"))
    state = secrets.token_urlsafe(20)
    session["oauth_state"] = state
    scope = "identify"
    from urllib.parse import urlencode
    query = urlencode({"client_id":DISCORD_CLIENT_ID,"redirect_uri":DISCORD_REDIRECT_URI,"response_type":"code","scope":scope,"state":state})
    return redirect("https://discord.com/oauth2/authorize?"+query)

@app.route("/auth/discord/callback")
def discord_callback():
    if request.args.get("state") != session.pop("oauth_state", None): abort(400)
    code = request.args.get("code")
    if not code: return redirect(url_for("login"))
    token_resp = requests.post("https://discord.com/api/oauth2/token", data={
        "client_id": DISCORD_CLIENT_ID, "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type":"authorization_code", "code":code, "redirect_uri":DISCORD_REDIRECT_URI
    }, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=15)
    if not token_resp.ok: abort(400, "Discord token exchange failed")
    token = token_resp.json().get("access_token")
    profile_resp = requests.get("https://discord.com/api/users/@me", headers={"Authorization":"Bearer "+token}, timeout=15)
    if not profile_resp.ok: abort(400, "Discord profile fetch failed")
    profile = profile_resp.json()
    uid = str(profile["id"])
    avatar = (f"https://cdn.discordapp.com/avatars/{uid}/{profile['avatar']}.png" if profile.get("avatar") else "")
    with db() as c:
        c.execute("INSERT OR IGNORE INTO users(id,username,avatar,custom_name,created_at) VALUES(?,?,?,?,?)",
                  (uid, profile.get("username","Discord user"), avatar, profile.get("username","Discord user"), datetime.datetime.utcnow().isoformat()))
        c.execute("UPDATE users SET username=?,avatar=? WHERE id=?", (profile.get("username","Discord user"), avatar, uid))
    session["user_id"] = uid
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    if request.method == "POST":
        name = (request.form.get("custom_name","").strip()[:32] or current_user()["username"])
        with db() as c: c.execute("UPDATE users SET custom_name=? WHERE id=?", (name,session["user_id"]))
        flash("Profile updated.")
        return redirect(url_for("profile"))
    return render_template("profile.html")

@app.route("/my-resources")
@login_required
def my_resources():
    with db() as c:
        items = c.execute("""SELECT r.* FROM resources r JOIN unlocks u ON u.resource_id=r.id
                            WHERE u.user_id=? ORDER BY u.unlocked_at DESC""", (session["user_id"],)).fetchall()
    return render_template("my_resources.html", resources=items)

@app.route("/redeem", methods=["GET","POST"])
@login_required
def redeem():
    if request.method == "POST":
        code = request.form.get("code","").strip().upper()
        now = datetime.datetime.utcnow()
        with db() as c:
            row = c.execute("SELECT * FROM codes WHERE code=?", (code,)).fetchone()
            if not row: flash("Invalid code.")
            elif row["expires_at"] and datetime.datetime.fromisoformat(row["expires_at"]) < now: flash("This code has expired.")
            elif row["uses"] >= row["use_limit"]: flash("This code has reached its usage limit.")
            elif c.execute("SELECT 1 FROM code_redemptions WHERE code=? AND user_id=?", (code,session["user_id"])).fetchone(): flash("You already used this code.")
            else:
                c.execute("INSERT INTO code_redemptions(code,user_id,redeemed_at) VALUES(?,?,?)",(code,session["user_id"],now.isoformat()))
                c.execute("UPDATE codes SET uses=uses+1 WHERE code=?", (code,))
                c.execute("INSERT OR IGNORE INTO unlocks(user_id,resource_id,unlocked_at) VALUES(?,?,?)",(session["user_id"],row["resource_id"],now.isoformat()))
                flash("Code redeemed! Resource unlocked.")
        return redirect(url_for("redeem"))
    return render_template("redeem.html")

@app.route("/resource/<int:rid>/submit", methods=["POST"])
@login_required
def submit_proof(rid):
    proof = request.files.get("proof")
    if not proof or not proof.filename: flash("Choose a screenshot first."); return redirect(url_for("resource",rid=rid))
    ext = pathlib.Path(proof.filename).suffix.lower()
    if ext not in {".png",".jpg",".jpeg",".webp"}: flash("Upload a PNG, JPG, or WEBP screenshot."); return redirect(url_for("resource",rid=rid))
    safe = secure_filename(f"proof_{session['user_id']}_{rid}_{secrets.token_hex(6)}{ext}")
    proof.save(UPLOAD_DIR/safe)
    with db() as c:
        if c.execute("SELECT 1 FROM submissions WHERE user_id=? AND resource_id=? AND status='pending'",(session["user_id"],rid)).fetchone():
            flash("You already have a pending request for this resource.")
        else:
            c.execute("INSERT INTO submissions(user_id,resource_id,proof_name,status,submitted_at) VALUES(?,?,?,'pending',?)",(session["user_id"],rid,safe,datetime.datetime.utcnow().isoformat()))
            flash("Proof submitted. Please wait for review.")
    return redirect(url_for("resource",rid=rid))

@app.route("/download/<int:rid>")
@login_required
def download(rid):
    with db() as c:
        row = c.execute("SELECT file_name,title FROM resources WHERE id=?", (rid,)).fetchone()
        allowed = c.execute("SELECT 1 FROM unlocks WHERE user_id=? AND resource_id=?",(session["user_id"],rid)).fetchone()
    if not row or not allowed: abort(403)
    if not row["file_name"] or not (UPLOAD_DIR/row["file_name"]).exists(): abort(404)
    return send_file(UPLOAD_DIR/row["file_name"], as_attachment=True, download_name=row["title"]+".zip")

@app.route("/owner")
@owner_required
def owner():
    with db() as c:
        counts = {
            "users": c.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "resources": c.execute("SELECT COUNT(*) FROM resources").fetchone()[0],
            "pending": c.execute("SELECT COUNT(*) FROM submissions WHERE status='pending'").fetchone()[0],
            "codes": c.execute("SELECT COUNT(*) FROM codes").fetchone()[0],
        }
    return render_template("owner.html", counts=counts)

@app.route("/owner/submissions")
@owner_required
def owner_submissions():
    with db() as c:
        rows = c.execute("""SELECT s.*,u.username,u.custom_name,r.title resource_title
        FROM submissions s JOIN users u ON u.id=s.user_id JOIN resources r ON r.id=s.resource_id
        ORDER BY s.submitted_at DESC""").fetchall()
    return render_template("submissions.html", submissions=rows)

@app.route("/owner/proof/<int:sid>")
@owner_required
def owner_proof(sid):
    with db() as c:
        row = c.execute("SELECT proof_name FROM submissions WHERE id=?",(sid,)).fetchone()
    if not row: abort(404)
    return send_file(UPLOAD_DIR/row["proof_name"])

@app.route("/owner/submission/<int:sid>/<action>", methods=["POST"])
@owner_required
def review_submission(sid, action):
    if action not in {"approve","decline"}: abort(400)
    now = datetime.datetime.utcnow().isoformat()
    with db() as c:
        row = c.execute("SELECT user_id,resource_id FROM submissions WHERE id=?",(sid,)).fetchone()
        if not row: abort(404)
        c.execute("UPDATE submissions SET status=?,reviewed_at=? WHERE id=?", (action,now,sid))
        if action == "approve":
            c.execute("INSERT OR IGNORE INTO unlocks(user_id,resource_id,unlocked_at) VALUES(?,?,?)",(row["user_id"],row["resource_id"],now))
    flash(f"Submission {action}d.")
    return redirect(url_for("owner_submissions"))

@app.route("/owner/add-resource", methods=["GET","POST"])
@owner_required
def add_resource():
    if request.method == "POST":
        title = request.form.get("title","").strip()
        description = request.form.get("description","").strip()
        boosts = max(0,int(request.form.get("boost_count",0)))
        file = request.files.get("resource_file")
        preview = request.files.get("preview")
        if not title or not file or not file.filename: flash("Title and resource ZIP are required."); return redirect(url_for("add_resource"))
        ext = pathlib.Path(file.filename).suffix.lower()
        if ext not in {".zip",".rar",".7z"}: flash("Upload ZIP, RAR, or 7Z."); return redirect(url_for("add_resource"))
        stored = secure_filename(f"resource_{secrets.token_hex(8)}{ext}")
        file.save(UPLOAD_DIR/stored)
        preview_name = ""
        if preview and preview.filename:
            pext = pathlib.Path(preview.filename).suffix.lower()
            if pext in {".png",".jpg",".jpeg",".webp"}:
                preview_name = secure_filename(f"preview_{secrets.token_hex(8)}{pext}")
                preview.save(UPLOAD_DIR/preview_name)
        with db() as c:
            c.execute("INSERT INTO resources(title,description,boost_count,file_name,preview_name,created_at) VALUES(?,?,?,?,?,?)",
                     (title,description,boosts,stored,preview_name,datetime.datetime.utcnow().isoformat()))
        flash("Resource added.")
        return redirect(url_for("owner"))
    return render_template("add_resource.html")

@app.route("/owner/codes", methods=["GET","POST"])
@owner_required
def codes():
    with db() as c:
        resources = c.execute("SELECT id,title FROM resources ORDER BY title").fetchall()
    if request.method == "POST":
        resource_id = int(request.form.get("resource_id"))
        count = min(100, max(1,int(request.form.get("count",1))))
        use_limit = min(10000, max(1,int(request.form.get("use_limit",1))))
        days = int(request.form.get("days",7))
        expires = None if days == 0 else (datetime.datetime.utcnow()+datetime.timedelta(days=days)).isoformat()
        generated = []
        with db() as c:
            for _ in range(count):
                code = "RICKY-" + "".join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(8))
                c.execute("INSERT INTO codes(code,resource_id,use_limit,expires_at,created_at) VALUES(?,?,?,?,?)",(code,resource_id,use_limit,expires,datetime.datetime.utcnow().isoformat()))
                generated.append(code)
        return render_template("codes.html", resources=resources, generated=generated)
    return render_template("codes.html", resources=resources, generated=[])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","5000")), debug=False)
