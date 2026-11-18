"""ReaderLog server: accounts, email verification, password reset, rate limiting,
books API, and the app itself.

Run locally:   pip install fastapi uvicorn
               uvicorn backend:app --port 8000      (then open http://localhost:8000)
Keep shelfie-standalone.html and manifest.json in the same folder as this file.

Settings (all optional, set as environment variables):
  APP_URL       public address of the app, used in email links   e.g. https://readerlog.example.com
  FORCE_HTTPS   set to 1 on a public server: redirects http -> https and sends HSTS
  SMTP_HOST, SMTP_PORT (587 or 465), SMTP_USER, SMTP_PASS, MAIL_FROM
                outgoing email. If SMTP_HOST is NOT set, emails are printed in this
                console instead and new accounts are verified automatically, which is
                handy for running on your own computer.
  SHELFIE_DB    path of the SQLite file (default: shelfie.db next to this file)

Passwords are salted + PBKDF2-hashed. Sessions are random tokens that expire after
30 days. Verification and reset links are single-use random tokens (only a hash of
each token is stored). TLS itself is provided by your host or reverse proxy.
"""
import hashlib, hmac, json, os, re, secrets, smtplib, sqlite3, ssl, time, urllib.parse, urllib.request
from email.message import EmailMessage
from pathlib import Path
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel

HERE = Path(__file__).parent
APP_URL = os.getenv("APP_URL", "http://localhost:8000").rstrip("/")
FORCE_HTTPS = os.getenv("FORCE_HTTPS") == "1"
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER or "noreply@readerlog.local")
MAIL_ENABLED = bool(SMTP_HOST)
DAY = 86400

app = FastAPI(title="ReaderLog")
db = sqlite3.connect(os.getenv("SHELFIE_DB", str(HERE / "shelfie.db")), check_same_thread=False)
db.row_factory = sqlite3.Row
db.executescript("""
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, pw BLOB NOT NULL, created INT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id), expires INT NOT NULL);
CREATE TABLE IF NOT EXISTS books(user_id INT NOT NULL REFERENCES users(id), id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(user_id, id));
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, user_id INT NOT NULL, kind TEXT NOT NULL, expires INT NOT NULL);
CREATE TABLE IF NOT EXISTS attempts(kind TEXT NOT NULL, key TEXT NOT NULL, ts INT NOT NULL);
CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts(kind, key, ts);
""")
try:  # databases created before usernames existed
    db.execute("ALTER TABLE users ADD COLUMN username TEXT")
except sqlite3.OperationalError:
    pass
try:  # databases created before email verification existed: trust the accounts that already exist
    db.execute("ALTER TABLE users ADD COLUMN verified INTEGER")
    db.execute("UPDATE users SET verified=1")
except sqlite3.OperationalError:
    pass
for _r in db.execute("SELECT id, email FROM users WHERE username IS NULL").fetchall():
    base = re.sub(r"[^a-z0-9_.]", "", _r["email"].split("@")[0].lower())[:16] or "reader"
    name = base if len(base) >= 3 and not db.execute("SELECT 1 FROM users WHERE username=?", (base,)).fetchone() else f"{base[:12]}{_r['id']}"
    db.execute("UPDATE users SET username=? WHERE id=?", (name, _r["id"]))
db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_username ON users(username)")
db.commit()


# ---------- HTTPS + security headers ----------
@app.middleware("http")
async def security(request: Request, call_next):
    if FORCE_HTTPS:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if proto != "https":
            return RedirectResponse(str(request.url.replace(scheme="https")), status_code=308)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if FORCE_HTTPS:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# ---------- rate limiting (stored in the database, so it survives restarts) ----------
def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return fwd or (request.client.host if request.client else "unknown")


def too_many(kind: str, key: str, limit: int, window: int) -> bool:
    n = db.execute("SELECT COUNT(*) FROM attempts WHERE kind=? AND key=? AND ts>?",
                   (kind, key, int(time.time()) - window)).fetchone()[0]
    return n >= limit


def record(kind: str, key: str):
    now = int(time.time())
    db.execute("INSERT INTO attempts VALUES(?,?,?)", (kind, key, now))
    db.execute("DELETE FROM attempts WHERE ts<?", (now - DAY,))
    db.commit()


def clear(kind: str, key: str):
    db.execute("DELETE FROM attempts WHERE kind=? AND key=?", (kind, key))
    db.commit()


def limit_or_429(kind: str, key: str, limit: int, window: int, msg: str):
    if too_many(kind, key, limit, window):
        raise HTTPException(429, msg)


# ---------- email ----------
def send_mail(to: str, subject: str, body: str):
    if not MAIL_ENABLED:
        print(f"\n--- EMAIL (SMTP not configured, so it was not sent) ---\nTo: {to}\nSubject: {subject}\n\n{body}\n"
              "-------------------------------------------------------\n", flush=True)
        return
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = MAIL_FROM, to, subject
    msg.set_content(body)
    try:
        ctx = ssl.create_default_context()
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=15) as s:
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.starttls(context=ctx)
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
    except Exception as e:  # never crash a request because mail failed
        print("Could not send email:", e, flush=True)


# ---------- single-use tokens (email verification, password reset) ----------
def sha(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def make_token(uid: int, kind: str, ttl: int) -> str:
    tok = secrets.token_urlsafe(32)
    db.execute("INSERT INTO tokens VALUES(?,?,?,?)", (sha(tok), uid, kind, int(time.time()) + ttl))
    db.commit()
    return tok


def use_token(tok: str, kind: str):
    row = db.execute("SELECT user_id FROM tokens WHERE hash=? AND kind=? AND expires>?",
                     (sha(tok), kind, int(time.time()))).fetchone()
    if row:
        db.execute("DELETE FROM tokens WHERE hash=?", (sha(tok),))
        db.commit()
        return row["user_id"]
    return None


def queue_verification(bg: BackgroundTasks, uid: int, email: str, username: str):
    tok = make_token(uid, "verify", 2 * DAY)
    bg.add_task(send_mail, email, "Confirm your ReaderLog account",
                f"Hi {username},\n\nWelcome to ReaderLog. Confirm your email address by opening this link "
                f"(it works for 2 days):\n\n{APP_URL}/api/verify?token={tok}\n\n"
                "If you didn't create this account, you can ignore this email.\n")


# ---------- accounts ----------
class Creds(BaseModel):
    email: str          # for login this may hold the email OR the username
    password: str


class Signup(Creds):
    username: str


class Forgot(BaseModel):
    email: str          # email or username


class ResetIn(BaseModel):
    token: str
    password: str


USER_RE = re.compile(r"[a-z0-9_.]{3,20}")


def clean_username(raw: str) -> str:
    u = raw.strip().lower().lstrip("@")
    if not USER_RE.fullmatch(u):
        raise HTTPException(400, "Username must be 3-20 characters: letters, numbers, _ or .")
    return u


def hash_pw(password: str, salt: bytes) -> bytes:
    # pbkdf2 is available in every Python build (macOS's system Python often lacks scrypt)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def new_session(uid: int) -> str:
    tok = secrets.token_urlsafe(32)
    db.execute("INSERT INTO sessions VALUES(?,?,?)", (tok, uid, int(time.time()) + 30 * DAY))
    db.commit()
    return tok


def find_user(ident: str):
    ident = ident.strip().lower()
    return db.execute("SELECT * FROM users WHERE email=? OR username=?", (ident, ident.lstrip("@"))).fetchone()


@app.post("/api/signup")
def signup(c: Signup, request: Request, bg: BackgroundTasks):
    ip = client_ip(request)
    limit_or_429("signup", ip, 10, 3600, "Too many sign-ups from this connection. Please try again later.")
    email = c.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Enter a valid email")
    if len(c.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    username = clean_username(c.username)
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        raise HTTPException(409, "That username is taken - try another")
    salt = os.urandom(16)
    try:
        cur = db.execute("INSERT INTO users(email,username,salt,pw,created,verified) VALUES(?,?,?,?,?,?)",
                         (email, username, salt, hash_pw(c.password, salt), int(time.time()), 0 if MAIL_ENABLED else 1))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That email already has an account - log in instead")
    record("signup", ip)
    if MAIL_ENABLED:
        queue_verification(bg, cur.lastrowid, email, username)
        return {"message": f"Almost there! We sent a confirmation link to {email}. Open it, then log in."}
    return {"token": new_session(cur.lastrowid)}


@app.post("/api/login")
def login(c: Creds, request: Request):
    ident, ip = c.email.strip().lower(), client_ip(request)
    msg = "Too many login attempts. Please wait 15 minutes and try again."
    limit_or_429("login", ident, 5, 900, msg)      # per account
    limit_or_429("loginip", ip, 30, 900, msg)      # per connection
    u = find_user(ident)
    if not u or not hmac.compare_digest(u["pw"], hash_pw(c.password, u["salt"])):
        record("login", ident)
        record("loginip", ip)
        raise HTTPException(401, "Wrong email/username or password")
    if not u["verified"]:
        raise HTTPException(403, "Please verify your email first - check your inbox for the confirmation link.")
    clear("login", ident)
    return {"token": new_session(u["id"])}


@app.get("/api/verify")
def verify(token: str):
    uid = use_token(token, "verify")
    if uid:
        db.execute("UPDATE users SET verified=1 WHERE id=?", (uid,))
        db.commit()
    return RedirectResponse("/?verified=1" if uid else "/?verified=0")


@app.post("/api/resend")
def resend(c: Forgot, request: Request, bg: BackgroundTasks):
    ip = client_ip(request)
    limit_or_429("resend", ip, 5, 3600, "Too many requests. Please try again later.")
    record("resend", ip)
    u = find_user(c.email)
    if u and not u["verified"]:
        queue_verification(bg, u["id"], u["email"], u["username"])
    return {"message": "If that account still needs confirming, a fresh link is on its way."}


@app.post("/api/forgot")
def forgot(c: Forgot, request: Request, bg: BackgroundTasks):
    ip, ident = client_ip(request), c.email.strip().lower()
    msg = "Too many reset requests. Please try again in an hour."
    limit_or_429("forgot", ip, 5, 3600, msg)
    limit_or_429("forgotid", ident, 3, 3600, msg)
    record("forgot", ip)
    record("forgotid", ident)
    u = find_user(ident)
    if u:   # same reply whether or not the account exists, so nobody can probe for emails
        tok = make_token(u["id"], "reset", 3600)
        bg.add_task(send_mail, u["email"], "Reset your ReaderLog password",
                    f"Hi {u['username']},\n\nSomeone asked to reset the password for your ReaderLog account. "
                    f"If that was you, choose a new one here (the link works once, for one hour):\n\n{APP_URL}/?reset={tok}\n\n"
                    "If it wasn't you, ignore this email. Your password has not changed.\n")
    out = "If that account exists, a reset link is on its way. It works for one hour."
    if not MAIL_ENABLED:
        out += " (This server has no email set up, so the link was printed in the server console.)"
    return {"message": out}


@app.post("/api/reset")
def reset(c: ResetIn, request: Request):
    ip = client_ip(request)
    limit_or_429("reset", ip, 10, 3600, "Too many attempts. Please try again later.")
    record("reset", ip)
    if len(c.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    uid = use_token(c.token, "reset")
    if not uid:
        raise HTTPException(400, "That reset link is invalid or has expired. Request a new one.")
    salt = os.urandom(16)
    db.execute("UPDATE users SET salt=?, pw=?, verified=1 WHERE id=?", (salt, hash_pw(c.password, salt), uid))
    db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))   # log out every device
    db.commit()
    return {"message": "Password updated. Log in with your new password."}


def current_user(authorization: str = Header(default="")):
    tok = authorization.removeprefix("Bearer ").strip()
    r = db.execute("SELECT u.id, u.email, u.username FROM sessions s JOIN users u ON u.id=s.user_id "
                   "WHERE s.token=? AND s.expires>?", (tok, int(time.time()))).fetchone()
    if not r:
        raise HTTPException(401, "Please log in")
    return r


@app.get("/api/me")
def me(u=Depends(current_user)):
    return {"email": u["email"], "username": u["username"]}


@app.put("/api/me")
def rename(body: dict, u=Depends(current_user)):
    name = clean_username(str(body.get("username", "")))
    if db.execute("SELECT 1 FROM users WHERE username=? AND id!=?", (name, u["id"])).fetchone():
        raise HTTPException(409, "That username is taken - try another")
    db.execute("UPDATE users SET username=? WHERE id=?", (name, u["id"]))
    db.commit()
    return {"username": name}


# ---------- books (each row belongs to one user) ----------
@app.get("/api/books")
def list_books(u=Depends(current_user)):
    return [json.loads(r["data"]) for r in db.execute("SELECT data FROM books WHERE user_id=?", (u["id"],))]


@app.put("/api/books/{bid}")
def put_book(bid: str, body: dict, u=Depends(current_user)):
    data = json.dumps({**body, "id": bid})
    if len(data) > 50_000:
        raise HTTPException(413, "Book record too large")
    db.execute("INSERT INTO books VALUES(?,?,?) ON CONFLICT(user_id,id) DO UPDATE SET data=excluded.data",
               (u["id"], bid, data))
    db.commit()
    return {"ok": True}


@app.delete("/api/books/{bid}")
def delete_book(bid: str, u=Depends(current_user)):
    db.execute("DELETE FROM books WHERE user_id=? AND id=?", (u["id"], bid))
    db.commit()
    return {"ok": True}


@app.get("/api/lookup")
def lookup(title: str, author: str = "", u=Depends(current_user)):
    """Open Library lookup: author, pages, cover."""
    q = urllib.parse.quote(f"{title} {author}".strip())
    url = f"https://openlibrary.org/search.json?q={q}&limit=5&fields=title,author_name,number_of_pages_median,cover_i"
    with urllib.request.urlopen(url, timeout=10) as r:
        docs = json.load(r).get("docs", [])
    hit = next((d for d in docs if d.get("number_of_pages_median")), docs[0] if docs else None)
    if not hit:
        raise HTTPException(404, "Not found")
    return {"title": hit["title"], "author": (hit.get("author_name") or [""])[0],
            "pages": hit.get("number_of_pages_median"),
            "cover": f"https://covers.openlibrary.org/b/id/{hit['cover_i']}-M.jpg" if hit.get("cover_i") else None}


# ---------- the app itself ----------
@app.get("/")
def index():
    return FileResponse(HERE / "shelfie-standalone.html")


@app.get("/manifest.json")
def manifest():
    return FileResponse(HERE / "manifest.json")
