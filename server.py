import base64
import traceback
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, select, delete
from sqlalchemy.orm import declarative_base, sessionmaker
import secrets
import os
from pathlib import Path
import json

# Optional push deps (lazy)
try:  # pragma: no cover
    from pywebpush import webpush, WebPushException
except Exception:  # pragma: no cover
    webpush = None
    class WebPushException(Exception):
        pass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# ---- DB ----
DATABASE_URL = "sqlite:///./chat.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserId(Base):
    __tablename__ = "user_ids"
    id = Column(Integer, primary_key=True)
    id_hash = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    to_id_hash = Column(String(64), index=True, nullable=False)
    payload = Column(JSON, nullable=False)  # encrypted message blob from client
    created_at = Column(DateTime, default=datetime.utcnow)

class ShareSlot(Base):
    __tablename__ = "share_slots"
    id = Column(Integer, primary_key=True)
    code4 = Column(String(8), unique=True, nullable=False, index=True)  # 4-char code
    blob = Column(JSON, nullable=False)  # AES-GCM {iv, ct}
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class VapidKey(Base):
    __tablename__ = "vapid_key"
    id = Column(Integer, primary_key=True)
    public_key = Column(String(128), nullable=False)
    private_key = Column(String(128), nullable=False)  # base64url no padding raw scalar for P-256
    subject_email = Column(String(255), nullable=False, default="mailto:example@example.com")

class PushSubscription(Base):
    __tablename__ = "push_subscriptions"
    id = Column(Integer, primary_key=True)
    id_hash = Column(String(64), index=True, unique=True, nullable=False)
    subscription = Column(JSON, nullable=False)  # raw subscription JSON from client
    last_notified_at = Column(DateTime, nullable=True)

Base.metadata.create_all(engine)

# ---- App ----
app = FastAPI()

# Enforce HTTPS by redirecting HTTP → HTTPS.
# Built-in HTTPSRedirectMiddleware doesn't consider X-Forwarded-Proto, so add a tiny wrapper that does.
from starlette.middleware.base import BaseHTTPMiddleware
from urllib.parse import urlsplit, urlunsplit

class HttpsOrForwardedRedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        scheme = request.url.scheme
        xf_proto = request.headers.get('x-forwarded-proto', '').split(',')[0].strip().lower()
        if scheme != 'https' and xf_proto != 'https':
            # Build https URL preserving host, path, query
            url = request.url
            parts = urlsplit(str(url))
            https_url = urlunsplit(('https', parts.netloc, parts.path, parts.query, parts.fragment))
            return RedirectResponse(url=https_url, status_code=307)
        return await call_next(request)

app.add_middleware(HttpsOrForwardedRedirectMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ---- Admin config ----
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_ENABLED = bool(ADMIN_PASSWORD)
# Session secret for admin login state; ephemeral if not set explicitly
SESSION_SECRET = os.getenv("ADMIN_SESSION_SECRET") or base64.urlsafe_b64encode(os.urandom(32)).decode()
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="strict", https_only=True)

# --- Security headers (CSP, HSTS, etc.) ---
from starlette.types import ASGIApp, Receive, Scope, Send

class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])
                def set_header(name: str, value: str):
                    headers.append((name.encode("latin-1"), value.encode("latin-1")))

                # Strong default CSP: no inline script; allow inline styles (minimal inline used); self-only resources
                csp = (
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "font-src 'self'; "
                    "connect-src 'self'; "
                    "object-src 'none'; "
                    "base-uri 'none'; "
                    "frame-ancestors 'none'; "
                    "manifest-src 'self'; "
                    "worker-src 'self' blob:"
                )
                set_header("content-security-policy", csp)

                # Other helpful headers
                set_header("x-content-type-options", "nosniff")
                set_header("referrer-policy", "no-referrer")
                set_header("permissions-policy", "geolocation=(), microphone=(), camera=(), payment=()")

                # HSTS: instruct browsers to only use HTTPS for this host
                # Note: only effective over HTTPS; harmless on HTTP
                set_header("strict-transport-security", "max-age=31536000; includeSubDomains")

            await send(message)

        await self.app(scope, receive, send_wrapper)

app.add_middleware(SecurityHeadersMiddleware)

# ---- Schemas ----
class ReserveReq(BaseModel):
    id_hash: str

class ReserveResp(BaseModel):
    unique: bool

class PushMsgReq(BaseModel):
    to_id_hash: str
    payload: Dict[str, Any]

class PollReq(BaseModel):
    id_hash: str
    max: Optional[int] = 50

class PollRespItem(BaseModel):
    id: int
    payload: Dict[str, Any]

class PollResp(BaseModel):
    items: List[PollRespItem]

class ShareCreateReq(BaseModel):
    ttl_seconds: int
    blob: Dict[str, Any]
    prefer_code4: Optional[str] = None  # optional preferred 4-char code from client

class ShareCreateResp(BaseModel):
    code4: str

class ShareGetResp(BaseModel):
    blob: Dict[str, Any]

class VapidPublicResp(BaseModel):
    public_key: str
    subject_email: str

class PushSubscribeReq(BaseModel):
    id_hash: str
    subscription: Dict[str, Any]

class PushSubscribeResp(BaseModel):
    ok: bool

# ---- Helpers ----
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no confusing chars

def gen_code4():
    return "".join(secrets.choice(ALPHABET) for _ in range(4))

def _b64u(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def vapid_public_key_b64url(priv: ec.EllipticCurvePrivateKey) -> str:
    raw_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode()

def vapid_private_key_b64url(priv: ec.EllipticCurvePrivateKey) -> str:
    # 32-byte big-endian scalar (the secret number d)
    d_bytes = priv.private_numbers().private_value.to_bytes(32, 'big')
    return base64.urlsafe_b64encode(d_bytes).rstrip(b"=").decode()


def _ensure_vapid_key(db):
    vk = db.execute(select(VapidKey)).scalar_one_or_none()
    if vk:
        return vk
    # Generate new P-256 keypair
    try:
        priv_obj = ec.generate_private_key(ec.SECP256R1())
    except TypeError:  # pragma: no cover
        from cryptography.hazmat.backends import default_backend  # pragma: no cover
        priv_obj = ec.generate_private_key(ec.SECP256R1(), default_backend())

    public_key = vapid_public_key_b64url(priv_obj)
    private_key = vapid_private_key_b64url(priv_obj)

    vk = VapidKey(public_key=public_key, private_key=private_key, subject_email="mailto:notify@example.com")
    db.add(vk); db.commit(); db.refresh(vk)
    return vk

# ---- Routes ----
@app.post("/id/reserve", response_model=ReserveResp)
def reserve_id(req: ReserveReq):
    if not req.id_hash or len(req.id_hash) > 64:
        raise HTTPException(400, "bad id_hash")
    with SessionLocal() as db:
        exists = db.execute(select(UserId).where(UserId.id_hash == req.id_hash)).scalar_one_or_none()
        if exists:
            return ReserveResp(unique=False)
        db.add(UserId(id_hash=req.id_hash))
        db.commit()
        return ReserveResp(unique=True)

@app.post("/messages/push")
def push_message(req: PushMsgReq):
    if not req.to_id_hash:
        raise HTTPException(400, "missing to_id_hash")
    with SessionLocal() as db:
        m = Message(to_id_hash=req.to_id_hash, payload=req.payload)
        db.add(m); db.flush(); msg_id = m.id; db.commit()
        # After storing, attempt to send a push with encrypted payload so SW can decrypt
        try:
            if webpush is not None:
                sub = db.execute(select(PushSubscription).where(PushSubscription.id_hash == req.to_id_hash)).scalar_one_or_none()
                if sub:
                    vk = _ensure_vapid_key(db)
                    # Include the payload as-is (still end-to-end encrypted); SW will decide whether to show
                    payload = {
                        "kind": "message",
                        "to": req.to_id_hash,
                        "payload": req.payload,
                    }
                    webpush(
                        subscription_info=sub.subscription,
                        data=json.dumps(payload),
                        vapid_private_key=vk.private_key,
                        vapid_claims={"sub": vk.subject_email},
                    )
        except WebPushException:
            print(traceback.format_exc())
        except Exception:
            print(traceback.format_exc())
    return {"ok": True, "id": msg_id}

@app.post("/messages/poll", response_model=PollResp)
def poll_messages(req: PollReq):
    if not req.id_hash:
        raise HTTPException(400, "missing id_hash")
    limit = max(1, min(int(req.max or 50), 100))
    with SessionLocal() as db:
        q = db.execute(
            select(Message).where(Message.to_id_hash == req.id_hash).order_by(Message.id.asc()).limit(limit)
        ).scalars().all()
        items = [PollRespItem(id=m.id, payload=m.payload) for m in q]
        if q:
            db.execute(delete(Message).where(Message.id.in_([m.id for m in q])))
            db.commit()
        return PollResp(items=items)

@app.post("/share/create", response_model=ShareCreateResp)
def share_create(req: ShareCreateReq):
    ttl = max(10, min(req.ttl_seconds, 60 * 60 * 24))  # 10s .. 24h
    exp = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    # Try to honor client-provided prefer_code4 when available and free
    preferred = (req.prefer_code4 or "").strip().upper()[:4]
    with SessionLocal() as db:
        code = None
        if preferred and not db.execute(select(ShareSlot).where(ShareSlot.code4 == preferred)).scalar_one_or_none():
            code = preferred
        else:
            code = gen_code4()
            while db.execute(select(ShareSlot).where(ShareSlot.code4 == code)).scalar_one_or_none() is not None:
                code = gen_code4()
        slot = ShareSlot(code4=code, blob=req.blob, expires_at=exp)
        db.add(slot)
        db.commit()
        return ShareCreateResp(code4=code)

@app.get("/share/get/{code4}", response_model=ShareGetResp)
def share_get(code4: str):
    code4 = (code4 or "").upper()
    with SessionLocal() as db:
        slot = db.execute(select(ShareSlot).where(ShareSlot.code4 == code4)).scalar_one_or_none()
        if not slot:
            raise HTTPException(404, "not found")
        if datetime.now(timezone.utc) > slot.expires_at.replace(tzinfo=timezone.utc):
            db.delete(slot)
            db.commit()
            raise HTTPException(410, "expired")
        # One-time use: consume and delete the slot upon successful retrieval
        blob = slot.blob
        db.delete(slot)
        db.commit()
        return ShareGetResp(blob=blob)

@app.get("/push/vapid/public", response_model=VapidPublicResp)
def get_vapid_public():
    with SessionLocal() as db:
        vk = _ensure_vapid_key(db)
        return VapidPublicResp(public_key=vk.public_key, subject_email=vk.subject_email)

@app.post("/push/subscribe", response_model=PushSubscribeResp)
def push_subscribe(req: PushSubscribeReq):
    if not req.id_hash or not isinstance(req.subscription, dict):
        raise HTTPException(400, "bad request")
    endpoint = req.subscription.get("endpoint")
    keys = (req.subscription.get("keys") or {})
    if not endpoint or not keys.get("p256dh") or not keys.get("auth"):
        raise HTTPException(400, "missing subscription fields")
    with SessionLocal() as db:
        existing = db.execute(select(PushSubscription).where(PushSubscription.id_hash == req.id_hash)).scalar_one_or_none()
        if existing:
            existing.subscription = req.subscription
        else:
            db.add(PushSubscription(id_hash=req.id_hash, subscription=req.subscription))
        _ensure_vapid_key(db)  # make sure key exists
        db.commit()
    return PushSubscribeResp(ok=True)

# ---- Admin dashboard ----
def _admin_enabled_or_404():
    if not ADMIN_ENABLED:
        raise HTTPException(404, "not found")

def _admin_logged_in(req: Request) -> bool:
    try:
        return bool(req.session.get("admin_auth"))
    except Exception:
        return False

def _html_page(title: str, body_html: str) -> HTMLResponse:
    html = f"""
    <!doctype html>
    <html lang='en'>
    <head>
      <meta charset='utf-8'>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <title>{title}</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }}
        header {{ display:flex; justify-content: space-between; align-items: center; margin-bottom:1rem; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 6px 8px; vertical-align: top; }}
        th {{ background: #f5f5f5; text-align: left; }}
        code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
        .muted {{ color:#666; }}
        .danger {{ color:#b00020; }}
        .btn {{ display:inline-block; padding: 6px 10px; border:1px solid #ccc; background:#fafafa; border-radius:6px; text-decoration:none; color:#111; }}
        .btn.danger {{ border-color:#b00020; color:#b00020; }}
        form.inline {{ display:inline; margin:0; padding:0; }}
      </style>
    </head>
    <body>
      <header>
        <h1>{title}</h1>
        <nav>
          <form class="inline" method="post" action="/admin/logout">
            <button class="btn" type="submit">Logout</button>
          </form>
        </nav>
      </header>
      {body_html}
    </body>
    </html>
    """.strip()
    return HTMLResponse(html)

def _html_login(message: str = "") -> HTMLResponse:
    msg = f"<p class='danger'>{message}</p>" if message else ""
    html = f"""
    <!doctype html>
    <html lang='en'>
    <head>
      <meta charset='utf-8'>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <title>Admin Login</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; max-width: 480px; margin: 10vh auto; padding: 0 1rem; }}
        label {{ display:block; margin: 0.5rem 0 0.25rem; }}
        input[type=password] {{ width: 100%; padding: 8px; font-size: 16px; }}
        button {{ margin-top: 1rem; padding: 8px 12px; }}
      </style>
    </head>
    <body>
      <h1>Admin</h1>
      {msg}
      <form method="post" action="/admin/login">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required autocomplete="current-password" />
        <button type="submit">Sign in</button>
      </form>
    </body>
    </html>
    """.strip()
    return HTMLResponse(html)

from fastapi import Form

@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request):
    _admin_enabled_or_404()
    if not _admin_logged_in(request):
        return _html_login()
    # Overview: list tables and counts
    with SessionLocal() as db:
        tables = [
            ("user_ids", UserId),
            ("messages", Message),
            ("share_slots", ShareSlot),
            ("push_subscriptions", PushSubscription),
            ("vapid_key", VapidKey),
        ]
        rows = []
        for name, model in tables:
            try:
                count = db.execute(select(model)).scalars().all()
                n = len(count)
            except Exception:
                n = 0
            rows.append((name, n))
    body = [
        "<p class='muted'>Minimal admin dashboard. Data shown only after login. Use with care.</p>",
        "<table>",
        "<tr><th>Table</th><th>Rows</th><th>Actions</th></tr>",
    ]
    for name, n in rows:
        body.append(
            f"<tr><td><code>{name}</code></td><td>{n}</td><td>"
            f"<a class='btn' href='/admin/table/{name}'>View</a>"
            f"</td></tr>"
        )
    body.append("</table>")
    return _html_page("Admin Dashboard", "\n".join(body))

@app.post("/admin/login")
def admin_login(request: Request, password: str = Form(...)):
    _admin_enabled_or_404()
    if password == ADMIN_PASSWORD:
        request.session["admin_auth"] = True
        return RedirectResponse(url="/admin", status_code=303)
    return _html_login("Invalid password.")

@app.post("/admin/logout")
def admin_logout(request: Request):
    _admin_enabled_or_404()
    try:
        request.session.clear()
    except Exception:
        request.session["admin_auth"] = False
    return RedirectResponse(url="/admin", status_code=303)

def _model_by_name(name: str):
    mapping = {
        "user_ids": UserId,
        "messages": Message,
        "share_slots": ShareSlot,
        "push_subscriptions": PushSubscription,
        "vapid_key": VapidKey,
    }
    return mapping.get(name)

def _render_rows_table(name: str, model, items: list) -> str:
    # Determine columns dynamically
    cols = [c.name for c in model.__table__.columns]
    head = "<tr>" + "".join(f"<th>{c}</th>" for c in cols) + "<th>Actions</th></tr>"
    body = [head]
    for row in items:
        tds = []
        for c in cols:
            val = getattr(row, c)
            if isinstance(val, dict):
                try:
                    val_str = "<pre>" + json.dumps(val, indent=2) + "</pre>"
                except Exception:
                    val_str = f"<code>{val}</code>"
            else:
                val_str = str(val)
            tds.append(f"<td>{val_str}</td>")
        # delete per-row form
        tds.append(
            "<td>"
            f"<form class='inline' method='post' action='/admin/table/{name}/delete-row'>"
            f"<input type='hidden' name='id' value='{getattr(row, 'id', '')}'/>"
            f"<button class='btn danger' type='submit' onclick=\"return confirm('Delete row {getattr(row, 'id', '')}?')\">Delete</button>"
            "</form>"
            "</td>"
        )
        body.append("<tr>" + "".join(tds) + "</tr>")
    return "<table>" + "\n".join(body) + "</table>"

@app.get("/admin/table/{name}", response_class=HTMLResponse)
def admin_table(request: Request, name: str, limit: int = 200):
    _admin_enabled_or_404()
    if not _admin_logged_in(request):
        return _html_login()
    model = _model_by_name(name)
    if not model:
        raise HTTPException(404, "unknown table")
    limit = max(1, min(int(limit or 200), 1000))
    with SessionLocal() as db:
        items = db.execute(select(model).order_by(model.id.asc()).limit(limit)).scalars().all()
    rows_html = _render_rows_table(name, model, items)
    controls = (
        f"<p><a class='btn' href='/admin'>&larr; Back</a> "
        f"<form class='inline' method='post' action='/admin/table/{name}/clear'>"
        f"<button class='btn danger' type='submit' onclick=\"return confirm('Clear ALL rows in {name}?')\">Clear table</button>"
        f"</form></p>"
    )
    return _html_page(f"Admin — {name}", controls + rows_html)

from fastapi import status

@app.post("/admin/table/{name}/clear")
def admin_clear_table(request: Request, name: str):
    _admin_enabled_or_404()
    if not _admin_logged_in(request):
        return _html_login()
    model = _model_by_name(name)
    if not model:
        raise HTTPException(404, "unknown table")
    with SessionLocal() as db:
        db.execute(delete(model))
        db.commit()
    return RedirectResponse(url=f"/admin/table/{name}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/table/{name}/delete-row")
def admin_delete_row(request: Request, name: str, id: int = Form(...)):
    _admin_enabled_or_404()
    if not _admin_logged_in(request):
        return _html_login()
    model = _model_by_name(name)
    if not model:
        raise HTTPException(404, "unknown table")
    with SessionLocal() as db:
        try:
            db.execute(delete(model).where(model.id == id))
            db.commit()
        except Exception:
            db.rollback()
            raise HTTPException(400, "failed to delete row")
    return RedirectResponse(url=f"/admin/table/{name}", status_code=status.HTTP_303_SEE_OTHER)

# ---- Static files (dev) ----
# Serve from "static" (renamed from static_old) to preserve original design
STATIC_DIR = Path(__file__).resolve().parent / "static"

@app.get("/{path:path}")
def root(path: str = ""):
    # default document
    if path in ("", "/"):
        path = "index.html"

    # resolve against STATIC_DIR and prevent path traversal
    fs_path = (STATIC_DIR / path).resolve()
    try:
        STATIC_DIR_RESOLVED = STATIC_DIR.resolve()
    except Exception:
        STATIC_DIR_RESOLVED = STATIC_DIR
    if not str(fs_path).startswith(str(STATIC_DIR_RESOLVED)):
        raise HTTPException(404, "not found")

    if not fs_path.exists() or not fs_path.is_file():
        raise HTTPException(404, "not found")

    fs_path_str = str(fs_path)
    if fs_path_str.endswith(".html"):
        content_type = "text/html"
    elif fs_path_str.endswith(".js"):
        content_type = "application/javascript"
    elif fs_path_str.endswith(".css"):
        content_type = "text/css"
    elif fs_path_str.endswith(".webmanifest"):
        content_type = "application/manifest+json"
    elif fs_path_str.endswith(".png"):
        content_type = "image/png"
    elif fs_path_str.endswith(".svg"):
        content_type = "image/svg+xml"
    elif fs_path_str.endswith(".ico"):
        content_type = "image/x-icon"
    elif fs_path_str.endswith(".json"):
        content_type = "application/json"
    else:
        content_type = "application/octet-stream"

    return FileResponse(path=fs_path_str, media_type=content_type)

# ---- Dev HTTPS bootstrap ----
if __name__ == "__main__":
    import subprocess
    from pathlib import Path
    import uvicorn
    import stat

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    activate_ssl = os.getenv("SSL_MODE", "on").lower() in ("1", "true", "on", "adhoc")

    env_certfile = os.getenv("SSL_CERTFILE")
    env_keyfile = os.getenv("SSL_KEYFILE")
    default_store = Path(__file__).resolve().parent / ".adhoc_ssl"
    store_dir = Path(os.getenv("SSL_STORE_DIR", str(default_store)))
    store_dir.mkdir(parents=True, exist_ok=True)
    ssl_days = int(os.getenv("SSL_DAYS", "30") or 30)

    def _gen_adhoc_cert(tmpdir: Path):
        cert_path = tmpdir / "adhoc-cert.pem"
        key_path = tmpdir / "adhoc-key.pem"
        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-nodes",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-days",
                    str(ssl_days),
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
                ],
                check=True,
                capture_output=True,
            )
            try:
                key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            return str(cert_path), str(key_path)
        except Exception:
            pass
        try:
            cfg_path = tmpdir / "openssl.cnf"
            cfg_path.write_text(
                (
                    """
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
x509_extensions    = v3_req
distinguished_name = dn

[ dn ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
"""
                ).strip()
            )
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-nodes",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-days",
                    str(ssl_days),
                    "-config",
                    str(cfg_path),
                    "-extensions",
                    "v3_req",
                ],
                check=True,
                capture_output=True,
            )
            try:
                key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            return str(cert_path), str(key_path)
        except Exception as e:
            print(f"[WARN] Failed to generate ad hoc cert via openssl: {e}")
            return None, None

    def _cert_valid(p: Path) -> bool:
        try:
            res = subprocess.run(
                ["openssl", "x509", "-checkend", "0", "-noout", "-in", str(p)],
                capture_output=True,
            )
            return res.returncode == 0
        except Exception:
            return False

    if activate_ssl:
        if env_certfile and env_keyfile:
            print("[INFO] Starting with provided SSL certs (SSL_CERTFILE/SSL_KEYFILE).")
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level="info",
                ssl_certfile=env_certfile,
                ssl_keyfile=env_keyfile,
            )
        else:
            cert_path = store_dir / "cert.pem"
            key_path = store_dir / "key.pem"
            have_valid = cert_path.exists() and key_path.exists() and _cert_valid(cert_path)
            if not have_valid:
                tmp_cert, tmp_key = _gen_adhoc_cert(store_dir)
                if tmp_cert and tmp_key:
                    try:
                        Path(tmp_cert).replace(cert_path)
                        Path(tmp_key).replace(key_path)
                    except Exception:
                        cert_path.write_bytes(Path(tmp_cert).read_bytes())
                        key_path.write_bytes(Path(tmp_key).read_bytes())
                    have_valid = True
                    print(f"[INFO] Generated new ad hoc cert (valid ~{ssl_days} days) at {cert_path}")
                else:
                    have_valid = False
            if have_valid:
                print(
                    "[INFO] Starting with ad hoc SSL (self-signed, dev-only). "
                    f"Using persisted certs in {store_dir}. Set SSL_MODE=off to disable or provide SSL_CERTFILE/SSL_KEYFILE."
                )
                uvicorn.run(
                    app,
                    host=host,
                    port=port,
                    log_level="info",
                    ssl_certfile=str(cert_path),
                    ssl_keyfile=str(key_path),
                )
            else:
                print("[WARN] Falling back to HTTP (no SSL).")
                uvicorn.run(app, host=host, port=port, log_level="info")
    else:
        uvicorn.run(app, host=host, port=port, log_level="info")
