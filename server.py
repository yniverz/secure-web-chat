# server.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, select, delete, func
from sqlalchemy.orm import declarative_base, sessionmaker
import secrets
import string
import os
import json

# Optional dependency for Web Push
try:
    from pywebpush import webpush, WebPushException
except Exception:  # pragma: no cover
    webpush = None
    WebPushException = Exception
try:
    from cryptography.hazmat.primitives.serialization import (
        load_der_private_key,
        Encoding,
        PrivateFormat,
        NoEncryption,
    )
except Exception:
    load_der_private_key = None


def _b64u_to_b64(s: str) -> str:
    s = s.replace('-', '+').replace('_', '/')
    pad = '=' * ((4 - len(s) % 4) % 4)
    return s + pad


def _pkcs8_der_b64u_to_pem(b64u: str) -> str:
    """Convert base64url-encoded PKCS8 DER to PEM string."""
    # If already PEM, return as-is
    if b64u.strip().startswith('-----BEGIN'):
        return b64u
    from textwrap import wrap
    b64 = _b64u_to_b64(b64u)
    lines = '\n'.join(wrap(b64, 64))
    return f"-----BEGIN PRIVATE KEY-----\n{lines}\n-----END PRIVATE KEY-----\n"


def _ec_sec1_der_b64u_to_pem(b64u: str) -> str:
    # Some stacks expect SEC1 EC PRIVATE KEY instead of generic PKCS8
    if b64u.strip().startswith('-----BEGIN'):
        return b64u
    from textwrap import wrap
    b64 = _b64u_to_b64(b64u)
    lines = '\n'.join(wrap(b64, 64))
    return f"-----BEGIN EC PRIVATE KEY-----\n{lines}\n-----END EC PRIVATE KEY-----\n"


def _coerce_vapid_priv_to_pem(s: str) -> str:
    """Accepts base64url DER or PEM and returns a valid PEM for cryptography/pywebpush."""
    if s.strip().startswith('-----BEGIN'):
        return s
    # Prefer proper DER->PEM via cryptography if available
    if load_der_private_key is not None:
        try:
            import base64
            b64 = _b64u_to_b64(s)
            der = base64.b64decode(b64)
            key = load_der_private_key(der, password=None)
            pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode('ascii')
            return pem
        except Exception:
            # fall through to simple wrappers
            pass
    # Last resort: try raw PEM wrappers
    try:
        return _pkcs8_der_b64u_to_pem(s)
    except Exception:
        return _ec_sec1_der_b64u_to_pem(s)


DB_URL = "sqlite:///chat.db"
engine = create_engine(DB_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

# ---- Models ----
class UserId(Base):
    __tablename__ = "user_ids"
    id = Column(Integer, primary_key=True)
    id_hash = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    to_id_hash = Column(String(64), index=True, nullable=False)
    payload = Column(JSON, nullable=False)  # opaque: {type, content}
    created_at = Column(DateTime, default=datetime.utcnow)

class ShareSlot(Base):
    __tablename__ = "share_slots"
    id = Column(Integer, primary_key=True)
    code4 = Column(String(8), unique=True, nullable=False, index=True)  # 4-char
    blob = Column(JSON, nullable=False)  # AES-GCM {iv, ct}
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

# ---- FastAPI ----
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

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
    prefer_code4: Optional[str] = None
    blob: Dict[str, Any]
    ttl_seconds: Optional[int] = 3600

class ShareCreateResp(BaseModel):
    code4: str

class ShareGetResp(BaseModel):
    blob: Dict[str, Any]


# Push storage: minimal info needed to send web push for an id_hash
class PushInfo(Base):
    __tablename__ = "push_info"
    id = Column(Integer, primary_key=True)
    id_hash = Column(String(64), unique=True, index=True, nullable=False)
    # Minimal set needed for web push
    endpoint = Column(Text, nullable=False)
    p256dh = Column(String(200), nullable=False)
    auth = Column(String(100), nullable=False)
    vapid_public_key = Column(String(200), nullable=False)
    vapid_private_key = Column(Text, nullable=False)
    subject_email = Column(String(200), nullable=True)
    last_notified_at = Column(DateTime, nullable=True)

Base.metadata.create_all(engine)

# Pydantic schema for push register
class PushRegisterReq(BaseModel):
    id_hash: str
    card: Dict[str, Any]  # { subscription: {endpoint, keys:{p256dh,auth}}, vapid:{public_key, private_key, subject_email?} }

class PushRegisterResp(BaseModel):
    ok: bool


# ---- Helpers ----
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no confusing chars

def gen_code4():
    return "".join(secrets.choice(ALPHABET) for _ in range(4))

# ---- Routes ----
@app.post("/id/reserve", response_model=ReserveResp)
def reserve_id(req: ReserveReq):
    if not req.id_hash or len(req.id_hash) > 64:
        raise HTTPException(400, "bad id_hash")
    with SessionLocal() as db:
      # if exists: tell client it’s already taken (not unique)
      exists = db.execute(select(UserId).where(UserId.id_hash == req.id_hash)).scalar_one_or_none()
      if exists:
          return ReserveResp(unique=False)
      # else create and say unique True
      u = UserId(id_hash=req.id_hash)
      db.add(u); db.commit()
      return ReserveResp(unique=True)

@app.post("/messages/push")
def push_message(req: PushMsgReq):
    if not req.to_id_hash:
        raise HTTPException(400, "missing to_id_hash")
    with SessionLocal() as db:
        m = Message(to_id_hash=req.to_id_hash, payload=req.payload)
        db.add(m)
        db.flush()            # <-- assigns PK while session is live
        msg_id = m.id         # <-- capture now
        # Attempt to trigger a notification if allowed (throttled)
        try:
            pi = db.execute(select(PushInfo).where(PushInfo.id_hash == req.to_id_hash)).scalar_one_or_none()
            if pi and webpush is not None:
                # Throttle window in seconds (env configurable, default 5s)
                throttle_s = int(os.getenv("PUSH_THROTTLE_SECONDS", "5") or 5)
                now = datetime.utcnow()
                can_notify = True
                if pi.last_notified_at is not None:
                    delta = now - (pi.last_notified_at if pi.last_notified_at.tzinfo is None else pi.last_notified_at.replace(tzinfo=None))
                    can_notify = delta.total_seconds() >= throttle_s
                if can_notify:
                    payload = {}
                    try:
                        # Optional small preview if it's a standard chat message
                        if req.payload and isinstance(req.payload, dict):
                            if req.payload.get("type") == "msg":
                                payload = {"title": "Secure Chat", "preview": "New message", "tag": "secure-chat-msg"}
                            elif req.payload.get("type") == "control":
                                payload = {"title": "Secure Chat", "preview": "Update", "tag": "secure-chat-ctrl"}
                    except Exception:
                        payload = {}
                    try:
                        webpush(
                            subscription_info={
                                "endpoint": pi.endpoint,
                                "keys": {"p256dh": pi.p256dh, "auth": pi.auth}
                            },
                            data=json.dumps(payload),
                            vapid_private_key=_coerce_vapid_priv_to_pem(pi.vapid_private_key),
                            vapid_claims={"sub": pi.subject_email or "mailto:you@example.com"},
                        )
                        pi.last_notified_at = now
                    except WebPushException as e:
                        # Retry with EC PRIVATE KEY label if PEM parse failed
                        if 'Could not deserialize key data' in str(e):
                            try:
                                webpush(
                                    subscription_info={
                                        "endpoint": pi.endpoint,
                                        "keys": {"p256dh": pi.p256dh, "auth": pi.auth}
                                    },
                                    data=json.dumps(payload),
                                    vapid_private_key=_coerce_vapid_priv_to_pem(pi.vapid_private_key),
                                    vapid_claims={"sub": pi.subject_email or "mailto:you@example.com"},
                                )
                                pi.last_notified_at = now
                                e = None
                            except WebPushException as e2:
                                e = e2
                        if e:
                            code = getattr(e, "response", None).status_code if getattr(e, "response", None) else None
                            if code in (404, 410):
                                db.delete(pi)
                            else:
                                print(f"[WARN] WebPush failed: {e}")
                        # If gone/unauthorized, drop the push info to avoid repeated failures
                        code = getattr(e, "response", None).status_code if getattr(e, "response", None) else None
                        if code in (404, 410):
                            db.delete(pi)
                        else:
                            # keep but log
                            print(f"[WARN] WebPush failed: {e}")
                # else: throttled
        except Exception as e:
            # Don’t block message insertion on push issues
            print(f"[WARN] Push notify attempt failed: {e}")
        db.commit()
    return {"ok": True, "id": msg_id}

@app.post("/messages/poll", response_model=PollResp)
def poll_messages(req: PollReq):
    if not req.id_hash:
        raise HTTPException(400, "missing id_hash")
    with SessionLocal() as db:
        q = db.execute(
            select(Message).where(Message.to_id_hash == req.id_hash).order_by(Message.id.asc()).limit(req.max or 50)
        ).scalars().all()
        items = [PollRespItem(id=m.id, payload=m.payload) for m in q]
        if q:
            db.execute(delete(Message).where(Message.id.in_([m.id for m in q])))
            db.commit()
        return PollResp(items=items)

@app.post("/share/create", response_model=ShareCreateResp)
def share_create(req: ShareCreateReq):
    ttl = max(60, min(req.ttl_seconds or 3600, 86400))  # 1 min to 24h
    exp = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    with SessionLocal() as db:
        # try prefer_code4 first, else generate unique
        code = (req.prefer_code4 or gen_code4()).upper()
        # ensure 4 chars from our alphabet
        code = "".join([c if c in ALPHABET else secrets.choice(ALPHABET) for c in code])[:4]
        # if taken, regenerate until free
        while db.execute(select(ShareSlot).where(ShareSlot.code4 == code)).scalar_one_or_none() is not None:
            code = gen_code4()
        slot = ShareSlot(code4=code, blob=req.blob, expires_at=exp)
        db.add(slot); db.commit()
        return ShareCreateResp(code4=code)

@app.post("/share/get/{code4}", response_model=ShareGetResp)
def share_get(code4: str):
    code4 = (code4 or "").upper()
    with SessionLocal() as db:
        slot = db.execute(select(ShareSlot).where(ShareSlot.code4 == code4)).scalar_one_or_none()
        if not slot:
            raise HTTPException(404, "not found")
        if datetime.now(timezone.utc) > slot.expires_at.replace(tzinfo=timezone.utc):
            # delete expired
            db.delete(slot); db.commit()
            raise HTTPException(410, "expired")
        # one-time read? Optional — here we keep until expiry; you can delete-on-read instead:
        # db.delete(slot); db.commit()
        return ShareGetResp(blob=slot.blob)


@app.post("/push/register", response_model=PushRegisterResp)
def push_register(req: PushRegisterReq):
    # Validate card shape minimally
    if not req.id_hash or not isinstance(req.card, dict):
        raise HTTPException(400, "bad request")
    sub = (req.card or {}).get("subscription") or {}
    vapid = (req.card or {}).get("vapid") or {}
    endpoint = sub.get("endpoint")
    keys = sub.get("keys") or {}
    p256dh = keys.get("p256dh")
    auth = keys.get("auth")
    vpub = vapid.get("public_key")
    vpriv = vapid.get("private_key")
    subj = vapid.get("subject_email") or "mailto:you@example.com"
    if not (endpoint and p256dh and auth and vpub and vpriv):
        raise HTTPException(400, "missing fields")
    with SessionLocal() as db:
        existing = db.execute(select(PushInfo).where(PushInfo.id_hash == req.id_hash)).scalar_one_or_none()
        if existing:
            existing.endpoint = endpoint
            existing.p256dh = p256dh
            existing.auth = auth
            existing.vapid_public_key = vpub
            existing.vapid_private_key = vpriv
            existing.subject_email = subj
        else:
            pi = PushInfo(
                id_hash=req.id_hash,
                endpoint=endpoint,
                p256dh=p256dh,
                auth=auth,
                vapid_public_key=vpub,
                vapid_private_key=vpriv,
                subject_email=subj,
            )
            db.add(pi)
        db.commit()
    return PushRegisterResp(ok=True)


@app.get("/{path:path}")
def root(path: str = ""):
    available = [
        "",
        "index.html",
        "app.js",
        "styles.css",
        "manifest.webmanifest",
        "sw.js",
        "icons/icon-192.png",
        "icons/icon-512.png",
        "icons/apple-touch-icon-180.png",
    ]

    if path not in available:
        raise HTTPException(404, "not found")
    
    if path == "":
        path = "index.html"

    path = f"static/{path}"

    if path.endswith(".html"):
        content_type = "text/html"
    elif path.endswith(".js"):
        content_type = "application/javascript"
    elif path.endswith(".css"):
        content_type = "text/css"
    elif path.endswith(".webmanifest"):
        content_type = "application/manifest+json"
    elif path.endswith(".png"):
        content_type = "image/png"
    else:
        content_type = "application/octet-stream"

    with open(path, "r" if content_type.startswith("text/") or content_type == "application/javascript" else "rb") as f:
        content = f.read()

    return HTMLResponse(content=content, media_type=content_type)


if __name__ == "__main__":
    import os
    import subprocess
    from pathlib import Path
    import uvicorn
    import stat

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    activate_ssl = os.getenv("SSL_MODE", "on").lower() in ("1", "true", "on", "adhoc")

    # Allow explicit certs via env
    env_certfile = os.getenv("SSL_CERTFILE")
    env_keyfile = os.getenv("SSL_KEYFILE")
    # Where to persist generated ad-hoc certs
    default_store = Path(__file__).resolve().parent / ".adhoc_ssl"
    store_dir = Path(os.getenv("SSL_STORE_DIR", str(default_store)))
    store_dir.mkdir(parents=True, exist_ok=True)
    # Validity of generated cert in days (defaults to 30)
    ssl_days = int(os.getenv("SSL_DAYS", "30") or 30)

    def _gen_adhoc_cert(tmpdir: Path):
        """Generate a self-signed certificate for localhost with SANs using openssl.

        Tries `-addext` first; if unsupported, falls back to a temporary openssl.cnf.
        Returns (cert_path, key_path) or (None, None) on failure.
        """
        cert_path = tmpdir / "adhoc-cert.pem"
        key_path = tmpdir / "adhoc-key.pem"
        # Attempt 1: use -addext for SAN when supported
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
                # Restrict key permissions
                key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            return str(cert_path), str(key_path)
        except Exception:
            pass
        # Attempt 2: write a config with SANs and use -extensions
        try:
            cfg_path = tmpdir / "openssl.cnf"
            cfg_path.write_text(
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
""".strip()
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

    def _cert_is_currently_valid(cert_path: Path) -> bool:
        """Use openssl to check that the cert is not expired (checkend 0)."""
        try:
            res = subprocess.run(
                ["openssl", "x509", "-checkend", "0", "-noout", "-in", str(cert_path)],
                capture_output=True,
            )
            return res.returncode == 0
        except Exception:
            return False

    # Decide SSL parameters
    if activate_ssl:
        # 1) If explicit certs provided, use them directly.
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
            # 2) Persisted ad hoc certs in store_dir
            cert_path = store_dir / "cert.pem"
            key_path = store_dir / "key.pem"

            have_valid = cert_path.exists() and key_path.exists() and _cert_is_currently_valid(cert_path)
            if not have_valid:
                # Generate new and save into store_dir
                tmp_cert, tmp_key = _gen_adhoc_cert(store_dir)
                if tmp_cert and tmp_key:
                    # Move/replace into standard names
                    try:
                        Path(tmp_cert).replace(cert_path)
                        Path(tmp_key).replace(key_path)
                    except Exception:
                        # Fallback to copy if replace fails
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
        # Plain HTTP
        uvicorn.run(app, host=host, port=port, log_level="info")
