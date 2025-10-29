import base64
import traceback
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
