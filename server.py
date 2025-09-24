# server.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, select, delete
from sqlalchemy.orm import declarative_base, sessionmaker
import secrets
import string

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
    import tempfile
    import subprocess
    from pathlib import Path
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    activate_ssl = os.getenv("SSL_MODE", "on").lower() in ("1", "true", "on", "adhoc")

    temp_dir_ctx = None
    tmp_cert_path = None
    tmp_key_path = None

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
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
                ],
                check=True,
                capture_output=True,
            )
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
                    "1",
                    "-config",
                    str(cfg_path),
                    "-extensions",
                    "v3_req",
                ],
                check=True,
                capture_output=True,
            )
            return str(cert_path), str(key_path)
        except Exception as e:
            print(f"[WARN] Failed to generate ad hoc cert via openssl: {e}")
            return None, None

    # Decide SSL parameters
    if activate_ssl:
        temp_dir_ctx = tempfile.TemporaryDirectory(prefix="adhoc-ssl-")
        tmpdir = Path(temp_dir_ctx.name)
        tmp_cert_path, tmp_key_path = _gen_adhoc_cert(tmpdir)
        if tmp_cert_path and tmp_key_path:
            print(
                "[INFO] Starting with ad hoc SSL (self-signed, dev-only). "
                "Set SSL_MODE= to disable or provide SSL_CERTFILE/SSL_KEYFILE for custom certs."
            )
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level="info",
                ssl_certfile=tmp_cert_path,
                ssl_keyfile=tmp_key_path,
            )
        else:
            print("[WARN] Falling back to HTTP (no SSL).")
            uvicorn.run(app, host=host, port=port, log_level="info")
        # Cleanup TemporaryDirectory on exit
        if temp_dir_ctx is not None:
            temp_dir_ctx.cleanup()
    else:
        # Plain HTTP
        uvicorn.run(app, host=host, port=port, log_level="info")
