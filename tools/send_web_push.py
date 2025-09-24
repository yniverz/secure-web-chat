#!/usr/bin/env python3
"""
Minimal sender tool to deliver a Web Push notification using a peer's sendable push card.
This keeps your chat server uninvolved. Requires: pip install pywebpush cryptography

Usage:
  python tools/send_web_push.py --card path/to/card.json --title "Hello" --body "Preview text"

card.json shape (sendable push card):
{
  "subscription": {"endpoint": "...", "keys": {"p256dh": "...", "auth": "..."}},
  "vapid": {"subject_email": "mailto:you@example.com", "public_key": "...", "private_key": "..."}
}
"""
import argparse
import json
from pywebpush import webpush
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
    if b64u.strip().startswith('-----BEGIN'):
        return b64u
    from textwrap import wrap
    b64 = _b64u_to_b64(b64u)
    lines = '\n'.join(wrap(b64, 64))
    return f"-----BEGIN PRIVATE KEY-----\n{lines}\n-----END PRIVATE KEY-----\n"


def _ec_sec1_der_b64u_to_pem(b64u: str) -> str:
  if b64u.strip().startswith('-----BEGIN'):
    return b64u
  from textwrap import wrap
  b64 = _b64u_to_b64(b64u)
  lines = '\n'.join(wrap(b64, 64))
  return f"-----BEGIN EC PRIVATE KEY-----\n{lines}\n-----END EC PRIVATE KEY-----\n"


def _coerce_vapid_priv_to_pem(s: str) -> str:
  if s.strip().startswith('-----BEGIN'):
    return s
  if load_der_private_key is not None:
    try:
      import base64
      b64 = _b64u_to_b64(s)
      der = base64.b64decode(b64)
      key = load_der_private_key(der, password=None)
      pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode('ascii')
      return pem
    except Exception:
      pass
  try:
    return _pkcs8_der_b64u_to_pem(s)
  except Exception:
    return _ec_sec1_der_b64u_to_pem(s)


def main():
  p = argparse.ArgumentParser()
  p.add_argument("--card", required=True)
  p.add_argument("--title", default="Secure Chat")
  p.add_argument("--body", default="New message")
  p.add_argument("--tag", default="secure-chat-msg")
  args = p.parse_args()

  with open(args.card, 'r', encoding='utf-8') as f:
    card = json.load(f)
  sub = card["subscription"]
  vapid = card["vapid"]

  payload = json.dumps({"title": args.title, "preview": args.body, "tag": args.tag})

  webpush(
    subscription_info=sub,
    data=payload,
    vapid_private_key=_coerce_vapid_priv_to_pem(vapid["private_key"]),
    vapid_claims={"sub": vapid.get("subject_email", "mailto:you@example.com")},
  )
  print("Sent")


if __name__ == "__main__":
  main()
