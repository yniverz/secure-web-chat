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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--card", required=True)
    p.add_argument("--title", default="Secure Chat")
    p.add_argument("--body", default="New message")
    p.add_argument("--tag", default="secure-chat-msg")
    args = p.parse_args()

    card = json.load(open(args.card))
    sub = card["subscription"]
    vapid = card["vapid"]

    payload = json.dumps({"title": args.title, "preview": args.body, "tag": args.tag})

    webpush(
        subscription_info=sub,
        data=payload,
        vapid_private_key=vapid["private_key"],
        vapid_claims={"sub": vapid.get("subject_email", "mailto:you@example.com")},
        vapid_public_key=vapid["public_key"],
    )

    print("Sent")


if __name__ == "__main__":
    main()
