# Secure Web Chat — Dev HTTPS

This server can run with ad hoc HTTPS for local development. This is helpful for features that require a secure context (Service Workers, Web Push, Clipboard, etc.). Do not use ad hoc/self‑signed certificates in production.

## Options

- SSL_MODE=adhoc
  - Generates a temporary self‑signed certificate with `openssl` for `localhost` and starts the server over HTTPS.
  - Requires the `openssl` CLI to be available (macOS has it by default).
- SSL_CERTFILE + SSL_KEYFILE
  - Provide paths to an existing certificate and key to run HTTPS.
- Default (no SSL env)
  - Runs plain HTTP.

## Run examples (macOS, zsh)

- Ad hoc self-signed:

```sh
SSL_MODE=adhoc HOST=127.0.0.1 PORT=8443 \
  /usr/bin/env $(pwd)/.venv/bin/python server.py
```

Open https://127.0.0.1:8443 in your browser. You may need to accept the self-signed certificate warning once.

- Use your own cert/key:

```sh
SSL_CERTFILE=/path/to/cert.pem \
SSL_KEYFILE=/path/to/key.pem \
HOST=0.0.0.0 PORT=8443 \
  /usr/bin/env $(pwd)/.venv/bin/python server.py
```

## Notes

- Ad hoc certs are generated in a temporary directory and last only for the server lifetime (valid 1 day).
- For a smoother developer experience without warnings, consider generating a local CA and certs with `mkcert` and trust it on your system, then point `SSL_CERTFILE`/`SSL_KEYFILE` to those files.
- Production deployments should terminate TLS with a proper certificate (e.g., via a reverse proxy like nginx/traefik or a cloud load balancer).

Install requirements:

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Docker

Build and run with Docker Compose (dev HTTPS enabled by default):

```sh
docker compose up --build
```

Then open:

- HTTPS (self-signed): https://localhost:8001

Environment overrides:

- To disable HTTPS inside the container (e.g., when terminating TLS with a reverse proxy), set `SSL_MODE=off` in `docker-compose.yml`.
- To use your own certs, mount them and set `SSL_CERTFILE` and `SSL_KEYFILE`.

Data persistence:

- The SQLite database `chat.db` and ad hoc SSL artifacts are stored under the named volume `swc_data` at `/data` inside the container.

## Admin dashboard (/admin)

A minimal, password-gated admin dashboard is available at `/admin` to inspect and manage data tables. It's disabled by default.

Enable it by setting an admin password via environment variable:

```sh
# example (compose):
# in docker-compose.yml under services.secure-web-chat.environment
ADMIN_PASSWORD=change-me
```

Optional settings:

- `ADMIN_SESSION_SECRET`: secret used to sign the admin session cookie. If not set, a random, ephemeral secret is generated on startup (logins will not persist across restarts).

Capabilities:

- Login form at `/admin` (only shown when `ADMIN_PASSWORD` is set)
- View table contents of `user_ids`, `messages`, `share_slots`, `push_subscriptions`, and `vapid_key`
- Delete individual rows or clear entire tables

Notes and safety:

- This is a simple HTML-only dashboard that uses standard GET/POST; there is no CSRF protection and it is intended for trusted environments.
- Protect the endpoint at the network layer in production (e.g., firewall or reverse proxy with IP allowlists) and use HTTPS.
