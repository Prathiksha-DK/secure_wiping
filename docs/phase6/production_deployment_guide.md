# SecureWipe — Production Deployment & Security Hardening Guide

## 1. System Requirements & Prerequisites

* **Operating System**: Linux (Ubuntu 22.04 LTS / RHEL 9 / Debian 12) or Windows 10/11 Enterprise / Windows Server 2022.
* **Python Runtime**: Python 3.10+ with `virtualenv`.
* **Node.js**: Node.js 18+ (for Next.js frontend UI).
* **Privileges**: Low-privilege service account for Web UI; elevated `CAP_SYS_RAWIO` / `root` / `Administrator` for block sanitization daemon only.

---

## 2. Environment Configuration & Secret Management

In production, all secrets MUST be injected via environment variables:

```bash
# /etc/securewipe/securewipe.env

SECUREWIPE_ENV=PRODUCTION
SECUREWIPE_SECRET_KEY=9f8a3c82d0e1b4f6a7c980e123456789abcdef0123456789abcdef0123456789
SECUREWIPE_PORT=9758
SECUREWIPE_HOST=127.0.0.1
SECUREWIPE_ALLOWED_ORIGINS=https://securewipe.local,https://127.0.0.1:3000
SECUREWIPE_DATA_DIR=/var/lib/securewipe/data
```

> [!CAUTION]
> In `PRODUCTION` mode, SecureWipe will **refuse to start** if `SECUREWIPE_SECRET_KEY` is not set or uses the default development placeholder.

---

## 3. Systemd Service Configuration (Linux)

Create `/etc/systemd/system/securewipe-api.service`:

```ini
[Unit]
Description=SecureWipe Hardened Sanitization API Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/securewipe/backend
EnvironmentFile=/etc/securewipe/securewipe.env
ExecStart=/opt/securewipe/backend/linux_venv/bin/python3 app.py
Restart=always
RestartSec=5
ProtectSystem=strict
ReadWritePaths=/var/lib/securewipe/data /tmp
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now securewipe-api
```

---

## 4. Network Hardening & Reverse Proxy

1. **Localhost Binding**: SecureWipe API binds to `127.0.0.1:9758` by default in production.
2. **Reverse Proxy (Nginx)**: Terminate TLS (HTTPS) with HSTS, TLS 1.3 only, and secure cookies.

```nginx
server {
    listen 443 ssl http2;
    server_name securewipe.local;

    ssl_certificate /etc/ssl/certs/securewipe.crt;
    ssl_certificate_key /etc/ssl/private/securewipe.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /api/ {
        proxy_pass http://127.0.0.1:9758/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 5. Security Checklist Before Going Live

* [x] `SECUREWIPE_ENV=PRODUCTION` set.
* [x] `SECUREWIPE_SECRET_KEY` generated using a CSPRNG (`openssl rand -hex 32`).
* [x] Service bound strictly to `127.0.0.1`.
* [x] Standalone debug ports (5695, 8743) disabled or bound to localhost with auth.
* [x] Master administrator and operator passwords changed from defaults.
* [x] HTTPS enforced via reverse proxy.
* [x] Storage safety checks verified with automated test suite.
