# TLS Certificate Expiry Monitor

A purpose-built, multi-domain TLS/SSL certificate expiry monitor. Add the domains you operate, see days-remaining at a glance, and get alerted at 30/14/7/3/1 days before a certificate expires — before your users do.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.app/new?github_url=https://github.com/lNamelessl/ssl-cert-expiry-monitor)

## Features

- **Multi-domain dashboard** — add/remove host:port targets; days-remaining table with color bands (>30 green, 14–30 amber, <14 red; expired/invalid/unreachable always red).
- **Real TLS checks** — Node `tls.connect` with SNI and full certificate verification. Captures expiry, issuer, subject, SAN count and the SHA-256 fingerprint. Broken certificates (expired, self-signed, hostname mismatch) are still *reported*: the checker re-reads the certificate non-strictly so you see exactly how expired it is.
- **Alert thresholds at 30/14/7/3/1 days** (configurable via `ALERT_THRESHOLDS`) with a **once-per-threshold-per-certificate** state machine: an alert for a given threshold and certificate fires exactly once until the certificate is renewed (keyed on the SHA-256 fingerprint, persisted in SQLite). Restarts never re-fire.
- **Three optional alert sinks** — generic webhook (JSON POST), SMTP email (nodemailer), Telegram bot message. All off by default; the service is fully functional with zero configuration.
- **Persistent by design** — SQLite (better-sqlite3) on a Railway volume mounted at `/data`: domains, check history (last 200 checks per domain) and alert state all survive restarts and redeploys.
- **Lightweight** — Node 22 + Fastify, vanilla-JS dashboard served by the same process. No framework, no build step, no external assets.
- **Optional admin password** — reads are always open; when `ADMIN_PASSWORD` is set, adding/removing domains requires the `x-admin-password` header (the UI prompts for it).
- **Target guard** — check-start is refused for loopback, link-local/cloud-metadata (169.254.169.254), unspecified and multicast targets (including resolved addresses). The intended use is monitoring public domains you operate.

## Deploy on Railway

One click, zero prompts: the template provisions a single Node 22 service with a persistent volume at `/data`, a generated public domain, and a healthcheck on `/health`. Then just add domains in the dashboard.

## Configuration (all optional)

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_PASSWORD` | *(unset)* | When set, mutating API calls require header `x-admin-password`. Reads stay open. |
| `ALERT_WEBHOOK_URL` | *(unset)* | POST target for JSON alerts (Slack-compatible catchers, n8n, webhook.site, …). |
| `SMTP_URL` + `ALERT_EMAIL_TO` | *(unset)* | nodemailer transport URL (e.g. `smtps://user:pass@host:465`) and recipient. |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | *(unset)* | Telegram bot message sink. |
| `ALERT_THRESHOLDS` | `30,14,7,3,1` | Comma-separated alert thresholds in days. |
| `CHECK_INTERVAL_HOURS` | `6` | Default check interval for new domains (per-domain override supported). |
| `MAX_CONCURRENT_CHECKS` | `4` | Concurrent TLS check limit. |
| `CHECK_TIMEOUT_MS` | `10000` | TLS connect/timeout budget. |
| `DATA_DIR` | `/data` | SQLite directory. Use `./data` for local development. |
| `PORT` | `8080` | HTTP port (Railway injects this automatically). |

## Alert payload (webhook)

```json
{
  "event": "cert_expiry_warning",
  "severity": "warning",
  "service": "ssl-cert-expiry-monitor",
  "domain": "example.com",
  "port": 443,
  "daysRemaining": 21,
  "thresholdDays": 30,
  "expiresAt": "2026-11-13T08:52:17.000Z",
  "subject": "CN=example.com",
  "issuer": "C=US, O=Let's Encrypt, CN=YR1",
  "fingerprint": "sha256:…",
  "status": "valid",
  "checkedAt": "2026-10-06T10:00:00.000Z"
}
```

`severity` is `warning` for the 30/14-day thresholds and `critical` for 7/3/1 and expired certificates.

## API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | `200 {"status":"ok","lastCheck":…}` — always 200, even with zero domains. |
| `GET` | `/api/v1/domains` | All domains with latest check + band. |
| `POST` | `/api/v1/domains` | `{host, port?, intervalHours?}` — runs the first check immediately. |
| `DELETE` | `/api/v1/domains/:id` | Removes the domain, its history and alert state. |
| `POST` | `/api/v1/domains/:id/check` | Force a check now. |
| `GET` | `/api/v1/domains/:id/history` | Recent checks (max 200). |

## Trust boundary & security notes

- The dashboard (reads) is public to anyone with the URL. Set `ADMIN_PASSWORD` to protect add/remove/force-check.
- Only talk to the deployment over `https://` — the admin password must never be sent over plain HTTP.
- Connecting to hosts you name is the product, so the service will dial arbitrary public hosts:port. Loopback, link-local/metadata, unspecified and multicast targets are refused at check-start; private LAN ranges remain allowed for legitimate internal monitoring. Do not deploy this template on a network where that policy is unacceptable.

## Local development

```bash
npm install
DATA_DIR=./data npm start          # http://localhost:8080
npm run selftest                   # band/guard/state-machine/live-TLS assertions
```

## Stack

Node 22, Fastify 5, better-sqlite3 13 (bundled native prebuilds — no compiler needed), nodemailer, vanilla JS UI. Dockerfile is multi-stage on `node:22-bookworm-slim` with a non-root runtime user and a boot wrapper that fixes volume ownership (`chown` → `gosu` drop-privileges).
