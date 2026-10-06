# TLS Certificate Expiry Monitor

Never get surprised by an expired TLS certificate again. This template deploys a dedicated, multi-domain certificate expiry monitor: add the domains you operate, watch days-remaining on a color-banded dashboard, and receive alerts at 30/14/7/3/1 days before expiry through a generic webhook, SMTP email, or Telegram. Unlike generalist uptime tools, it is built around one job — reading real TLS certificates (SNI, full chain verification, issuer/SAN/fingerprint capture) and escalating with a once-per-threshold-per-certificate state machine that never spams you and never forgets a renewal reset. All alert sinks are optional: the deploy form asks for nothing and the service is fully functional immediately after provisioning.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/ssl-cert-expiry-monitor)

## What you get

- One Node 22 service (Fastify + vanilla-JS dashboard, ~120 MB RAM) with a **persistent volume mounted at `/data`** — SQLite storage for domains, check history and alert state, so everything survives restarts.
- A generated public domain and a healthcheck-gated deploy (`/health` must return 200 before the deployment is marked ready).
- Default checks every 6 hours per domain (per-domain override), concurrency-limited, with SAN/issuer/expiry capture and color bands (>30 green, 14–30 amber, <14 red).
- Optional post-deploy variables: `ADMIN_PASSWORD` (gates add/remove behind a header), `ALERT_WEBHOOK_URL`, `SMTP_URL` + `ALERT_EMAIL_TO`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, `ALERT_THRESHOLDS`, `CHECK_INTERVAL_HOURS`.

# Deploy and Host

Deploying provisions a single service named **monitor**: a Dockerfile build on `node:22-bookworm-slim` (multi-stage, non-root runtime), a persistent **volume at `/data`**, one **public domain**, and a **healthcheck on `/health`** with an ON_FAILURE restart policy. There are **zero deploy-form variables** — nothing to type, no prompts: press the deploy button and the dashboard comes up empty and healthy. After deploy, open the public URL and add your domains; optionally set any of the alert variables listed below in the service's Variables tab.

## About Hosting

Hosting this monitor costs one small service (fits comfortably in Railway's entry plan: it sleeps between 30-second scheduler ticks and does one TLS handshake per domain per interval by default). The SQLite database lives on the attached volume, so redeploying or restarting never loses your domain list, check history (last 200 checks per domain) or alert state. Certificate checks run against the public internet — the service refuses to dial loopback, link-local/cloud-metadata (169.254.169.254), unspecified and multicast targets. Reads on the dashboard are public by URL; set `ADMIN_PASSWORD` to require a password for adding/removing domains.

## Why Deploy

- **Focused, not generalist:** purpose-built for certificate expiry — real chain verification, issuer/SAN/fingerprint capture, and expired certificates that are still *reported* (you see how expired, in red) rather than surfacing as a generic failed check.
- **Noise-free alerts:** one alert per threshold per certificate until renewal, keyed on the certificate fingerprint and persisted — restarts and redeploys never re-fire, and a renewed certificate automatically resets all thresholds.
- **Zero-config start, optional everything:** no deploy prompts at all; webhook, SMTP and Telegram sinks and the admin password are added later if you want them.
- **Stateful from day one:** the volume is part of the template, so your data is durable without any extra setup.

## Common Use Cases

- Watching certificates across a portfolio of domains (staging + production) from one dashboard.
- Early warning for Let's Encrypt/ACME renewals that silently broke — 30/14/7/3/1-day escalation beats a browser padlock complaint.
- Alerting a chat/ops endpoint (webhook, Telegram, email) that a certificate is about to expire, with a JSON payload you can pipe into n8n, Slack-compatible catchers or ticketing.
- Auditing third-party or partner endpoints you depend on (API gateways, SSO hosts) for certificate health.
- Post-renewal verification: hit "Check now" and confirm the new certificate's expiry, issuer and fingerprint.

## Dependencies for

This template has **no external service dependencies**: a single Node 22 container, the attached `/data` volume for SQLite persistence, and outbound internet access to perform TLS checks (port 443 or your configured port on the hosts you monitor). All alert sinks are optional and disabled unless you configure them.

### Deployment Dependencies

- **Volume:** one Railway volume mounted at `/data` (created automatically by the template; owned by root and taken over by the app's unprivileged user at boot).
- **Public domain:** generated automatically at deploy time; the healthcheck probes `/health`.
- **Optional environment variables (set after deploy if desired):** `ADMIN_PASSWORD`, `ALERT_WEBHOOK_URL`, `SMTP_URL`, `ALERT_EMAIL_TO`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `ALERT_THRESHOLDS` (default `30,14,7,3,1`), `CHECK_INTERVAL_HOURS` (default `6`), `MAX_CONCURRENT_CHECKS` (default `4`).
