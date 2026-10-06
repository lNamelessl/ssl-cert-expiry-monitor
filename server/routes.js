// REST API + optional password gate + /health.
// Auth model: dashboard reads are ALWAYS open. When ADMIN_PASSWORD is set,
// mutating endpoints (add / remove / force-check) require the
// "x-admin-password" header. Trust boundary: the app is reached over HTTPS
// (TLS terminated at Railway's edge); the password must only ever be sent to
// its https:// URL.
import config from './config.js';
import db from './db.js';
import { assertAllowed } from './guard.js';
import { bandFor } from './bands.js';
import scheduler from './scheduler.js';

const HOST_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

function present(row) {
  return {
    id: row.id,
    host: row.host,
    port: row.port,
    intervalHours: row.interval_hours,
    nextCheckAt: row.next_check_at,
    createdAt: row.created_at,
    status: row.status ?? null,
    daysRemaining: row.days_remaining ?? null,
    validTo: row.valid_to ?? null,
    issuer: row.issuer ?? null,
    subject: row.subject ?? null,
    sanCount: row.san_count ?? null,
    fingerprint: row.fingerprint ?? null,
    error: row.error ?? null,
    lastCheckedAt: row.last_checked_at ?? null,
    latencyMs: row.latency_ms ?? null,
    band: bandFor(row.days_remaining ?? null, row.status ?? null)
  };
}

async function requirePassword(req, reply) {
  if (!config.adminPassword) return;
  const given = req.headers['x-admin-password'];
  if (given !== config.adminPassword) {
    reply.code(401).send({ error: 'unauthorized: missing or wrong x-admin-password header' });
  }
}

export default async function registerRoutes(app) {
  app.get('/health', async () => ({
    status: 'ok',
    lastCheck: db.lastCheckAt(),
    domains: db.countDomains(),
    uptimeSec: Math.round(process.uptime()),
    version: config.version
  }));

  app.get('/api/v1/domains', async () => ({
    thresholds: config.thresholds,
    sinks: {
      webhook: Boolean(config.sinks.webhookUrl),
      smtp: Boolean(config.sinks.smtpUrl && config.alertEmailTo),
      telegram: Boolean(config.sinks.telegramToken && config.sinks.telegramChatId)
    },
    domains: db.listDomainsWithLatest().map(present)
  }));

  app.post('/api/v1/domains', { preHandler: requirePassword }, async (req, reply) => {
    const body = req.body || {};
    const host = String(body.host || '').trim().toLowerCase().replace(/\.$/, '');
    if (!HOST_RE.test(host)) {
      return reply.code(400).send({ error: 'invalid hostname — expected something like example.com' });
    }
    const port =
      body.port === undefined || body.port === null || body.port === ''
        ? 443
        : Number(body.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return reply.code(400).send({ error: 'invalid port (1-65535)' });
    }
    const intervalHours =
      body.intervalHours === undefined || body.intervalHours === null || body.intervalHours === ''
        ? config.defaultIntervalHours
        : Number(body.intervalHours);
    if (!Number.isInteger(intervalHours) || intervalHours < 1 || intervalHours > 168) {
      return reply.code(400).send({ error: 'invalid intervalHours (1-168)' });
    }
    try {
      await assertAllowed(host);
    } catch (err) {
      return reply.code(400).send({ error: err.message });
    }
    if (db.getDomainByHostPort(host, port)) {
      return reply.code(409).send({ error: 'this host:port is already monitored' });
    }
    const row = db.addDomain({ host, port, intervalHours });
    scheduler.checkNow(row); // first check immediately
    return reply.code(201).send(present(row));
  });

  app.delete('/api/v1/domains/:id', { preHandler: requirePassword }, async (req, reply) => {
    const id = Number(req.params.id);
    if (!db.getDomain(id)) return reply.code(404).send({ error: 'no such domain' });
    db.deleteDomain(id);
    return reply.code(204).send();
  });

  app.post('/api/v1/domains/:id/check', { preHandler: requirePassword }, async (req, reply) => {
    const row = db.getDomain(Number(req.params.id));
    if (!row) return reply.code(404).send({ error: 'no such domain' });
    const queued = scheduler.checkNow(row);
    return reply.code(202).send({ queued });
  });

  app.get('/api/v1/domains/:id/history', async (req, reply) => {
    const id = Number(req.params.id);
    if (!db.getDomain(id)) return reply.code(404).send({ error: 'no such domain' });
    let limit = Number(req.query.limit);
    if (!Number.isInteger(limit) || limit < 1) limit = 50;
    if (limit > 200) limit = 200;
    return { history: db.getHistory(id, limit) };
  });
}
