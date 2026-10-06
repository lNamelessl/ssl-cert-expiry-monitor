// SQLite persistence (better-sqlite3 v13: bundled native prebuilds, no compile).
// Single writer (this process), WAL mode, synchronous API — ideal for the
// small write volume of a monitor and for atomic alert-state bookkeeping.
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import config from './config.js';

fs.mkdirSync(config.dataDir, { recursive: true });
const file = path.join(config.dataDir, 'certwatch.db');

const db = new Database(file);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 443,
  interval_hours INTEGER NOT NULL DEFAULT 6,
  next_check_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(host, port)
);
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  checked_at TEXT NOT NULL,
  status TEXT NOT NULL,
  days_remaining INTEGER,
  valid_to TEXT,
  issuer TEXT,
  subject TEXT,
  san_count INTEGER,
  fingerprint TEXT,
  error TEXT,
  latency_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_checks_domain ON checks(domain_id, id DESC);
CREATE TABLE IF NOT EXISTS alert_log (
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  threshold_days INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  channel TEXT NOT NULL,
  sent_at TEXT NOT NULL,
  PRIMARY KEY (domain_id, threshold_days, fingerprint, channel)
);
`);

const stmts = {
  insertDomain: db.prepare(
    'INSERT INTO domains (host, port, interval_hours, next_check_at, created_at) VALUES (?, ?, ?, NULL, ?)'
  ),
  getDomain: db.prepare('SELECT * FROM domains WHERE id = ?'),
  getByHostPort: db.prepare('SELECT * FROM domains WHERE host = ? AND port = ?'),
  deleteDomain: db.prepare('DELETE FROM domains WHERE id = ?'),
  setNextCheck: db.prepare('UPDATE domains SET next_check_at = ? WHERE id = ?'),
  due: db.prepare(
    'SELECT * FROM domains WHERE next_check_at IS NULL OR next_check_at <= ? ORDER BY COALESCE(next_check_at, created_at)'
  ),
  listAll: db.prepare(`
    SELECT d.id, d.host, d.port, d.interval_hours, d.next_check_at, d.created_at,
           c.status, c.days_remaining, c.valid_to, c.issuer, c.subject,
           c.san_count, c.fingerprint, c.error, c.checked_at AS last_checked_at, c.latency_ms
    FROM domains d
    LEFT JOIN checks c ON c.id = (
      SELECT id FROM checks WHERE domain_id = d.id ORDER BY id DESC LIMIT 1
    )
    ORDER BY d.id
  `),
  insertCheck: db.prepare(`
    INSERT INTO checks (domain_id, checked_at, status, days_remaining, valid_to,
                        issuer, subject, san_count, fingerprint, error, latency_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  prune: db.prepare(`
    DELETE FROM checks WHERE domain_id = ? AND id NOT IN (
      SELECT id FROM checks WHERE domain_id = ? ORDER BY id DESC LIMIT 200
    )
  `),
  history: db.prepare(
    'SELECT * FROM checks WHERE domain_id = ? ORDER BY id DESC LIMIT ?'
  ),
  countDomains: db.prepare('SELECT COUNT(*) AS n FROM domains'),
  lastCheck: db.prepare('SELECT MAX(checked_at) AS t FROM checks')
};

export default {
  raw: db,
  file,
  addDomain({ host, port, intervalHours }) {
    const info = stmts.insertDomain.run(host, port, intervalHours, new Date().toISOString());
    return stmts.getDomain.get(info.lastInsertRowid);
  },
  getDomain: (id) => stmts.getDomain.get(id),
  getDomainByHostPort: (host, port) => stmts.getByHostPort.get(host, port),
  deleteDomain: (id) => stmts.deleteDomain.run(id),
  listDomainsWithLatest: () => stmts.listAll.all(),
  dueDomains: (nowIso) => stmts.due.all(nowIso),
  setNextCheck: (id, iso) => stmts.setNextCheck.run(iso, id),
  insertCheck(domainId, r) {
    stmts.insertCheck.run(
      domainId,
      new Date().toISOString(),
      r.status,
      r.daysRemaining ?? null,
      r.validTo ?? null,
      r.issuer ?? null,
      r.subject ?? null,
      r.sanCount ?? null,
      r.fingerprint ?? null,
      r.error ?? null,
      r.latencyMs ?? null
    );
    stmts.prune.run(domainId, domainId); // keep newest 200 per domain
  },
  getHistory: (domainId, limit) => stmts.history.all(domainId, limit),
  countDomains: () => stmts.countDomains.get().n,
  lastCheckAt: () => {
    const row = stmts.lastCheck.get();
    return row && row.t ? row.t : null;
  }
};
