// Scheduler: plain 30s interval tick over a due-queue (per-domain
// next_check_at), with a concurrency-limited dispatch pool. cron syntax adds
// nothing for per-domain intervals; this is simpler and observable.
import config from './config.js';
import db from './db.js';
import { checkTls } from './tlscheck.js';
import { assertAllowed, GuardError } from './guard.js';
import { makeEvaluator, channelsFromConfig } from './alerts.js';

const evaluate = makeEvaluator({
  db,
  thresholds: config.thresholds,
  channels: channelsFromConfig()
});

const inFlight = new Set();
let timer = null;

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

// One full check of one domain: guard -> tls check -> persist -> alert state machine.
export async function runCheck(domain) {
  const started = Date.now();
  try {
    await assertAllowed(domain.host);
  } catch (err) {
    const blocked = err instanceof GuardError;
    const result = {
      status: blocked ? 'blocked' : 'unreachable',
      daysRemaining: null,
      error: err.message,
      latencyMs: Date.now() - started
    };
    db.insertCheck(domain.id, result);
    log({ msg: 'check', host: domain.host, port: domain.port, ...result });
    return result;
  }

  const result = await checkTls(domain.host, domain.port, config.checkTimeoutMs);
  db.insertCheck(domain.id, result);
  log({
    msg: 'check',
    host: domain.host,
    port: domain.port,
    status: result.status,
    daysRemaining: result.daysRemaining,
    issuer: result.issuer || undefined,
    latencyMs: result.latencyMs,
    error: result.error || undefined
  });

  if (result.fingerprint && ['valid', 'expired', 'invalid'].includes(result.status)) {
    try {
      await evaluate(domain, result);
    } catch (err) {
      log({ msg: 'alert_error', host: domain.host, error: err.message });
    }
  }
  return result;
}

function dispatch(domain) {
  inFlight.add(domain.id);
  runCheck(domain)
    .catch((err) => log({ msg: 'check_crash', host: domain.host, error: err.message }))
    .finally(() => {
      inFlight.delete(domain.id);
      const jitter = 0.98 + Math.random() * 0.04; // +/-2% so checks spread out
      const next = new Date(Date.now() + domain.interval_hours * 3600000 * jitter).toISOString();
      db.setNextCheck(domain.id, next);
    });
}

function tick() {
  if (inFlight.size >= config.maxConcurrentChecks) return;
  for (const d of db.dueDomains(new Date().toISOString())) {
    if (inFlight.size >= config.maxConcurrentChecks) break;
    if (inFlight.has(d.id)) continue;
    dispatch(d);
  }
}

export default {
  start() {
    if (timer) return;
    log({
      msg: 'scheduler_start',
      tickMs: 30000,
      concurrency: config.maxConcurrentChecks,
      defaultIntervalHours: config.defaultIntervalHours,
      thresholds: config.thresholds
    });
    tick(); // immediate first pass (fresh boot: due domains checked right away)
    timer = setInterval(tick, 30000);
  },
  stop() {
    if (timer) clearInterval(timer);
    timer = null;
  },
  isBusy: (id) => inFlight.has(id),
  checkNow(domain) {
    if (inFlight.has(domain.id)) return false;
    dispatch(domain);
    return true;
  }
};
