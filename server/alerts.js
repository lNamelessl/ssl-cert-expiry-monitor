// Alert state machine + sinks.
//
// Semantics: ONE alert per threshold per certificate per channel, until the
// certificate is renewed. State is the alert_log table keyed on
// (domain, threshold_days, cert fingerprint, channel) and persisted in SQLite
// on the /data volume, so restarts never re-fire.
//
// A check that produced cert data (valid | expired | invalid) is evaluated;
// unreachable/blocked checks never fire expiry alerts (a network blip must
// not page anyone about an expiry).
import config from './config.js';

function renderText(a) {
  return [
    `TLS certificate alert for ${a.domain}:${a.port}`,
    `status: ${a.status}`,
    a.daysRemaining < 0
      ? `EXPIRED ${Math.abs(a.daysRemaining)} day(s) ago`
      : `days remaining: ${a.daysRemaining}`,
    `threshold: ${a.thresholdDays} day(s)`,
    `expires at: ${a.expiresAt}`,
    `issuer: ${a.issuer}`,
    `subject: ${a.subject}`,
    `fingerprint: ${a.fingerprint}`
  ].join('\n');
}

async function sendWebhook(alert, cfg) {
  const res = await fetch(cfg.sinks.webhookUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...alert, service: 'ssl-cert-expiry-monitor' }),
    signal: AbortSignal.timeout(10000)
  });
  if (!res.ok) throw new Error(`webhook responded HTTP ${res.status}`);
}

let smtpTransport = null;
async function sendSmtp(alert, cfg) {
  if (!smtpTransport) {
    const nodemailer = (await import('nodemailer')).default;
    smtpTransport = nodemailer.createTransport(cfg.sinks.smtpUrl);
  }
  const subject =
    alert.daysRemaining < 0
      ? `[cert-expiry] ${alert.domain}: certificate EXPIRED`
      : `[cert-expiry] ${alert.domain}: expires in ${alert.daysRemaining} day(s)`;
  await smtpTransport.sendMail({
    from: process.env.ALERT_EMAIL_FROM || 'cert-expiry-monitor@no-reply.local',
    to: cfg.alertEmailTo,
    subject,
    text: renderText(alert)
  });
}

async function sendTelegram(alert, cfg) {
  const res = await fetch(
    `https://api.telegram.org/bot${cfg.sinks.telegramToken}/sendMessage`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        chat_id: cfg.sinks.telegramChatId,
        text: renderText(alert),
        disable_web_page_preview: true
      }),
      signal: AbortSignal.timeout(10000)
    }
  );
  if (!res.ok) throw new Error(`telegram responded HTTP ${res.status}`);
}

export function severityFor(result, thresholdDays) {
  if (result.status === 'expired' || (result.daysRemaining ?? 0) < 0) return 'critical';
  return thresholdDays >= 14 ? 'warning' : 'critical';
}

// Which channels are configured right now (all optional).
export function channelsFromConfig(cfg = config) {
  const channels = [];
  if (cfg.sinks.webhookUrl) {
    channels.push({ name: 'webhook', send: (a) => sendWebhook(a, cfg) });
  }
  if (cfg.sinks.smtpUrl && cfg.alertEmailTo) {
    channels.push({ name: 'smtp', send: (a) => sendSmtp(a, cfg) });
  }
  if (cfg.sinks.telegramToken && cfg.sinks.telegramChatId) {
    channels.push({ name: 'telegram', send: (a) => sendTelegram(a, cfg) });
  }
  return channels;
}

export function makeEvaluator({ db, thresholds, channels }) {
  const isSent = db.raw.prepare(
    'SELECT 1 FROM alert_log WHERE domain_id = ? AND threshold_days = ? AND fingerprint = ? AND channel = ?'
  );
  const record = db.raw.prepare(
    'INSERT OR IGNORE INTO alert_log (domain_id, threshold_days, fingerprint, channel, sent_at) VALUES (?, ?, ?, ?, ?)'
  );
  const tx = db.raw.transaction((rows) => {
    for (const r of rows) record.run(...r);
  });

  return async function evaluate(domain, result) {
    if (channels.length === 0 || result.daysRemaining == null) return;
    for (const thresholdDays of thresholds) {
      if (result.daysRemaining > thresholdDays) continue;
      const pending = [];
      for (const ch of channels) {
        if (isSent.get(domain.id, thresholdDays, result.fingerprint, ch.name)) continue;
        const alert = {
          event: 'cert_expiry_warning',
          severity: severityFor(result, thresholdDays),
          domain: domain.host,
          port: domain.port,
          daysRemaining: result.daysRemaining,
          thresholdDays,
          expiresAt: result.validTo,
          subject: result.subject,
          issuer: result.issuer,
          fingerprint: result.fingerprint,
          status: result.status,
          checkedAt: new Date().toISOString()
        };
        await ch.send(alert); // send first; record only on success (at-least-once)
        pending.push([domain.id, thresholdDays, result.fingerprint, ch.name, alert.checkedAt]);
      }
      if (pending.length > 0) tx(pending);
    }
  };
}
