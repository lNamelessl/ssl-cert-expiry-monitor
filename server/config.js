// Central configuration. EVERY variable is optional: the container boots with
// sane defaults and zero environment variables (Railway zero-prompt template).

function intEnv(name, dflt, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return dflt;
  const v = Number.parseInt(raw, 10);
  if (!Number.isFinite(v)) return dflt;
  if (min !== undefined && v < min) return dflt;
  if (max !== undefined && v > max) return dflt;
  return v;
}

function thresholdsFromEnv() {
  const dflt = [30, 14, 7, 3, 1];
  const raw = process.env.ALERT_THRESHOLDS;
  if (!raw) return dflt;
  const parsed = raw
    .split(',')
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n) && n >= 0 && n <= 3650);
  return parsed.length > 0 ? [...new Set(parsed)].sort((a, b) => b - a) : dflt;
}

const config = {
  port: intEnv('PORT', 8080, 1, 65535),
  dataDir: process.env.DATA_DIR || '/data',
  defaultIntervalHours: intEnv('CHECK_INTERVAL_HOURS', 6, 1, 168),
  maxConcurrentChecks: intEnv('MAX_CONCURRENT_CHECKS', 4, 1, 32),
  checkTimeoutMs: intEnv('CHECK_TIMEOUT_MS', 10000, 1000, 60000),
  adminPassword: process.env.ADMIN_PASSWORD || '',
  alertEmailTo: process.env.ALERT_EMAIL_TO || '',
  thresholds: thresholdsFromEnv(),
  sinks: {
    webhookUrl: process.env.ALERT_WEBHOOK_URL || '',
    smtpUrl: process.env.SMTP_URL || '',
    telegramToken: process.env.TELEGRAM_BOT_TOKEN || '',
    telegramChatId: process.env.TELEGRAM_CHAT_ID || ''
  },
  version: '1.0.0'
};

export default config;
