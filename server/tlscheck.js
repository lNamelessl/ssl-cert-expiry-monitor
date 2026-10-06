// TLS certificate check.
// Phase 1: strict connect (rejectUnauthorized: true, SNI = hostname, default
//          checkServerIdentity ON). A clean handshake => status "valid".
// Phase 2: only when phase 1 failed with a CERTIFICATE problem, retry once
//          permissively (rejectUnauthorized: false) purely to CAPTURE the
//          certificate metadata (expiry, issuer, subject, SANs, fingerprint).
//          This is what lets the dashboard show "expired 4199 days ago, red"
//          for broken certs instead of an opaque "check failed".
// Anything else (timeout, refused, DNS) => status "unreachable", no cert data.
import tls from 'node:tls';

const CERT_ERROR_RE =
  /CERT_|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME|ERR_TLS|ERR_SSL|certificate/i;

function connectOnce(host, port, timeoutMs, rejectUnauthorized) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host, // SNI = hostname
        rejectUnauthorized,
        minVersion: 'TLSv1.2'
      },
      () => resolve(socket)
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy(new Error(`connection timeout after ${timeoutMs}ms`));
    });
    socket.once('error', reject);
  });
}

function normalizeDn(dn) {
  if (!dn) return '';
  if (typeof dn === 'string') return dn;
  const order = ['CN', 'O', 'OU', 'L', 'ST', 'C'];
  const val = (v) => (Array.isArray(v) ? v.join(', ') : String(v));
  const parts = [];
  for (const k of order) {
    if (dn[k] !== undefined) parts.push(`${k}=${val(dn[k])}`);
  }
  for (const k of Object.keys(dn)) {
    if (!order.includes(k)) parts.push(`${k}=${val(dn[k])}`);
  }
  return parts.join(', ');
}

function capture(socket) {
  const cert = socket.getPeerCertificate(true); // leaf + chain
  if (!cert || Object.keys(cert).length === 0) {
    throw new Error('no certificate presented');
  }
  const validToDate = new Date(cert.valid_to);
  if (Number.isNaN(validToDate.getTime())) {
    throw new Error('unparseable certificate expiry date');
  }
  const sans = String(cert.subjectaltname || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return {
    validTo: validToDate.toISOString(),
    daysRemaining: Math.floor((validToDate.getTime() - Date.now()) / 86400000),
    issuer: normalizeDn(cert.issuer),
    subject: normalizeDn(cert.subject),
    sanCount: sans.length,
    fingerprint: 'sha256:' + (cert.fingerprint256 || '')
  };
}

function classify(err) {
  const code = String(err.code || '');
  const msg = String(err.message || '');
  if (code === 'CERT_HAS_EXPIRED' || /certificate has expired/i.test(msg)) return 'expired';
  if (CERT_ERROR_RE.test(code + ' ' + msg)) return 'invalid';
  return null; // not a certificate problem
}

function unreachable(err, started) {
  return {
    status: 'unreachable',
    daysRemaining: null,
    validTo: null,
    issuer: null,
    subject: null,
    sanCount: null,
    fingerprint: null,
    error: String(err.message || err),
    latencyMs: Date.now() - started
  };
}

export async function checkTls(host, port, timeoutMs = 10000) {
  const started = Date.now();
  try {
    const socket = await connectOnce(host, port, timeoutMs, true);
    const info = capture(socket);
    socket.destroy();
    return { status: 'valid', ...info, error: null, latencyMs: Date.now() - started };
  } catch (strictErr) {
    const kind = classify(strictErr);
    if (!kind) return unreachable(strictErr, started);
    try {
      const socket = await connectOnce(host, port, timeoutMs, false);
      const info = capture(socket);
      socket.destroy();
      return {
        status: kind, // "expired" or "invalid"
        ...info,
        error: String(strictErr.code ? `${strictErr.code}: ` : '') + String(strictErr.message || strictErr),
        latencyMs: Date.now() - started
      };
    } catch (permissiveErr) {
      return unreachable(permissiveErr, started);
    }
  }
}
