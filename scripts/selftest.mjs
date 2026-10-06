// Local selftest (run before push): band mapping, target guard, alert state
// machine (once per threshold per certificate, reset on renewal), and two
// live TLS checks against public fixtures. No test framework — node:assert.
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const failures = [];
async function test(name, fn) {
  try {
    await fn();
    console.log('PASS', name);
  } catch (err) {
    failures.push(name);
    console.error('FAIL', name, '\n  ', err.message);
  }
}

// ---------- 1. color bands ----------
const { bandFor } = await import('../server/bands.js');
await test('band mapping: >30 green / 14-30 amber / <14 red / broken red', () => {
  assert.equal(bandFor(54, 'valid'), 'green');
  assert.equal(bandFor(31, 'valid'), 'green');
  assert.equal(bandFor(30, 'valid'), 'amber');
  assert.equal(bandFor(14, 'valid'), 'amber');
  assert.equal(bandFor(13, 'valid'), 'red');
  assert.equal(bandFor(1, 'valid'), 'red');
  assert.equal(bandFor(0, 'valid'), 'red');
  assert.equal(bandFor(-4199, 'expired'), 'red');
  assert.equal(bandFor(null, 'unreachable'), 'red');
  assert.equal(bandFor(null, 'blocked'), 'red');
  assert.equal(bandFor(null, null), 'none');
});

// ---------- 2. target guard ----------
const { assertAllowed, GuardError, forbiddenReason } = await import('../server/guard.js');
await test('guard blocks loopback / link-local / metadata / unspecified / multicast literals', async () => {
  const bad = ['127.0.0.1', '169.254.169.254', '::1', 'fe80::1', '::ffff:127.0.0.1', '0.0.0.0', '224.0.0.1'];
  for (const target of bad) {
    await assert.rejects(() => assertAllowed(target), GuardError, `should block ${target}`);
    assert.ok(forbiddenReason(target), `has reason for ${target}`);
  }
});
await test('guard blocks hostnames that resolve into loopback', async () => {
  await assert.rejects(() => assertAllowed('localhost'), GuardError);
});
await test('guard allows public hosts', async () => {
  await assertAllowed('example.com');
  await assertAllowed('github.com');
});

// ---------- 3. alert state machine (temp DB, fake channel) ----------
await test('alert state machine: 5 fires for expired cert, no dupes, resets on renewal', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'certmon-selftest-'));
  try {
    process.env.DATA_DIR = tmp;
    const configMod = await import('../server/config.js');
    const db = (await import('../server/db.js')).default;
    const { makeEvaluator } = await import('../server/alerts.js');

    const sent = [];
    const channels = [{ name: 'webhook', send: async (a) => sent.push(`${a.thresholdDays}:${a.fingerprint}`) }];
    const evaluate = makeEvaluator({ db, thresholds: configMod.default.thresholds, channels });
    const domain = db.addDomain({ host: 'example.com', port: 443, intervalHours: 6 });

    const cert = (fp, days) => ({
      status: days < 0 ? 'expired' : 'valid',
      daysRemaining: days,
      validTo: '2027-01-01T00:00:00.000Z',
      issuer: 'CN=Test CA',
      subject: 'CN=example.com',
      sanCount: 1,
      fingerprint: fp,
      error: null,
      latencyMs: 5
    });

    const expired = cert('sha256:AAA', -10);
    await evaluate(domain, expired);
    assert.equal(sent.length, 5, `expired cert fires all 5 thresholds once (got ${sent.length})`);

    await evaluate(domain, expired); // re-check: no duplicates
    await evaluate(domain, expired); // and again
    assert.equal(sent.length, 5, 'no duplicate alerts on repeated checks');

    const renewed = cert('sha256:BBB', 20); // days=20 -> only threshold 30 qualifies
    await evaluate(domain, renewed);
    assert.equal(sent.length, 6, 'renewed certificate gets a fresh alert');
    assert.ok(sent.includes('30:sha256:BBB'), 'renewal fired threshold 30');
    assert.ok(!sent.includes('14:sha256:BBB'), 'threshold 14 not fired at 20 days');

    await evaluate(domain, renewed);
    assert.equal(sent.length, 6, 'still no duplicates after renewal');

    assert.equal(db.raw.prepare('SELECT COUNT(*) AS n FROM alert_log').get().n, 6);
    db.raw.close();
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------- 4. live TLS checks (public fixtures) ----------
const { checkTls } = await import('../server/tlscheck.js');
await test('live check: github.com is valid with usable metadata', async () => {
  const r = await checkTls('github.com', 443, 10000);
  assert.equal(r.status, 'valid', JSON.stringify(r));
  assert.ok(r.daysRemaining > 0, `daysRemaining ${r.daysRemaining}`);
  assert.ok(r.validTo.endsWith('Z'), `validTo ${r.validTo}`);
  assert.ok(r.issuer.length > 0, 'issuer captured');
  assert.ok(r.subject.includes('CN=github.com'), `subject ${r.subject}`);
  assert.ok(r.fingerprint.startsWith('sha256:'), 'fingerprint captured');
  assert.ok(r.sanCount > 0, 'SANs captured');
});
await test('live check: expired.badssl.com detected as expired', async () => {
  const r = await checkTls('expired.badssl.com', 443, 10000);
  assert.equal(r.status, 'expired', JSON.stringify(r));
  assert.ok(r.daysRemaining < 0, `negative days, got ${r.daysRemaining}`);
  assert.ok(/expired/i.test(r.error || ''), `error mentions expiry: ${r.error}`);
  assert.ok(r.validTo.startsWith('2015-04-12'), `ground truth validTo, got ${r.validTo}`);
  assert.ok(r.fingerprint.startsWith('sha256:'), 'metadata still captured in phase 2');
});
await test('live check: unreachable target reported cleanly', async () => {
  const r = await checkTls('no-such-host-certmon.invalid', 443, 10000);
  assert.equal(r.status, 'unreachable');
  assert.equal(r.daysRemaining, null);
  assert.ok(r.error, 'error message present');
});

console.log('');
if (failures.length > 0) {
  console.error(`${failures.length} test(s) FAILED`);
  process.exit(1);
}
console.log('ALL TESTS PASSED');
