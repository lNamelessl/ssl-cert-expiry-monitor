// Dashboard — vanilla JS, no build step, no external dependencies.
'use strict';

const $ = (sel) => document.querySelector(sel);
let adminPw = sessionStorage.getItem('certmon.adminPw') || '';
let openHistory = new Set(); // domain ids with expanded history

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
}

function fmtAgo(iso) {
  if (!iso) return 'never';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (adminPw) headers['x-admin-password'] = adminPw;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) {
    $('#pwPanel').hidden = false;
    throw new Error('admin password required');
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body && body.error) msg = body.error;
    } catch {}
    throw new Error(msg);
  }
  return res;
}

function showErr(which, err) {
  const el = $(which);
  el.textContent = err.message;
  setTimeout(() => { el.textContent = ''; }, 8000);
}

function badge(text, cls) {
  const span = document.createElement('span');
  span.className = `badge ${cls}`;
  span.textContent = text;
  return span;
}

function renderDomain(d) {
  const tr = document.createElement('tr');

  const tdHost = document.createElement('td');
  const hostSpan = document.createElement('span');
  hostSpan.className = 'hostcell';
  hostSpan.textContent = d.host;
  tdHost.appendChild(hostSpan);
  const sub = document.createElement('span');
  sub.className = 'sub';
  sub.textContent = `:${d.port} · every ${d.intervalHours}h`;
  tdHost.appendChild(sub);
  tr.appendChild(tdHost);

  const tdStatus = document.createElement('td');
  if (d.status) {
    tdStatus.appendChild(badge(d.status, `status-${d.status}`));
  } else {
    tdStatus.appendChild(badge('pending', 'band-none'));
  }
  tr.appendChild(tdStatus);

  const tdDays = document.createElement('td');
  if (d.daysRemaining !== null && d.daysRemaining !== undefined) {
    tdDays.appendChild(badge(String(d.daysRemaining), `band-${d.band}`));
  } else {
    tdDays.appendChild(badge('—', 'band-none'));
  }
  tr.appendChild(tdDays);

  const tdExp = document.createElement('td');
  tdExp.textContent = d.validTo ? fmtDate(d.validTo) : '—';
  tr.appendChild(tdExp);

  const tdIssuer = document.createElement('td');
  tdIssuer.textContent = d.issuer || '—';
  tr.appendChild(tdIssuer);

  const tdLast = document.createElement('td');
  tdLast.textContent = fmtAgo(d.lastCheckedAt);
  tr.appendChild(tdLast);

  const tdAct = document.createElement('td');
  const bCheck = document.createElement('button');
  bCheck.className = 'link';
  bCheck.textContent = 'Check now';
  bCheck.onclick = async () => {
    try {
      await api(`/api/v1/domains/${d.id}/check`, { method: 'POST' });
      setTimeout(load, 2500);
    } catch (err) { showErr('#addMsg', err); }
  };
  const bHist = document.createElement('button');
  bHist.className = 'link';
  bHist.textContent = openHistory.has(d.id) ? 'Hide history' : 'History';
  bHist.onclick = () => {
    if (openHistory.has(d.id)) openHistory.delete(d.id);
    else openHistory.add(d.id);
    load();
  };
  const bDel = document.createElement('button');
  bDel.className = 'link danger';
  bDel.textContent = 'Remove';
  bDel.onclick = async () => {
    if (!confirm(`Remove ${d.host}:${d.port} and its history?`)) return;
    try {
      await api(`/api/v1/domains/${d.id}`, { method: 'DELETE' });
      openHistory.delete(d.id);
      load();
    } catch (err) { showErr('#addMsg', err); }
  };
  tdAct.append(bCheck, bHist, bDel);
  tr.appendChild(tdAct);
  return tr;
}

async function appendHistory(tbody, d) {
  const tr = document.createElement('tr');
  tr.className = 'histrow';
  const td = document.createElement('td');
  td.colSpan = 7;
  try {
    const res = await api(`/api/v1/domains/${d.id}/history?limit=20`);
    const body = await res.json();
    const ul = document.createElement('ul');
    for (const h of body.history) {
      const li = document.createElement('li');
      li.textContent =
        `${fmtAgo(h.checked_at)} — ${h.status}` +
        (h.days_remaining !== null ? ` · ${h.days_remaining}d left` : '') +
        (h.error ? ` · ${h.error}` : '') +
        (h.latency_ms !== null ? ` · ${h.latency_ms}ms` : '');
      ul.appendChild(li);
    }
    td.appendChild(ul);
  } catch (err) {
    td.textContent = `history unavailable: ${err.message}`;
  }
  tr.appendChild(td);
  tbody.appendChild(tr);
}

async function load() {
  try {
    const res = await api('/api/v1/domains');
    const body = await res.json();
    const tbody = $('#rows');
    tbody.textContent = '';
    for (const d of body.domains) {
      tbody.appendChild(renderDomain(d));
      if (openHistory.has(d.id)) await appendHistory(tbody, d);
    }
    $('#empty').hidden = body.domains.length > 0;
    const sinks = Object.entries(body.sinks)
      .map(([k, v]) => `${k}${v ? '' : ' (off)'}`)
      .join(', ');
    $('#meta').textContent =
      `Alert thresholds: ${body.thresholds.join('/')} days (one alert per threshold per certificate until renewed) · ` +
      `Alert sinks: ${sinks}`;
  } catch (err) {
    if (err.message !== 'admin password required') showErr('#addMsg', err);
  }
}

async function loadHealth() {
  try {
    const res = await fetch('/health');
    const body = await res.json();
    const pill = $('#health');
    pill.textContent = `ok · ${body.domains} domain${body.domains === 1 ? '' : 's'} · last check ${fmtAgo(body.lastCheck)}`;
    pill.classList.add('ok');
  } catch {
    $('#health').textContent = 'unreachable';
  }
}

$('#addForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const payload = { host: $('#host').value.trim() };
  if ($('#port').value) payload.port = Number($('#port').value);
  if ($('#interval').value) payload.intervalHours = Number($('#interval').value);
  try {
    const res = await api('/api/v1/domains', { method: 'POST', body: JSON.stringify(payload) });
    const row = await res.json();
    $('#host').value = '';
    $('#port').value = '';
    $('#addMsg').textContent = `added ${row.host}, first check running…`;
    setTimeout(load, 2500);
  } catch (err) {
    showErr('#addMsg', err);
  }
});

$('#pwForm').addEventListener('submit', (ev) => {
  ev.preventDefault();
  adminPw = $('#pwInput').value;
  sessionStorage.setItem('certmon.adminPw', adminPw);
  $('#pwPanel').hidden = true;
  $('#pwMsg').textContent = '';
  load();
});

loadHealth();
load();
setInterval(load, 30000);
setInterval(loadHealth, 60000);
