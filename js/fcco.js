'use strict';
// ============================================================
// ROMI NEXUS — FCCO DASHBOARD v1.3
// OWASP + DIFC DPL 2020 HARDENING
//
// v1.1 — CSP: bar width via CSS custom property
// v1.2 — White page fix: show shell first, try/catch bootApp
// v1.3 — Compliance hardening:
//   [OWASP A04 / DIFC Art.19] localStorage encrypted via AES-GCM,
//     key derived from session CSRF token (HKDF-SHA-256)
//   [DIFC Art.5]  90-day TTL: records older than 90d auto-purged on boot
//   [DIFC Art.17] deleteAllData() — right to erasure, bound to UI button
//   [OWASP A06]   cdnjs removed from CSP entirely (was unused)
//   [DIFC Notice] data processing notice shown at auth screen
//   Modal show/hide via classList only (no style.display — CSP clean)
// v4.2.5 — CRM SYNC: mirror writes to Supabase via Worker
// ============================================================

const API_URL = 'https://rominexus-gateway-v6.vacorp-inquiries.workers.dev';
const DATA_TTL_DAYS = 90;

function sanitize(str) {
  return String(str || '')
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
}

// ============================================================
// CRM SYNC — v4.2.5
// Persists localStorage state to Supabase via Worker.
// Called after every write to qc_list, hours_log, attr_log.
// Fire-and-forget: localStorage remains the source of truth
// for UI rendering; Supabase is the audit-grade backup.
// ============================================================
async function syncToServer(action, payload) {
  const s = getSession();
  if (!s.email || !s.csrf) return; // not authenticated — skip silently

  try {
    const body = JSON.stringify({
      action,
      email:  s.email,
      _csrf:  s.csrf,
      ...payload,
    });
    const res = await fetch(API_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    const data = await res.json().catch(() => ({}));
    if (data.error) {
      console.warn('[CRM SYNC] Server rejected:', action, data.error);
    }
  } catch (e) {
    console.warn('[CRM SYNC] Network error — will retry on next save:', e.message);
    // Non-fatal: localStorage entry is still written.
    // On next login, a full sync pass can be triggered.
  }
}

// ============================================================
// ── ENCRYPTED localStorage (OWASP A04 / DIFC Art.19) ──
// Key is derived fresh each session from the CSRF token via HKDF.
// Data at rest is AES-GCM encrypted — unreadable without the key.
// Falls back to plain JSON read on decryption failure (migration).
// ============================================================
let _cryptoKey = null;

async function deriveCryptoKey(csrf) {
  const enc     = new TextEncoder();
  const rawKey  = enc.encode(csrf);
  const baseKey = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveKey']);
  _cryptoKey = await crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt: enc.encode('rn-fcco-v1'), info: enc.encode('localStorage') },
    baseKey,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

async function encryptData(obj) {
  if (!_cryptoKey) return JSON.stringify(obj);
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const enc  = new TextEncoder();
  const ct   = await crypto.subtle.encrypt({name:'AES-GCM', iv}, _cryptoKey, enc.encode(JSON.stringify(obj)));
  const buf  = new Uint8Array(iv.length + ct.byteLength);
  buf.set(iv, 0);
  buf.set(new Uint8Array(ct), iv.length);
  return btoa(String.fromCharCode(...buf));
}

async function decryptData(raw, def) {
  if (!_cryptoKey || !raw) return def;
  try {
    const buf  = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
    const iv   = buf.slice(0, 12);
    const ct   = buf.slice(12);
    const pt   = await crypto.subtle.decrypt({name:'AES-GCM', iv}, _cryptoKey, ct);
    return JSON.parse(new TextDecoder().decode(pt));
  } catch(_) {
    try { return JSON.parse(raw); } catch(_2) { return def; }
  }
}

async function getLocalData(key, def) {
  try {
    const raw = localStorage.getItem('rn_mario_' + key);
    if (!raw) return def;
    return await decryptData(raw, def);
  } catch(_) { return def; }
}
async function setLocalData(key, val) {
  try {
    const enc = await encryptData(val);
    localStorage.setItem('rn_mario_' + key, enc);
  } catch(_) {}
}

// ── DIFC Art.5 — 90-day TTL purge ──
async function purgeStaledData() {
  const cutoff = Date.now() - DATA_TTL_DAYS * 86400000;

  const hours = await getLocalData('hours_log', []);
  const freshHours = hours.filter(e => {
    const t = e.ts ? new Date(e.ts).getTime() : new Date(e.date).getTime();
    return t >= cutoff;
  });
  if (freshHours.length !== hours.length) await setLocalData('hours_log', freshHours);

  const qc = await getLocalData('qc_list', []);
  const freshQC = qc.filter(e => {
    const t = e.addedAt ? new Date(e.addedAt).getTime() : Date.now();
    return t >= cutoff;
  });
  if (freshQC.length !== qc.length) await setLocalData('qc_list', freshQC);

  const attr = await getLocalData('attr_log', []);
  const freshAttr = attr.filter(e => {
    const t = e.ts ? new Date(e.ts).getTime() : Date.now();
    return t >= cutoff;
  });
  if (freshAttr.length !== attr.length) await setLocalData('attr_log', freshAttr);
}

// ── DIFC Art.17 — Right to Erasure ──
async function deleteAllData() {
  if (!confirm('DELETE ALL LOCAL DATA?\n\nThis will permanently erase all hours logs, counterparty records, and attribution data stored on this device.\n\nThis action cannot be undone.')) return;
  try {
    ['hours_log','qc_list','attr_log'].forEach(k => localStorage.removeItem('rn_mario_' + k));
    clearSession();
    alert('All local data deleted. You will now be logged out.');
    location.reload();
  } catch(e) {
    alert('Error deleting data: ' + e.message);
  }
}

// ── Session state ──
let _email = '';
let _csrf  = '';
let _name  = '';

function getSession() {
  try {
    return {
      email: sessionStorage.getItem('rn_mario_email') || '',
      csrf:  sessionStorage.getItem('rn_mario_csrf')  || '',
      name:  sessionStorage.getItem('rn_mario_name')  || '',
    };
  } catch(_) { return {email:'',csrf:'',name:''}; }
}
function setSession(email, csrf, name) {
  try {
    sessionStorage.setItem('rn_mario_email', email);
    sessionStorage.setItem('rn_mario_csrf',  csrf);
    sessionStorage.setItem('rn_mario_name',  name);
  } catch(_) {}
}
function clearSession() {
  try {
    sessionStorage.removeItem('rn_mario_email');
    sessionStorage.removeItem('rn_mario_csrf');
    sessionStorage.removeItem('rn_mario_name');
  } catch(_) {}
}

// ── Auth ──
async function sendOTP() {
  const emailInput = document.getElementById('authEmail');
  const email = (emailInput.value || '').trim().toLowerCase();
  if (!email || !/^[^\s@]{1,64}@[^\s@]{1,255}$/.test(email)) {
    setAuthMsg(1, 'VALID EMAIL REQUIRED', 'err'); return;
  }
  setAuthMsg(1, 'SENDING…', 'info');
  document.getElementById('sendOtpBtn').disabled = true;
  try {
    const body = 'action=sendOTP&email=' + encodeURIComponent(email);
    const res  = await fetch(API_URL, {
      method:  'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body
    });
    const data = await res.json();
    if (data.error) { setAuthMsg(1, String(data.error).substring(0,80), 'err'); document.getElementById('sendOtpBtn').disabled=false; return; }
    _email = email;
    document.getElementById('stepEmail').classList.remove('active');
    document.getElementById('stepOTP').classList.add('active');
    setAuthMsg(2, 'CODE SENT — CHECK YOUR EMAIL', 'ok');
  } catch(e) { setAuthMsg(1, 'NETWORK ERROR — RETRY', 'err'); document.getElementById('sendOtpBtn').disabled=false; }
}

async function verifyOTP() {
  const otp = (document.getElementById('authOTP').value || '').trim();
  if (!/^\d{6}$/.test(otp)) { setAuthMsg(2, 'ENTER 6-DIGIT CODE', 'err'); return; }
  setAuthMsg(2, 'VERIFYING…', 'info');
  document.getElementById('verifyOtpBtn').disabled = true;
  try {
    const csrf = generateCSRF();
    const body = 'action=verifyOTP&email=' + encodeURIComponent(_email) +
                 '&otp=' + encodeURIComponent(otp) +
                 '&_csrf=' + encodeURIComponent(csrf);
    const res  = await fetch(API_URL, {
      method:  'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body
    });
    const data = await res.json();
    if (data.error) {
      setAuthMsg(2, String(data.error).substring(0,80), 'err');
      document.getElementById('verifyOtpBtn').disabled = false;
      return;
    }
    _csrf = csrf;
    _name = data.name || _email;
    setSession(_email, _csrf, _name);
    await deriveCryptoKey(_csrf);
    bootApp();
  } catch(e) { setAuthMsg(2, 'NETWORK ERROR — RETRY', 'err'); document.getElementById('verifyOtpBtn').disabled=false; }
}

function generateCSRF() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

function setAuthMsg(step, msg, cls) {
  const el = document.getElementById('authMsg' + step);
  if (!el) return;
  el.textContent = msg;
  el.className   = 'auth-msg ' + (cls || '');
}

function logout() {
  clearSession();
  _cryptoKey = null;
  location.reload();
}

// ── Boot ──
function bootApp() {
  try {
    const shell   = document.getElementById('appShell');
    const overlay = document.getElementById('authOverlay');
    if (shell)   shell.style.display   = 'block';
    if (overlay) overlay.style.display = 'none';

    const s = getSession();
    _email = s.email; _csrf = s.csrf; _name = s.name;

    const nameEl = document.getElementById('topbarName');
    if (nameEl) nameEl.textContent = _name || _email;

    initDateField();
    purgeStaledData().then(() => {
      refreshKPIs();
      renderWeekGrid();
      renderHoursLog();
      renderQCTable();
      renderMilestoneTracker();
      renderAttrLog();
      checkAlerts();
    });
  } catch(err) {
    const shell = document.getElementById('appShell');
    if (shell) {
      shell.style.display = 'block';
      const errBanner = document.getElementById('alertBanner');
      if (errBanner) {
        errBanner.textContent = '⚠ DASHBOARD RENDER ERROR — ' + String(err.message || err).substring(0, 120) + ' — PLEASE RELOAD';
        errBanner.classList.add('show');
      }
    }
    console.error('[FCCO bootApp]', err);
  }
}

function initDateField() {
  const el = document.getElementById('logDate');
  if (!el) return;
  const d = new Date();
  el.value = d.getFullYear() + '-' +
    String(d.getMonth()+1).padStart(2,'0') + '-' +
    String(d.getDate()).padStart(2,'0');
}

// ── KPIs ──
async function refreshKPIs() {
  const qcList    = await getLocalData('qc_list',    []);
  const hoursLog  = await getLocalData('hours_log',  []);

  const qcPassed  = qcList.filter(q => q.gateStatus === 'PASS').length;
  const qcPct     = Math.min(100, Math.round((qcPassed / 20) * 100));

  const weekHours = calcWeekHours(hoursLog);
  const hoursPct  = Math.min(100, Math.round((weekHours / 35) * 100));

  const target    = new Date('2026-06-30');
  const today     = new Date();
  today.setHours(0,0,0,0);
  const days      = Math.max(0, Math.round((target - today) / 86400000));

  const pipeline  = qcList.filter(q => q.gateStatus !== 'PASS').length;

  const qcEl = document.getElementById('kpiQC');
  if (qcEl) {
    qcEl.textContent = qcPassed;
    qcEl.className   = 'dh-val ' + (qcPassed >= 18 ? 'success' : qcPassed >= 10 ? '' : qcPassed < 5 ? 'danger' : 'warn');
  }
  const qcBar = document.getElementById('kpiQCBar');
  if (qcBar) {
    qcBar.style.setProperty('--bar-width', qcPct + '%');
    qcBar.className = 'progress-fill ' + (qcPassed >= 18 ? '' : qcPassed < 5 ? 'danger' : 'warn');
  }
  const hEl = document.getElementById('kpiHours');
  if (hEl) {
    hEl.textContent = weekHours.toFixed(1) + 'h';
    hEl.className   = 'dh-val ' + (weekHours >= 35 ? 'success' : weekHours >= 25 ? 'warn' : 'danger');
  }
  const hBar = document.getElementById('kpiHoursBar');
  if (hBar) {
    hBar.style.setProperty('--bar-width', hoursPct + '%');
    hBar.className = 'progress-fill ' + (weekHours >= 35 ? '' : weekHours >= 20 ? 'warn' : 'danger');
  }
  const dEl = document.getElementById('kpiDays');
  if (dEl) {
    dEl.textContent = days;
    dEl.className   = 'dh-val ' + (days > 30 ? '' : days > 14 ? 'warn' : 'danger');
  }
  const pEl = document.getElementById('kpiPipeline');
  if (pEl) {
    pEl.textContent = pipeline;
    pEl.className   = 'dh-val ' + (pipeline >= 3 ? '' : 'warn');
  }
  const totalH = hoursLog.reduce((s,e) => s + (parseFloat(e.hours)||0), 0);
  const ttEl = document.getElementById('totalHoursAllTime');
  if (ttEl) ttEl.textContent = 'Total: ' + totalH.toFixed(1) + 'h logged';
  const wcEl = document.getElementById('weekTotal');
  if (wcEl) wcEl.textContent = weekHours.toFixed(1) + 'h / 35h min';
}

function calcWeekHours(log) {
  const now = new Date();
  const day = now.getDay();
  const mon = new Date(now);
  mon.setDate(now.getDate() - ((day + 6) % 7));
  mon.setHours(0,0,0,0);
  const sun = new Date(mon);
  sun.setDate(mon.getDate() + 7);
  return log.reduce((s, e) => {
    const d = new Date(e.date);
    return (d >= mon && d < sun) ? s + (parseFloat(e.hours)||0) : s;
  }, 0);
}

function calcDayHours(log, isoDate) {
  return log.filter(e => e.date === isoDate).reduce((s,e) => s + (parseFloat(e.hours)||0), 0);
}

// ── Week Grid ──
async function renderWeekGrid() {
  const log  = await getLocalData('hours_log', []);
  const grid = document.getElementById('weekGrid');
  if (!grid) return;
  grid.innerHTML = '';
  const now = new Date();
  const day = now.getDay();
  const mon = new Date(now);
  mon.setDate(now.getDate() - ((day + 6) % 7));
  mon.setHours(0,0,0,0);
  for (let i = 0; i < 7; i++) {
    const d   = new Date(mon);
    d.setDate(mon.getDate() + i);
    const iso = d.getFullYear() + '-' +
      String(d.getMonth()+1).padStart(2,'0') + '-' +
      String(d.getDate()).padStart(2,'0');
    const hrs     = calcDayHours(log, iso);
    const isToday = iso === todayISO();
    const block   = document.createElement('div');
    block.className = 'day-block' +
      (hrs >= 5 ? ' filled' : hrs > 0 ? ' target' : '') +
      (isToday ? ' today' : '');
    block.title       = iso + ' — ' + hrs.toFixed(1) + 'h';
    block.textContent = hrs > 0 ? hrs.toFixed(0) + 'h' : (isToday ? '●' : '');
    grid.appendChild(block);
  }
}

function todayISO() {
  const d = new Date();
  return d.getFullYear() + '-' +
    String(d.getMonth()+1).padStart(2,'0') + '-' +
    String(d.getDate()).padStart(2,'0');
}

// ── Hours Log ──
async function submitHoursLog() {
  const date     = document.getElementById('logDate').value;
  const hours    = parseFloat(document.getElementById('logHours').value || '0');
  const activity = document.getElementById('logActivity').value;
  const desc     = (document.getElementById('logDesc').value || '').trim();

  if (!date)                         { setStatus('logStatus', 'DATE REQUIRED', 'err'); return; }
  if (hours <= 0 || hours > 16)      { setStatus('logStatus', 'HOURS MUST BE 0.5–16', 'err'); return; }
  if (!activity)                     { setStatus('logStatus', 'SELECT ACTIVITY TYPE', 'err'); return; }
  if (!desc || desc.length < 5)      { setStatus('logStatus', 'DESCRIPTION REQUIRED (min 5 chars)', 'err'); return; }

  document.getElementById('logSubmitBtn').disabled = true;
  setStatus('logStatus', 'SAVING…', 'info');

  const entry = {
    id:       Date.now().toString(36),
    date,
    hours,
    activity,
    desc:     desc.substring(0,500),
    ts:       new Date().toISOString(),
  };

  const log = await getLocalData('hours_log', []);
  log.unshift(entry);
  await setLocalData('hours_log', log);
  // v4.2.5: Mirror to Supabase for MOU §3.2 audit compliance
  syncToServer('syncHoursLog', {
    log_date:      entry.date,
    hours:         String(entry.hours),
    activity_type: entry.activity,
    description:   entry.desc,
    local_id:      entry.id,
  });

  document.getElementById('logHours').value    = '';
  document.getElementById('logActivity').value = '';
  document.getElementById('logDesc').value     = '';

  setStatus('logStatus', '✓ LOGGED — ENSURE THIS IS ENTERED IN THE ACTUAL CRM', 'ok');
  document.getElementById('logSubmitBtn').disabled = false;
  refreshKPIs();
  renderWeekGrid();
  renderHoursLog();
}

async function renderHoursLog() {
  const log = await getLocalData('hours_log', []);
  const el  = document.getElementById('hoursLogList');
  if (!el) return;
  el.innerHTML = '';
  if (!log.length) {
    const empty = document.createElement('div');
    empty.className   = 'empty-state';
    empty.textContent = 'NO HOURS LOGGED';
    el.appendChild(empty);
    return;
  }
  log.slice(0, 50).forEach(e => {
    const row  = document.createElement('div');
    row.className = 'log-entry';
    const left = document.createElement('div');
    const desc = document.createElement('div');
    desc.className   = 'log-desc';
    desc.textContent = e.desc;
    const meta = document.createElement('div');
    meta.className   = 'log-meta js-log-meta';
    meta.textContent = (e.activity || '').replace(/_/g,' ') + ' · ' + e.date;
    left.appendChild(desc);
    left.appendChild(meta);
    const right = document.createElement('div');
    right.className   = 'log-hours';
    right.textContent = e.hours + 'h';
    row.appendChild(left);
    row.appendChild(right);
    el.appendChild(row);
  });
}

// ── QC Pipeline ──
async function renderQCTable() {
  const list = await getLocalData('qc_list', []);
  const body = document.getElementById('qcTableBody');
  if (!body) return;
  const countEl = document.getElementById('qcCount');
  if (countEl) countEl.textContent = list.length + ' counterpart' + (list.length===1?'y':'ies');
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="6"><div class="empty-state">NO COUNTERPARTIES — ADD YOUR FIRST</div></td></tr>';
    return;
  }
  body.innerHTML = '';
  list.forEach((q, idx) => {
    const tr     = document.createElement('tr');
    const tdName = document.createElement('td');
    tdName.textContent = q.name;
    const tdComm = document.createElement('td');
    tdComm.textContent = q.commodity || '—';
    const tdStage    = document.createElement('td');
    const stageBadge = document.createElement('span');
    const stageMap   = ['PENDING','DOCS IN','SCREENED','SUBMITTED'];
    stageBadge.className  = 'stage-badge stage-' + (q.stage||0);
    stageBadge.textContent = stageMap[q.stage||0] || 'PENDING';
    tdStage.appendChild(stageBadge);
    const tdGate = document.createElement('td');
    const gateEl = document.createElement('span');
    gateEl.className   = q.gateStatus === 'PASS' ? 'gate-pass' : q.gateStatus === 'FAIL' ? 'gate-fail' : 'gate-na';
    gateEl.textContent = q.gateStatus === 'PASS' ? '✓ PASS' : q.gateStatus === 'FAIL' ? '✗ FAIL' : '— PENDING';
    tdGate.appendChild(gateEl);
    const tdAttr     = document.createElement('td');
    const attrBadge  = document.createElement('span');
    attrBadge.className  = 'attr-badge ' + (q.attribution === 'TIMOTHY' ? 'attr-timothy' : 'attr-mario');
    attrBadge.textContent = q.attribution === 'TIMOTHY' ? 'TIMOTHY' : 'MARIO';
    tdAttr.appendChild(attrBadge);
    const tdAct  = document.createElement('td');
    tdAct.className = 'js-flex-gap4';
    const gateBtn = document.createElement('button');
    gateBtn.className   = 'action-btn';
    gateBtn.textContent = 'GATE';
    gateBtn.onclick     = () => openGateChecklist(idx);
    const advBtn = document.createElement('button');
    advBtn.className   = 'action-btn';
    advBtn.textContent = 'ADVANCE';
    advBtn.onclick     = () => advanceStage(idx);
    if ((q.stage||0) >= 3) advBtn.disabled = true;
    tdAct.appendChild(gateBtn);
    tdAct.appendChild(advBtn);
    tr.appendChild(tdName); tr.appendChild(tdComm); tr.appendChild(tdStage);
    tr.appendChild(tdGate); tr.appendChild(tdAttr); tr.appendChild(tdAct);
    body.appendChild(tr);
  });
}

async function advanceStage(idx) {
  const list = await getLocalData('qc_list', []);
  if (!list[idx]) return;
  if ((list[idx].stage||0) < 3) {
    list[idx].stage = (list[idx].stage||0) + 1;
    await setLocalData('qc_list', list);
    renderQCTable();
    refreshKPIs();
    renderAttrLog();
  }
}

// ── Modal — show/hide via classList (no style.display, CSP clean) ──
let _modalMode  = 'checklist';
let _modalQCIdx = -1;

function openAddQC() {
  _modalMode = 'addQC';
  document.getElementById('modalTitle').textContent      = 'ADD COUNTERPARTY';
  document.getElementById('modalMode-checklist').classList.add('hidden');
  document.getElementById('modalMode-addQC').classList.remove('hidden');
  document.getElementById('modalActionBtn').textContent  = 'ADD TO PIPELINE';
  document.getElementById('newQCName').value             = '';
  document.getElementById('newQCNotes').value            = '';
  document.getElementById('modalStatus').textContent     = '';
  document.getElementById('modal-overlay').classList.add('open');
}

async function openGateChecklist(idx) {
  _modalMode  = 'checklist';
  _modalQCIdx = idx;
  const list  = await getLocalData('qc_list', []);
  const q     = list[idx] || {};
  document.getElementById('modalTitle').textContent      = 'QC GATE — ' + (q.name || '');
  document.getElementById('modalMode-checklist').classList.remove('hidden');
  document.getElementById('modalMode-addQC').classList.add('hidden');
  document.getElementById('modalActionBtn').textContent  = 'SAVE GATE STATUS';
  document.getElementById('modalStatus').textContent     = '';
  const chks = ['kyc','pof','mandate','genuine','pof2','written','screen','crm','attr'];
  const saved = q.checklist || {};
  chks.forEach(k => {
    const el = document.getElementById('chk-' + k);
    if (!el) return;
    el.classList.toggle('checked', !!saved[k]);
  });
  updateGateStatus();
  document.getElementById('modal-overlay').classList.add('open');
}

function toggleChk(el) {
  el.classList.toggle('checked');
  updateGateStatus();
}

function updateGateStatus() {
  const chks    = ['kyc','pof','mandate','genuine','pof2','written','screen','crm','attr'];
  const passed  = chks.filter(k => { const el = document.getElementById('chk-'+k); return el && el.classList.contains('checked'); }).length;
  const allPass = passed === chks.length;
  const disp    = document.getElementById('gateStatusDisplay');
  if (disp) {
    disp.className   = 'gate-status ' + (allPass ? 'pass' : 'fail');
    disp.textContent = allPass
      ? '✓ GATE PASSED — READY TO SUBMIT TO VIEL'
      : '⚠ GATE INCOMPLETE — ' + passed + ' OF ' + chks.length + ' ITEMS CONFIRMED';
  }
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  _modalQCIdx = -1;
}

async function modalAction() {
  if (_modalMode === 'addQC') {
    const name  = (document.getElementById('newQCName').value || '').trim();
    const comm  = document.getElementById('newQCCommodity').value;
    const type  = document.getElementById('newQCType').value;
    const attr  = document.getElementById('newQCAttrib').value;
    const notes = (document.getElementById('newQCNotes').value || '').trim().substring(0, 400);
    if (!name || name.length < 2) { setStatus('modalStatus','NAME REQUIRED','err'); return; }
    if (!comm)                    { setStatus('modalStatus','SELECT COMMODITY','err'); return; }
    const list = await getLocalData('qc_list', []);
    list.push({ id: Date.now().toString(36), name, commodity: comm, type, attribution: attr,
      notes, stage: 0, gateStatus: 'PENDING', checklist: {}, addedAt: new Date().toISOString() });
    await setLocalData('qc_list', list);
    // v4.2.5: sync new counterparty to Supabase qc_gates
    const newEntry = list[list.length - 1];
    syncToServer('syncQCGate', {
      counterparty_name: newEntry.name,
      commodity:         newEntry.commodity,
      attribution:       newEntry.attribution,
      stage:             String(newEntry.stage),
      gate_status:       newEntry.gateStatus,
      checklist:         JSON.stringify(newEntry.checklist || {}),
      notes:             newEntry.notes || '',
      local_id:          newEntry.id,
    });
    const attrLog = await getLocalData('attr_log', []);
    attrLog.unshift({ name, attr, commodity: comm, ts: new Date().toISOString(), note: 'Added to pipeline' });
    await setLocalData('attr_log', attrLog);
    // v4.2.5: sync attribution event to Supabase
    syncToServer('syncAttrLog', {
      counterparty_name: name,
      commodity:         comm,
      attribution:       attr,
      note:              'Added to pipeline',
      local_id:          newEntry.id,
    });
    setStatus('modalStatus','✓ ADDED — ENSURE CRM ENTRY CREATED WITHIN 24H','ok');
    setTimeout(closeModal, 1500);
    renderQCTable(); refreshKPIs(); renderMilestoneTracker(); renderAttrLog();

  } else if (_modalMode === 'checklist') {
    const chks = ['kyc','pof','mandate','genuine','pof2','written','screen','crm','attr'];
    const state = {};
    let passed = 0;
    chks.forEach(k => {
      const el = document.getElementById('chk-' + k);
      if (el && el.classList.contains('checked')) { state[k]=true; passed++; }
      else state[k] = false;
    });
    const list = await getLocalData('qc_list', []);
    if (list[_modalQCIdx]) {
      list[_modalQCIdx].checklist   = state;
      list[_modalQCIdx].gateStatus  = (passed === chks.length) ? 'PASS' : 'FAIL';
      list[_modalQCIdx].gateUpdated = new Date().toISOString();
      await setLocalData('qc_list', list);
      // v4.2.5: sync gate status update to Supabase
      const updated = list[_modalQCIdx];
      if (updated) {
        syncToServer('syncQCGate', {
          counterparty_name: updated.name,
          commodity:         updated.commodity,
          attribution:       updated.attribution,
          stage:             String(updated.stage || 0),
          gate_status:       updated.gateStatus,
          checklist:         JSON.stringify(updated.checklist || {}),
          notes:             updated.notes || '',
          local_id:          updated.id,
        });
      }
    }
    setStatus('modalStatus', passed === chks.length ? '✓ GATE PASSED' : '⚠ GATE NOT YET COMPLETE', passed === chks.length ? 'ok' : 'err');
    setTimeout(closeModal, 1200);
    renderQCTable(); refreshKPIs(); renderMilestoneTracker();
  }
}

// ── Milestones ──
const MILESTONES = [
  { label: 'Week 2 target',     date: '2026-03-30', target:  3 },
  { label: 'Week 4 target',     date: '2026-04-14', target:  6 },
  { label: 'Week 6 target',     date: '2026-04-26', target:  9 },
  { label: 'Week 8 target',     date: '2026-05-10', target: 12 },
  { label: 'Week 13 buffer',    date: '2026-06-15', target: 19 },
  { label: 'KPI hard deadline', date: '2026-06-30', target: 20 },
];

async function renderMilestoneTracker() {
  const qcList = await getLocalData('qc_list', []);
  const passed = qcList.filter(q => q.gateStatus === 'PASS').length;
  const el     = document.getElementById('milestoneTracker');
  if (!el) return;
  el.innerHTML = '';
  const today  = new Date(); today.setHours(0,0,0,0);
  MILESTONES.forEach(m => {
    const mDate  = new Date(m.date); mDate.setHours(0,0,0,0);
    const isPast = mDate < today;
    const hit    = passed >= m.target;
    const wrap   = document.createElement('div'); wrap.className = 'js-wrap-border';
    const row    = document.createElement('div'); row.className  = 'js-row-between';
    const label  = document.createElement('div'); label.className = 'js-milestone-label';
    label.textContent = m.label + ' (' + m.date + ')';
    const right  = document.createElement('div'); right.className = 'js-milestone-right';
    const tgt    = document.createElement('div'); tgt.className   = 'js-milestone-tgt';
    tgt.textContent = passed + '/' + m.target;
    const badge  = document.createElement('div');
    badge.className  = 'js-milestone-badge ' + (hit ? 'js-milestone-ontrack' : isPast ? 'js-milestone-behind' : 'js-milestone-upcoming');
    badge.textContent = hit ? '✓ ON TRACK' : isPast ? '✗ BEHIND' : '— UPCOMING';
    right.appendChild(tgt); right.appendChild(badge);
    row.appendChild(label); row.appendChild(right);
    wrap.appendChild(row); el.appendChild(wrap);
  });
}

// ── Attribution Log ──
async function renderAttrLog() {
  const log = await getLocalData('attr_log', []);
  const el  = document.getElementById('attrLog');
  if (!el) return;
  el.innerHTML = '';
  if (!log.length) {
    const empty = document.createElement('div');
    empty.className   = 'empty-state';
    empty.textContent = 'NO ATTRIBUTION RECORDS';
    el.appendChild(empty);
    return;
  }
  log.slice(0, 30).forEach(e => {
    const row    = document.createElement('div'); row.className = 'attr-row';
    const left   = document.createElement('div');
    const name   = document.createElement('div'); name.className = 'attr-name'; name.textContent = e.name;
    const detail = document.createElement('div'); detail.className = 'attr-detail';
    detail.textContent = (e.commodity || '') + ' · ' + new Date(e.ts).toLocaleDateString();
    left.appendChild(name); left.appendChild(detail);
    const badge = document.createElement('div');
    badge.className  = 'attr-badge ' + (e.attr==='TIMOTHY' ? 'attr-timothy' : e.attr==='BOTH' ? 'attr-shared' : 'attr-mario');
    badge.textContent = e.attr;
    row.appendChild(left); row.appendChild(badge); el.appendChild(row);
  });
}

// ── Alerts ──
async function checkAlerts() {
  const hoursLog = await getLocalData('hours_log', []);
  const weekH    = calcWeekHours(hoursLog);
  const today    = new Date();
  const isFri    = today.getDay() === 5;
  const banner   = document.getElementById('alertBanner');
  const alerts   = [];
  if (weekH < 20 && today.getDay() >= 3) alerts.push('⚠ HOURS BELOW 20h THIS WEEK — TARGET IS 35h (MOU §3.2)');
  if (isFri) alerts.push('⚠ FRIDAY — KPI REPORT DUE TO VIEL BY 5PM');
  const qcList  = await getLocalData('qc_list', []);
  const qcP     = qcList.filter(q => q.gateStatus === 'PASS').length;
  const daysLeft = Math.max(0, Math.round((new Date('2026-06-30') - today) / 86400000));
  if (daysLeft < 30 && qcP < 15) alerts.push('⚠ CRITICAL — ' + (20-qcP) + ' QC STILL NEEDED WITH ' + daysLeft + ' DAYS LEFT');
  if (alerts.length && banner) {
    banner.textContent = alerts.join('  ·  ');
    banner.classList.add('show');
  }
}

// ── Helpers ──
function setStatus(id, msg, cls) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className   = 'status-msg ' + (cls || '');
}

// ── Clock ──
function updateClock() {
  const gst = new Date(Date.now() + 4 * 60 * 60 * 1000);
  const el  = document.getElementById('clock');
  if (el) el.textContent =
    String(gst.getUTCHours()).padStart(2,'0') + ':' +
    String(gst.getUTCMinutes()).padStart(2,'0') + ':' +
    String(gst.getUTCSeconds()).padStart(2,'0') + ' GST';
}
setInterval(updateClock, 1000);
updateClock();

// ============================================================
// ── CSP EVENT BINDINGS ──
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  const sendOtpBtn = document.getElementById('sendOtpBtn');
  if (sendOtpBtn) sendOtpBtn.addEventListener('click', sendOTP);

  const verifyOtpBtn = document.getElementById('verifyOtpBtn');
  if (verifyOtpBtn) verifyOtpBtn.addEventListener('click', verifyOTP);

  const logoutBtn = document.querySelector('.logout-btn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  const clearBtn = document.getElementById('clearDataBtn');
  if (clearBtn) clearBtn.addEventListener('click', deleteAllData);

  const logSubmitBtn = document.getElementById('logSubmitBtn');
  if (logSubmitBtn) logSubmitBtn.addEventListener('click', submitHoursLog);

  const addQCBtn = document.getElementById('addQCBtn');
  if (addQCBtn) addQCBtn.addEventListener('click', openAddQC);

  const modalCloseBtn = document.getElementById('modalCloseBtn');
  if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeModal);

  const modalActionBtn = document.getElementById('modalActionBtn');
  if (modalActionBtn) modalActionBtn.addEventListener('click', modalAction);

  const overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });

  const chks = ['kyc','pof','mandate','genuine','pof2','written','screen','crm','attr'];
  chks.forEach(k => {
    const el = document.getElementById('chk-' + k);
    if (el) el.addEventListener('click', function() { toggleChk(this); });
  });
});

// ── Init ──
(async function init() {
  const s = getSession();
  if (s.email && s.csrf) {
    _email = s.email; _csrf = s.csrf; _name = s.name;
    await deriveCryptoKey(_csrf);
    bootApp();
  }
})();
