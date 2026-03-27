'use strict';
// ============================================================
// ROMI NEXUS — MARIO DASHBOARD v1.0
// SECURITY: OWASP A03 — all untrusted data via textContent
//           OWASP A07 — session token in sessionStorage
//           OWASP A01 — server-side auth; role enforced backend
//           Input sanitization before any API submission
// ============================================================

const API_URL = 'rominexus-gateway-v6.vacorp-inquiries.workers.dev';

function sanitize(str) {
  return String(str || '')
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
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

function getLocalData(key, def) {
  try {
    const raw = localStorage.getItem('rn_mario_' + key);
    return raw ? JSON.parse(raw) : def;
  } catch(_) { return def; }
}
function setLocalData(key, val) {
  try { localStorage.setItem('rn_mario_' + key, JSON.stringify(val)); } catch(_) {}
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
  el.textContent = msg;
  el.className   = 'auth-msg ' + (cls || '');
}

function logout() {
  clearSession();
  location.reload();
}

// ── Boot ──
function bootApp() {
  document.getElementById('authOverlay').style.display = 'none';
  document.getElementById('appShell').style.display    = 'block';
  const s = getSession();
  _email = s.email; _csrf = s.csrf; _name = s.name;
  const nameEl = document.getElementById('topbarName');
  nameEl.textContent = _name || _email;
  initDateField();
  refreshKPIs();
  renderWeekGrid();
  renderHoursLog();
  renderQCTable();
  renderMilestoneTracker();
  renderAttrLog();
  checkAlerts();
}

function initDateField() {
  const d = new Date();
  const iso = d.getFullYear() + '-' +
    String(d.getMonth()+1).padStart(2,'0') + '-' +
    String(d.getDate()).padStart(2,'0');
  document.getElementById('logDate').value = iso;
}

// ── KPIs ──
function refreshKPIs() {
  const qcList    = getLocalData('qc_list',    []);
  const hoursLog  = getLocalData('hours_log',  []);

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
  qcEl.textContent = qcPassed;
  qcEl.className   = 'dh-val ' + (qcPassed >= 18 ? 'success' : qcPassed >= 10 ? '' : qcPassed < 5 ? 'danger' : 'warn');

  const qcBar = document.getElementById('kpiQCBar');
  qcBar.style.width     = qcPct + '%';
  qcBar.className       = 'progress-fill ' + (qcPassed >= 18 ? '' : qcPassed < 5 ? 'danger' : 'warn');

  const hEl = document.getElementById('kpiHours');
  hEl.textContent = weekHours.toFixed(1) + 'h';
  hEl.className   = 'dh-val ' + (weekHours >= 35 ? 'success' : weekHours >= 25 ? 'warn' : 'danger');

  const hBar = document.getElementById('kpiHoursBar');
  hBar.style.width  = hoursPct + '%';
  hBar.className    = 'progress-fill ' + (weekHours >= 35 ? '' : weekHours >= 20 ? 'warn' : 'danger');

  const dEl = document.getElementById('kpiDays');
  dEl.textContent = days;
  dEl.className   = 'dh-val ' + (days > 30 ? '' : days > 14 ? 'warn' : 'danger');

  const pEl = document.getElementById('kpiPipeline');
  pEl.textContent = pipeline;
  pEl.className   = 'dh-val ' + (pipeline >= 3 ? '' : 'warn');

  const totalH = hoursLog.reduce((s,e) => s + (parseFloat(e.hours)||0), 0);
  const ttEl = document.getElementById('totalHoursAllTime');
  ttEl.textContent = 'Total: ' + totalH.toFixed(1) + 'h logged';

  const wcEl = document.getElementById('weekTotal');
  wcEl.textContent = weekHours.toFixed(1) + 'h / 35h min';
}

function calcWeekHours(log) {
  const now   = new Date();
  const day   = now.getDay();
  const mon   = new Date(now);
  mon.setDate(now.getDate() - ((day + 6) % 7));
  mon.setHours(0,0,0,0);
  const sun   = new Date(mon);
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
function renderWeekGrid() {
  const log   = getLocalData('hours_log', []);
  const grid  = document.getElementById('weekGrid');
  grid.innerHTML = '';
  const now  = new Date();
  const day  = now.getDay();
  const mon  = new Date(now);
  mon.setDate(now.getDate() - ((day + 6) % 7));
  mon.setHours(0,0,0,0);

  for (let i = 0; i < 7; i++) {
    const d   = new Date(mon);
    d.setDate(mon.getDate() + i);
    const iso = d.getFullYear() + '-' +
      String(d.getMonth()+1).padStart(2,'0') + '-' +
      String(d.getDate()).padStart(2,'0');
    const hrs = calcDayHours(log, iso);
    const isToday = iso === todayISO();
    const block   = document.createElement('div');
    block.className = 'day-block' +
      (hrs >= 5 ? ' filled' : hrs > 0 ? ' target' : '') +
      (isToday   ? ' today'  : '');
    block.title = iso + ' — ' + hrs.toFixed(1) + 'h';
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

  if (!date) { setStatus('logStatus', 'DATE REQUIRED', 'err'); return; }
  if (hours <= 0 || hours > 16) { setStatus('logStatus', 'HOURS MUST BE 0.5–16', 'err'); return; }
  if (!activity) { setStatus('logStatus', 'SELECT ACTIVITY TYPE', 'err'); return; }
  if (!desc || desc.length < 5) { setStatus('logStatus', 'DESCRIPTION REQUIRED (min 5 chars)', 'err'); return; }

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

  const log = getLocalData('hours_log', []);
  log.unshift(entry);
  setLocalData('hours_log', log);

  document.getElementById('logHours').value   = '';
  document.getElementById('logActivity').value = '';
  document.getElementById('logDesc').value    = '';

  setStatus('logStatus', '✓ LOGGED — ENSURE THIS IS ENTERED IN THE ACTUAL CRM', 'ok');
  document.getElementById('logSubmitBtn').disabled = false;
  refreshKPIs();
  renderWeekGrid();
  renderHoursLog();
}

function renderHoursLog() {
  const log = getLocalData('hours_log', []);
  const el  = document.getElementById('hoursLogList');
  el.innerHTML = '';
  if (!log.length) {
    const empty = document.createElement('div');
    empty.className   = 'empty-state';
    empty.textContent = 'NO HOURS LOGGED';
    el.appendChild(empty);
    return;
  }
  log.slice(0, 50).forEach(e => {
    const row = document.createElement('div');
    row.className = 'log-entry';

    const left = document.createElement('div');
    const desc = document.createElement('div');
    desc.className   = 'log-desc';
    desc.textContent = e.desc;
    const meta = document.createElement('div');
    meta.className   = 'log-meta';
    meta.style.color = 'var(--text-muted)';
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
function renderQCTable() {
  const list = getLocalData('qc_list', []);
  const body = document.getElementById('qcTableBody');
  const countEl = document.getElementById('qcCount');
  countEl.textContent = list.length + ' counterpart' + (list.length===1?'y':'ies');

  if (!list.length) {
    body.innerHTML = '<tr><td colspan="6"><div class="empty-state">NO COUNTERPARTIES — ADD YOUR FIRST</div></td></tr>';
    return;
  }
  body.innerHTML = '';
  list.forEach((q, idx) => {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.textContent = q.name;

    const tdComm = document.createElement('td');
    tdComm.textContent = q.commodity || '—';

    const tdStage = document.createElement('td');
    const stageBadge = document.createElement('span');
    const stageMap = ['PENDING','DOCS IN','SCREENED','SUBMITTED'];
    stageBadge.className = 'stage-badge stage-' + (q.stage||0);
    stageBadge.textContent = stageMap[q.stage||0] || 'PENDING';
    tdStage.appendChild(stageBadge);

    const tdGate = document.createElement('td');
    const gateEl = document.createElement('span');
    gateEl.className   = q.gateStatus === 'PASS' ? 'gate-pass' : q.gateStatus === 'FAIL' ? 'gate-fail' : 'gate-na';
    gateEl.textContent = q.gateStatus === 'PASS' ? '✓ PASS' : q.gateStatus === 'FAIL' ? '✗ FAIL' : '— PENDING';
    tdGate.appendChild(gateEl);

    const tdAttr = document.createElement('td');
    const attrBadge = document.createElement('span');
    attrBadge.className = 'attr-badge ' + (q.attribution === 'TIMOTHY' ? 'attr-timothy' : 'attr-mario');
    attrBadge.textContent = q.attribution === 'TIMOTHY' ? 'TIMOTHY' : 'MARIO';
    tdAttr.appendChild(attrBadge);

    const tdAct = document.createElement('td');
    tdAct.style.display = 'flex';
    tdAct.style.gap     = '4px';

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

    tr.appendChild(tdName);
    tr.appendChild(tdComm);
    tr.appendChild(tdStage);
    tr.appendChild(tdGate);
    tr.appendChild(tdAttr);
    tr.appendChild(tdAct);
    body.appendChild(tr);
  });
}

function advanceStage(idx) {
  const list = getLocalData('qc_list', []);
  if (!list[idx]) return;
  if ((list[idx].stage||0) < 3) {
    list[idx].stage = (list[idx].stage||0) + 1;
    setLocalData('qc_list', list);
    renderQCTable();
    refreshKPIs();
    renderAttrLog();
  }
}

// ── Add QC Modal ──
let _modalMode = 'checklist';
let _modalQCIdx = -1;

function openAddQC() {
  _modalMode = 'addQC';
  document.getElementById('modalTitle').textContent = 'ADD COUNTERPARTY';
  document.getElementById('modalMode-checklist').style.display = 'none';
  document.getElementById('modalMode-addQC').style.display     = 'block';
  document.getElementById('modalActionBtn').textContent = 'ADD TO PIPELINE';
  document.getElementById('newQCName').value     = '';
  document.getElementById('newQCNotes').value    = '';
  document.getElementById('modalStatus').textContent = '';
  document.getElementById('modal-overlay').classList.add('open');
}

function openGateChecklist(idx) {
  _modalMode  = 'checklist';
  _modalQCIdx = idx;
  const list  = getLocalData('qc_list', []);
  const q     = list[idx] || {};
  document.getElementById('modalTitle').textContent = 'QC GATE — ' + (q.name || '');
  document.getElementById('modalMode-checklist').style.display = 'block';
  document.getElementById('modalMode-addQC').style.display     = 'none';
  document.getElementById('modalActionBtn').textContent = 'SAVE GATE STATUS';
  document.getElementById('modalStatus').textContent = '';

  const chks = ['kyc','pof','mandate','genuine','pof2','written','screen','crm','attr'];
  const saved = q.checklist || {};
  chks.forEach(k => {
    const el = document.getElementById('chk-' + k);
    if (!el) return;
    if (saved[k]) { el.classList.add('checked'); }
    else { el.classList.remove('checked'); }
  });
  updateGateStatus();
  document.getElementById('modal-overlay').classList.add('open');
}

function toggleChk(el, id) {
  el.classList.toggle('checked');
  updateGateStatus();
}

function updateGateStatus() {
  const chks   = ['kyc','pof','mandate','genuine','pof2','written','screen','crm','attr'];
  const passed = chks.filter(k => {
    const el = document.getElementById('chk-' + k);
    return el && el.classList.contains('checked');
  }).length;
  const total  = chks.length;
  const allPass = passed === total;
  const disp   = document.getElementById('gateStatusDisplay');
  disp.className = 'gate-status ' + (allPass ? 'pass' : 'fail');
  disp.textContent = allPass
    ? '✓ GATE PASSED — READY TO SUBMIT TO VIEL'
    : '⚠ GATE INCOMPLETE — ' + passed + ' OF ' + total + ' ITEMS CONFIRMED';
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  _modalQCIdx = -1;
}

function modalAction() {
  if (_modalMode === 'addQC') {
    const name   = (document.getElementById('newQCName').value || '').trim();
    const comm   = document.getElementById('newQCCommodity').value;
    const type   = document.getElementById('newQCType').value;
    const attr   = document.getElementById('newQCAttrib').value;
    const notes  = (document.getElementById('newQCNotes').value || '').trim().substring(0, 400);

    if (!name || name.length < 2) { setStatus('modalStatus','NAME REQUIRED','err'); return; }
    if (!comm) { setStatus('modalStatus','SELECT COMMODITY','err'); return; }

    const list  = getLocalData('qc_list', []);
    list.push({
      id:          Date.now().toString(36),
      name,
      commodity:   comm,
      type,
      attribution: attr,
      notes,
      stage:       0,
      gateStatus:  'PENDING',
      checklist:   {},
      addedAt:     new Date().toISOString(),
    });
    setLocalData('qc_list', list);

    const attrLog = getLocalData('attr_log', []);
    attrLog.unshift({
      name,
      attr,
      commodity: comm,
      ts: new Date().toISOString(),
      note: 'Added to pipeline',
    });
    setLocalData('attr_log', attrLog);

    setStatus('modalStatus','✓ ADDED — ENSURE CRM ENTRY CREATED WITHIN 24H','ok');
    setTimeout(closeModal, 1500);
    renderQCTable();
    refreshKPIs();
    renderMilestoneTracker();
    renderAttrLog();

  } else if (_modalMode === 'checklist') {
    const chks  = ['kyc','pof','mandate','genuine','pof2','written','screen','crm','attr'];
    const state = {};
    let   passed = 0;
    chks.forEach(k => {
      const el = document.getElementById('chk-' + k);
      if (el && el.classList.contains('checked')) { state[k]=true; passed++; }
      else state[k]=false;
    });
    const list = getLocalData('qc_list', []);
    if (list[_modalQCIdx]) {
      list[_modalQCIdx].checklist   = state;
      list[_modalQCIdx].gateStatus  = (passed === chks.length) ? 'PASS' : 'FAIL';
      list[_modalQCIdx].gateUpdated = new Date().toISOString();
      setLocalData('qc_list', list);
    }
    setStatus('modalStatus', passed === chks.length ? '✓ GATE PASSED' : '⚠ GATE NOT YET COMPLETE', passed === chks.length ? 'ok' : 'err');
    setTimeout(closeModal, 1200);
    renderQCTable();
    refreshKPIs();
    renderMilestoneTracker();
  }
}

// ── Milestones ──
const MILESTONES = [
  { label: 'Week 2 target',   date: '2026-03-30', target:  3 },
  { label: 'Week 4 target',   date: '2026-04-14', target:  6 },
  { label: 'Week 6 target',   date: '2026-04-26', target:  9 },
  { label: 'Week 8 target',   date: '2026-05-10', target: 12 },
  { label: 'Week 13 buffer',  date: '2026-06-15', target: 19 },
  { label: 'KPI hard deadline', date: '2026-06-30', target: 20 },
];

function renderMilestoneTracker() {
  const qcList = getLocalData('qc_list', []);
  const passed = qcList.filter(q => q.gateStatus === 'PASS').length;
  const el     = document.getElementById('milestoneTracker');
  el.innerHTML = '';
  const today  = new Date(); today.setHours(0,0,0,0);

  MILESTONES.forEach(m => {
    const mDate  = new Date(m.date);
    mDate.setHours(0,0,0,0);
    const isPast = mDate < today;
    const hit    = passed >= m.target;
    const row    = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;';

    const label = document.createElement('div');
    label.style.cssText = 'font-size:9px;color:var(--text-muted);letter-spacing:.5px;';
    label.textContent   = m.label + ' (' + m.date + ')';

    const right = document.createElement('div');
    right.style.cssText = 'display:flex;align-items:center;gap:8px;';

    const tgt = document.createElement('div');
    tgt.style.cssText = 'font-size:9px;color:var(--text-muted);';
    tgt.textContent   = passed + '/' + m.target;

    const badge = document.createElement('div');
    badge.style.cssText = 'font-size:8px;padding:2px 8px;font-weight:700;letter-spacing:1px;text-transform:uppercase;';
    if (hit) {
      badge.style.background = '#001a0d';
      badge.style.color      = 'var(--success)';
      badge.textContent      = '✓ ON TRACK';
    } else if (isPast) {
      badge.style.background = '#1a0007';
      badge.style.color      = 'var(--danger)';
      badge.textContent      = '✗ BEHIND';
    } else {
      badge.style.background = '#0d0a00';
      badge.style.color      = 'var(--warning)';
      badge.textContent      = '— UPCOMING';
    }
    right.appendChild(tgt);
    right.appendChild(badge);
    row.appendChild(label);
    row.appendChild(right);

    const wrap = document.createElement('div');
    wrap.style.cssText = 'padding:6px 0;border-bottom:1px solid var(--border);';
    wrap.appendChild(row);
    el.appendChild(wrap);
  });
}

// ── Attribution Log ──
function renderAttrLog() {
  const log = getLocalData('attr_log', []);
  const el  = document.getElementById('attrLog');
  el.innerHTML = '';
  if (!log.length) {
    const empty = document.createElement('div');
    empty.className   = 'empty-state';
    empty.textContent = 'NO ATTRIBUTION RECORDS';
    el.appendChild(empty);
    return;
  }
  log.slice(0, 30).forEach(e => {
    const row  = document.createElement('div');
    row.className = 'attr-row';

    const left = document.createElement('div');
    const name = document.createElement('div');
    name.className   = 'attr-name';
    name.textContent = e.name;
    const detail = document.createElement('div');
    detail.className   = 'attr-detail';
    detail.textContent = (e.commodity || '') + ' · ' + new Date(e.ts).toLocaleDateString();
    left.appendChild(name);
    left.appendChild(detail);

    const badge = document.createElement('div');
    badge.className = 'attr-badge ' + (e.attr==='TIMOTHY' ? 'attr-timothy' : e.attr==='BOTH' ? 'attr-shared' : 'attr-mario');
    badge.textContent = e.attr;

    row.appendChild(left);
    row.appendChild(badge);
    el.appendChild(row);
  });
}

// ── Alerts ──
function checkAlerts() {
  const hoursLog = getLocalData('hours_log', []);
  const weekH    = calcWeekHours(hoursLog);
  const today    = new Date();
  const isFri    = today.getDay() === 5;
  const banner   = document.getElementById('alertBanner');

  const alerts   = [];
  if (weekH < 20 && today.getDay() >= 3) alerts.push('⚠ HOURS BELOW 20h THIS WEEK — TARGET IS 35h (MOU §3.2)');
  if (isFri) alerts.push('⚠ FRIDAY — KPI REPORT DUE TO VIEL BY 5PM');

  const qcList  = getLocalData('qc_list', []);
  const passed  = qcList.filter(q => q.gateStatus === 'PASS').length;
  const daysLeft= Math.max(0, Math.round((new Date('2026-06-30') - today) / 86400000));
  if (daysLeft < 30 && passed < 15) alerts.push('⚠ CRITICAL — ' + (20-passed) + ' QC STILL NEEDED WITH ' + daysLeft + ' DAYS LEFT');

  if (alerts.length) {
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
// ── CSP EVENT BINDINGS (F-06 / OWASP HARDENING) ──
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  // 1. Auth Bindings
  const sendOtpBtn = document.getElementById('sendOtpBtn');
  if (sendOtpBtn) sendOtpBtn.addEventListener('click', sendOTP);

  const verifyOtpBtn = document.getElementById('verifyOtpBtn');
  if (verifyOtpBtn) verifyOtpBtn.addEventListener('click', verifyOTP);

  // 2. Global Bindings
  const logoutBtn = document.querySelector('.logout-btn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  const logSubmitBtn = document.getElementById('logSubmitBtn');
  if (logSubmitBtn) logSubmitBtn.addEventListener('click', submitHoursLog);

  // Find the "+ ADD" QC Pipeline button dynamically
  const actionBtns = document.querySelectorAll('.action-btn');
  actionBtns.forEach(btn => {
    if (btn.textContent.trim() === '+ ADD') {
      btn.addEventListener('click', openAddQC);
    }
  });

  // 3. Modal Bindings
  const modalCloseBtn = document.querySelector('.modal-close');
  if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeModal);

  const modalActionBtn = document.getElementById('modalActionBtn');
  if (modalActionBtn) modalActionBtn.addEventListener('click', modalAction);

  // 4. Modal overlay close — moved inside DOMContentLoaded to guarantee DOM is ready
  // Fix: was at module scope, which throws if script loads before DOM is parsed
  const overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });

  // 5. QC Quality Gate Checkboxes
  const chks = ['kyc', 'pof', 'mandate', 'genuine', 'pof2', 'written', 'screen', 'crm', 'attr'];
  chks.forEach(k => {
    const el = document.getElementById('chk-' + k);
    if (el) {
      el.addEventListener('click', function() {
        toggleChk(this, 'chk-' + k);
      });
    }
  });
});

// ── Init ──
(function init() {
  const s = getSession();
  if (s.email && s.csrf) {
    _email = s.email; _csrf = s.csrf; _name = s.name;
    bootApp();
  }
})();
