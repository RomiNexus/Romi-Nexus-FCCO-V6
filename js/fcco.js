'use strict';
// ============================================================
// ROMI NEXUS — TIMOTHY DASHBOARD (FCCO) v6.2
// Fixes:
// - Modal ID bug: 'modalMode-intro' → 'modalMode-addIntro' (matching HTML)
// - Form field ID bug: 'newEntityName' → 'newName' (matching HTML)
// - Q1 slot tracker: renderQSlots() added and called from bootApp()
// - KPI report: all form fields (hours, contacts, intros, recognitions, notes) included
// - calculateTotalCommission(): extracted for reuse
// ============================================================

const API_URL = 'https://rominexus-proxy.vacorp-inquiries.workers.dev';

function sanitize(str) {
  return String(str || '')
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
}

// ── Session ──
let _email = '';
let _csrf  = '';
let _name  = '';

function getSession() {
  try {
    return {
      email: sessionStorage.getItem('rn_tim_email') || '',
      csrf:  sessionStorage.getItem('rn_tim_csrf')  || '',
      name:  sessionStorage.getItem('rn_tim_name')  || '',
    };
  } catch(_) { return {email:'',csrf:'',name:''}; }
}
function setSession(email, csrf, name) {
  try {
    sessionStorage.setItem('rn_tim_email', email);
    sessionStorage.setItem('rn_tim_csrf',  csrf);
    sessionStorage.setItem('rn_tim_name',  name);
  } catch(_) {}
}
function clearSession() {
  try {
    sessionStorage.removeItem('rn_tim_email');
    sessionStorage.removeItem('rn_tim_csrf');
    sessionStorage.removeItem('rn_tim_name');
  } catch(_) {}
}

function getLocalData(key, def) {
  try {
    const raw = localStorage.getItem('rn_tim_' + key);
    return raw ? JSON.parse(raw) : def;
  } catch(_) { return def; }
}
function setLocalData(key, val) {
  try { localStorage.setItem('rn_tim_' + key, JSON.stringify(val)); } catch(_) {}
}

// ── Auth ──
async function sendOTP() {
  const emailInput = document.getElementById('authEmail');
  if(!emailInput) return;
  const email = (emailInput.value || '').trim().toLowerCase();
  if (!email || !/^[^\s@]{1,64}@[^\s@]{1,255}$/.test(email)) {
    setAuthMsg(1, 'VALID EMAIL REQUIRED', 'err'); return;
  }
  setAuthMsg(1, 'SENDING…', 'info');
  const btn = document.getElementById('sendOtpBtn');
  if(btn) btn.disabled = true;
  try {
    const res  = await fetch(API_URL, {
      method:  'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body:    'action=sendOTP&email=' + encodeURIComponent(email)
    });
    const data = await res.json();
    if (data.error) {
      setAuthMsg(1, String(data.error).substring(0,80), 'err');
      if(btn) btn.disabled=false; return;
    }
    _email = email;
    document.getElementById('stepEmail').classList.remove('active');
    document.getElementById('stepOTP').classList.add('active');
    setAuthMsg(2, 'CODE SENT — CHECK YOUR EMAIL', 'ok');
  } catch(e) {
    setAuthMsg(1, 'NETWORK ERROR — RETRY', 'err');
    if(btn) btn.disabled=false;
  }
}

async function verifyOTP() {
  const otpInput = document.getElementById('authOTP');
  if(!otpInput) return;
  const otp = (otpInput.value || '').trim();
  if (!/^\d{6}$/.test(otp)) { setAuthMsg(2, 'ENTER 6-DIGIT CODE', 'err'); return; }
  setAuthMsg(2, 'VERIFYING…', 'info');
  const btn = document.getElementById('verifyOtpBtn');
  if(btn) btn.disabled = true;
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
      if(btn) btn.disabled = false;
      return;
    }
    _csrf = csrf;
    _name = data.name || _email;
    setSession(_email, _csrf, _name);
    bootApp();
  } catch(e) {
    setAuthMsg(2, 'NETWORK ERROR — RETRY', 'err');
    if(btn) btn.disabled = false;
  }
}

function generateCSRF() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

function setAuthMsg(step, msg, cls) {
  const el = document.getElementById('authMsg' + step);
  if(el) { el.textContent = msg; el.className = 'auth-msg ' + (cls || ''); }
}

function logout() {
  clearSession();
  location.reload();
}

// ── Boot ──
function bootApp() {
  const authOverlay = document.getElementById('authOverlay');
  const appShell    = document.getElementById('appShell');
  if(authOverlay) authOverlay.style.display = 'none';
  if(appShell)    appShell.style.display    = 'block';

  const s = getSession();
  _email = s.email; _csrf = s.csrf; _name = s.name;

  const topbarName = document.getElementById('topbarName');
  if(topbarName) topbarName.textContent = _name || _email;

  initDateField();
  refreshKPIs();
  renderIntroTable();
  renderQSlots();       // Bug fix: was never called
  renderTouchpointMonitor();
  checkAlerts();
}

function initDateField() {
  const d   = new Date();
  const fri = new Date(d);
  const diff = (5 - d.getDay() + 7) % 7;
  fri.setDate(d.getDate() + (diff === 0 ? 7 : diff));
  const rptDate = document.getElementById('rptDate');
  if(rptDate) rptDate.value = isoDate(fri);
}

function isoDate(d) {
  return d.getFullYear() + '-' +
    String(d.getMonth()+1).padStart(2,'0') + '-' +
    String(d.getDate()).padStart(2,'0');
}

// ── KPIs ──
function calculateTotalCommission(list) {
  return list.reduce((s, i) => {
    const deal   = parseFloat(i.dealVal || 0);
    const romi   = deal * 0.02;   // 2.0% institutional fee
    const myComm = romi * 0.18;   // 18% FCCO commission
    return s + myComm;
  }, 0);
}

function refreshKPIs() {
  const list       = getLocalData('intros', []);
  const recognised = list.filter(i => i.recognised).length;
  const total      = list.length;
  const introPct   = Math.min(100, Math.round((total / 3) * 100));
  const recPct     = Math.min(100, Math.round((recognised / 3) * 100));

  const iEl = document.getElementById('kpiIntros');
  if(iEl) iEl.textContent = total;
  const iBar = document.getElementById('kpiIntrosBar');
  if(iBar) iBar.style.width = introPct + '%';

  const rEl = document.getElementById('kpiRecognised');
  if(rEl) rEl.textContent = recognised;
  const rBar = document.getElementById('kpiRecBar');
  if(rBar) rBar.style.width = recPct + '%';

  const totalComm = calculateTotalCommission(list);
  const cEl = document.getElementById('kpiCommission');
  if(cEl) cEl.textContent = totalComm > 0 ? '$' + Math.round(totalComm).toLocaleString() : '$0';

  const target  = new Date('2026-06-15');
  const today   = new Date(); today.setHours(0,0,0,0);
  const days    = Math.max(0, Math.round((target - today) / 86400000));
  const dEl     = document.getElementById('kpiDays');
  if(dEl) dEl.textContent = days;

  const iCount = document.getElementById('introCount');
  if(iCount) iCount.textContent = total + ' introduction' + (total===1?'':'s');
}

// ── Q1 Slot Tracker (Bug fix: was never rendered) ──
const Q1_TARGET = 3;

function renderQSlots() {
  const el = document.getElementById('qSlots');
  if (!el) return;
  const list       = getLocalData('intros', []);
  const recognised = list.filter(i => i.recognised);

  el.innerHTML = '';
  for (let i = 0; i < Q1_TARGET; i++) {
    const intro  = recognised[i] || null;
    const div    = document.createElement('div');
    div.className = 'q-slot ' + (intro ? 'filled' : 'empty');

    const num = document.createElement('div');
    num.className   = 'q-slot-num';
    num.textContent = String(i + 1);

    const name = document.createElement('div');
    name.className   = 'q-slot-name';
    name.textContent = intro ? intro.name : '— SLOT OPEN';

    const status = document.createElement('div');
    status.className   = 'q-slot-status';
    status.textContent = intro
      ? `${sanitize(intro.commodity || '')} · RECOGNISED ✓`
      : 'awaiting qualifying introduction';

    div.appendChild(num);
    div.appendChild(name);
    div.appendChild(status);
    el.appendChild(div);
  }
}

// ── Intro Table ──
function renderIntroTable() {
  const body = document.getElementById('introTableBody');
  if(!body) return;
  const list = getLocalData('intros', []);
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="7"><div style="text-align:center; padding:40px; color:var(--text-dim);">NO DATA — LOG YOUR FIRST INTRO</div></td></tr>';
    return;
  }
  body.innerHTML = '';
  list.forEach((intro, idx) => {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    const nameDiv = document.createElement('div');
    nameDiv.textContent = intro.name;
    const emailDiv = document.createElement('div');
    emailDiv.style.cssText = 'font-size:8px;color:var(--text-muted);';
    emailDiv.textContent = intro.contact || '';
    tdName.appendChild(nameDiv);
    if (intro.contact) tdName.appendChild(emailDiv);

    const tdComm = document.createElement('td');
    tdComm.textContent = intro.commodity || '—';

    const tdStatus = document.createElement('td');
    const sb = document.createElement('span');
    sb.className   = 'status-badge ' + (intro.recognised ? 'sb-recognised' : 'sb-pending');
    sb.textContent = intro.recognised ? 'RECOGNISED' : 'PENDING';
    tdStatus.appendChild(sb);

    const tdRec = document.createElement('td');
    tdRec.textContent = intro.recognised ? '✓ YES' : '⏳ PENDING';

    const tdTp = document.createElement('td');
    tdTp.textContent = intro.lastTouchpoint ? fmtDate(intro.lastTouchpoint) : '—';

    // Commission: 18% of Romi's 2% = 0.36% of deal value
    const tdC = document.createElement('td');
    const deal    = parseFloat(intro.dealVal || 0);
    const myComm  = deal * 0.02 * 0.18;
    tdC.textContent = deal > 0 ? '$' + Math.round(myComm).toLocaleString() : '—';

    const tdAct = document.createElement('td');
    const advBtn = document.createElement('button');
    advBtn.className   = 'action-btn';
    advBtn.textContent = intro.recognised ? 'ADVANCE' : 'MARK REC.';
    advBtn.onclick     = () => advanceIntro(idx);
    tdAct.appendChild(advBtn);

    tr.appendChild(tdName);
    tr.appendChild(tdComm);
    tr.appendChild(tdStatus);
    tr.appendChild(tdRec);
    tr.appendChild(tdTp);
    tr.appendChild(tdC);
    tr.appendChild(tdAct);
    body.appendChild(tr);
  });
}

function advanceIntro(idx) {
  const list = getLocalData('intros', []);
  if (!list[idx]) return;
  list[idx].recognised     = true;
  list[idx].lastTouchpoint = new Date().toISOString();
  setLocalData('intros', list);
  refreshKPIs();
  renderIntroTable();
  renderQSlots();         // Bug fix: update slot tracker when intro advances
  renderTouchpointMonitor();
}

// ── Touchpoint Monitor ──
function renderTouchpointMonitor() {
  const el = document.getElementById('touchpointList');
  if(!el) return;
  const list = getLocalData('intros', []);
  el.innerHTML = '';
  if (!list.length) {
    const empty = document.createElement('div');
    empty.style.cssText = 'padding:20px; text-align:center; color:var(--text-dim); font-size:9px;';
    empty.textContent = 'NO INTRODUCTIONS TO MONITOR';
    el.appendChild(empty);
    return;
  }
  const now    = Date.now();
  const SIX_MO = 6 * 30 * 24 * 60 * 60 * 1000;
  const THREE_MO = 3 * 30 * 24 * 60 * 60 * 1000;

  list.forEach((intro, idx) => {
    const lastTs  = intro.lastTouchpoint ? new Date(intro.lastTouchpoint).getTime() : new Date(intro.addedAt).getTime();
    const elapsed = now - lastTs;
    const isLapsed  = elapsed > SIX_MO;
    const isWarning = elapsed > THREE_MO && !isLapsed;

    const row = document.createElement('div');
    row.className = 'tp-row';

    const left = document.createElement('div');
    const nameEl = document.createElement('div');
    nameEl.className   = 'tp-name';
    nameEl.textContent = intro.name;
    const detail = document.createElement('div');
    detail.className   = 'tp-detail';
    detail.textContent = `Last touchpoint: ${fmtDate(intro.lastTouchpoint || intro.addedAt)}`;
    left.appendChild(nameEl);
    left.appendChild(detail);

    const right = document.createElement('div');
    right.className = 'tp-date ' + (isLapsed ? 'tp-overdue' : isWarning ? '' : 'tp-ok');
    right.textContent = isLapsed ? '⚠ LAPSED' : isWarning ? '⚡ DUE SOON' : '✓ CURRENT';

    const tpBtn = document.createElement('button');
    tpBtn.className   = 'action-btn';
    tpBtn.textContent = 'LOG TOUCHPOINT';
    tpBtn.style.marginLeft = '8px';
    tpBtn.onclick = () => openModal('touchpoint', idx);

    right.appendChild(tpBtn);
    row.appendChild(left);
    row.appendChild(right);
    el.appendChild(row);
  });
}

// ── Commission Calculator ──
function updateCalc() {
  const dealVal  = document.getElementById('calcInput');
  const typeEl   = document.getElementById('calcType');
  if(!dealVal) return;
  const deal     = parseFloat(dealVal.value || '0');
  const isStd    = typeEl ? typeEl.value === 'standard' : false;

  const romiDisplay   = document.getElementById('calcRomi');
  const yoursDisplay  = document.getElementById('calcYours');
  const onboardDisp   = document.getElementById('calcOnboard');
  const totalDisp     = document.getElementById('calcTotal');

  if (isNaN(deal) || deal <= 0) {
    [romiDisplay, yoursDisplay, onboardDisp, totalDisp].forEach(el => { if(el) el.textContent = '—'; });
    return;
  }
  const romi          = deal * 0.02;     // 2.0% institutional fee
  const myComm        = romi * 0.18;     // 18% FCCO
  const onboardFee    = isStd ? 2000 * 0.18 : 0;
  const total         = myComm + onboardFee;

  if(romiDisplay)  romiDisplay.textContent  = '$' + romi.toLocaleString('en-US', {minimumFractionDigits:2,maximumFractionDigits:2});
  if(yoursDisplay) yoursDisplay.textContent = '$' + myComm.toLocaleString('en-US', {minimumFractionDigits:2,maximumFractionDigits:2});
  if(onboardDisp)  onboardDisp.textContent  = isStd ? '$' + onboardFee.toLocaleString('en-US', {minimumFractionDigits:2,maximumFractionDigits:2}) : '—';
  if(totalDisp)    totalDisp.textContent    = '$' + total.toLocaleString('en-US', {minimumFractionDigits:2,maximumFractionDigits:2});
}

// ── KPI Report (Bug fix: include all form fields) ──
function submitKPIReport() {
  const dateEl   = document.getElementById('rptDate');
  if(!dateEl) return;
  const date         = dateEl.value;
  const hours        = (document.getElementById('rptHours')?.value        || '').trim();
  const contacts     = (document.getElementById('rptContacts')?.value     || '').trim();
  const intros       = (document.getElementById('rptIntros')?.value       || '').trim();
  const recognitions = (document.getElementById('rptRecognitions')?.value || '').trim();
  const notes        = (document.getElementById('rptNotes')?.value        || '').trim();

  if (!date) { setStatus('rptStatus', 'WEEK ENDING DATE REQUIRED', 'err'); return; }

  const list = getLocalData('intros', []);
  const totalComm = calculateTotalCommission(list);

  // Bug fix: include all form fields in the report
  const reportLines = [
    '════════════════════════════════',
    'ROMI NEXUS — WEEKLY KPI REPORT',
    `FRACTIONAL CCO: ${_name || _email}`,
    '════════════════════════════════',
    '',
    `WEEK ENDING: ${date}`,
    `HOURS WORKED THIS WEEK: ${hours || '—'} hrs`,
    `OUTREACH CONTACTS: ${contacts || '—'}`,
    '',
    '── INTRODUCTIONS ──',
    `SUBMITTED TO VIEL THIS WEEK: ${intros || '—'}`,
    `VIEL RECOGNITION RECEIVED: ${recognitions || '—'}`,
    `TOTAL PIPELINE SIZE: ${list.length} introductions`,
    `TOTAL RECOGNISED: ${list.filter(i => i.recognised).length}`,
    '',
    '── FINANCIAL PIPELINE ──',
    `ESTIMATED COMMISSION PIPELINE: $${Math.round(totalComm).toLocaleString()}`,
    '',
    '── Q1 STATUS ──',
    `Q1 TARGET: 3 recognised introductions by 15 June 2026`,
    `CURRENT: ${list.filter(i => i.recognised).length}/3 recognised`,
    '',
    '── COMPLIANCE OBSERVATIONS ──',
    notes || '(No compliance observations this week.)',
    '',
    '════════════════════════════════',
    'END OF REPORT',
    '════════════════════════════════',
  ];

  const out = document.getElementById('rptOutput');
  const txt = document.getElementById('rptText');
  if(txt) txt.value = reportLines.join('\n');
  if(out) out.style.display = 'block';
  setStatus('rptStatus', '✓ DRAFT GENERATED — COPY AND SEND TO VIEL', 'ok');
}

// ── Modal Handlers ──
let _currentModalMode  = 'intro';
let _touchpointTargetIdx = -1;

function openModal(mode, touchpointIdx) {
  const overlay       = document.getElementById('modal-overlay');
  // Bug fix: element is 'modalMode-addIntro' not 'modalMode-intro'
  const introModeEl   = document.getElementById('modalMode-addIntro');
  const tpModeEl      = document.getElementById('modalMode-touchpoint');
  const title         = document.getElementById('modalTitle');
  const saveBtn       = document.getElementById('modalSaveBtn');
  const statusEl      = document.getElementById('modalStatus');

  if(introModeEl) introModeEl.style.display = 'none';
  if(tpModeEl)    tpModeEl.style.display    = 'none';
  if(statusEl)    statusEl.textContent      = '';

  _currentModalMode = mode;

  if (mode === 'intro') {
    if(title)     title.textContent     = 'LOG NEW INTRODUCTION';
    if(saveBtn)   saveBtn.textContent   = 'SAVE INTRODUCTION';
    if(introModeEl) introModeEl.style.display = 'block'; // Bug fix: was 'modalMode-intro'
    // Clear form fields
    ['newName','newCommodity','newType','newContact','newDealVal','newNotes',
     'chkEmailSent','chkRecognised','chkScreened','chkCRM'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      if (el.type === 'checkbox') el.checked = false;
      else el.value = '';
    });
  } else {
    _touchpointTargetIdx = touchpointIdx !== undefined ? touchpointIdx : -1;
    if(title)   title.textContent   = 'RECORD TOUCHPOINT';
    if(saveBtn) saveBtn.textContent = 'LOG TOUCHPOINT';
    if(tpModeEl) tpModeEl.style.display = 'block';
    populateEntitySelect();
    if (_touchpointTargetIdx >= 0) {
      const sel = document.getElementById('tpEntitySelect');
      if (sel) sel.value = String(_touchpointTargetIdx);
    }
  }

  if(overlay) overlay.classList.add('open');
}

function populateEntitySelect() {
  const list = getLocalData('intros', []);
  const sel  = document.getElementById('tpEntitySelect');
  if(!sel) return;
  sel.innerHTML = '';
  list.forEach((i, idx) => {
    const opt      = document.createElement('option');
    opt.value      = String(idx);
    opt.textContent = i.name + (i.commodity ? ` (${i.commodity})` : '');
    sel.appendChild(opt);
  });
}

function closeModal() {
  const overlay = document.getElementById('modal-overlay');
  if(overlay) overlay.classList.remove('open');
  _touchpointTargetIdx = -1;
}

function modalAction() {
  if (_currentModalMode === 'intro') {
    // Bug fix: form field ID is 'newName' not 'newEntityName'
    const name     = (document.getElementById('newName')?.value || '').trim();
    const comm     = (document.getElementById('newCommodity')?.value || '').trim();
    const type     = (document.getElementById('newType')?.value || 'BUYER').trim();
    const contact  = (document.getElementById('newContact')?.value || '').trim();
    const dealVal  = (document.getElementById('newDealVal')?.value || '').trim();
    const notes    = (document.getElementById('newNotes')?.value || '').trim().substring(0, 500);
    const emailSent    = document.getElementById('chkEmailSent')?.checked;
    const recognised   = document.getElementById('chkRecognised')?.checked;
    const screened     = document.getElementById('chkScreened')?.checked;
    const crmEntered   = document.getElementById('chkCRM')?.checked;

    if (!name || name.length < 2) { setStatus('modalStatus', 'COUNTERPARTY NAME REQUIRED', 'err'); return; }
    if (!comm) { setStatus('modalStatus', 'SELECT COMMODITY', 'err'); return; }
    if (!emailSent) { setStatus('modalStatus', 'CONFIRM: INTRO EMAIL SENT TO VIEL', 'err'); return; }
    if (!screened)  { setStatus('modalStatus', 'CONFIRM: SANCTIONS PRE-SCREENING COMPLETED', 'err'); return; }

    const list = getLocalData('intros', []);
    list.push({
      id:            Date.now().toString(36),
      name,
      commodity:     comm,
      type,
      contact,
      dealVal:       parseFloat(dealVal) || 0,
      notes,
      emailSent,
      recognised:    recognised || false,
      screened,
      crmEntered:    crmEntered || false,
      addedAt:       new Date().toISOString(),
      lastTouchpoint: new Date().toISOString(),
    });
    setLocalData('intros', list);

    setStatus('modalStatus', '✓ INTRODUCTION LOGGED — CREATE CRM ENTRY WITHIN 24H', 'ok');
    setTimeout(closeModal, 1500);
    refreshKPIs();
    renderIntroTable();
    renderQSlots();
    renderTouchpointMonitor();
    checkAlerts();

  } else {
    // Touchpoint mode
    const idxRaw = document.getElementById('tpEntitySelect')?.value;
    const idx    = parseInt(idxRaw || '0');
    const desc   = (document.getElementById('tpDesc')?.value || '').trim();

    if (!desc || desc.length < 3) { setStatus('modalStatus', 'TOUCHPOINT DESCRIPTION REQUIRED', 'err'); return; }

    const list = getLocalData('intros', []);
    if (list[idx]) {
      list[idx].lastTouchpoint = new Date().toISOString();
      if (!list[idx].touchpointLog) list[idx].touchpointLog = [];
      list[idx].touchpointLog.push({ ts: new Date().toISOString(), desc: desc.substring(0, 400) });
      setLocalData('intros', list);
      setStatus('modalStatus', '✓ TOUCHPOINT LOGGED — ATTRIBUTION PROTECTED', 'ok');
      setTimeout(closeModal, 1200);
      renderIntroTable();
      renderTouchpointMonitor();
    } else {
      setStatus('modalStatus', 'ERROR: ENTITY NOT FOUND', 'err');
    }
  }
}

// ── Alerts ──
function checkAlerts() {
  const list   = getLocalData('intros', []);
  const banner = document.getElementById('alertBanner');
  if (!banner) return;

  const alerts = [];
  const recognised = list.filter(i => i.recognised).length;

  if (list.length < Q1_TARGET) {
    alerts.push(`⚠ ${Q1_TARGET - list.length} MORE INTRODUCTIONS NEEDED FOR Q1 TARGET`);
  } else if (recognised < Q1_TARGET) {
    alerts.push(`⚠ ${Q1_TARGET - recognised} INTRODUCTIONS STILL AWAITING VIEL RECOGNITION`);
  }

  // Check for lapsed touchpoints
  const SIX_MO = 6 * 30 * 24 * 60 * 60 * 1000;
  const lapsed = list.filter(i => {
    const ts = i.lastTouchpoint ? new Date(i.lastTouchpoint).getTime() : new Date(i.addedAt).getTime();
    return Date.now() - ts > SIX_MO;
  });
  if (lapsed.length) {
    alerts.push(`⚠ ${lapsed.length} ATTRIBUTION(S) LAPSED — LOG TOUCHPOINT IMMEDIATELY`);
  }

  if (alerts.length) {
    banner.textContent = alerts.join('  ·  ');
    banner.classList.add('show');
  } else {
    banner.classList.remove('show');
  }
}

// ── Helpers ──
function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '—';
  return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0');
}

function setStatus(id, msg, cls) {
  const el = document.getElementById(id);
  if(el) { el.textContent = msg; el.className = 'status-msg ' + (cls || ''); }
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
// CSP EVENT BINDINGS
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  const sendOtpBtn = document.getElementById('sendOtpBtn');
  if (sendOtpBtn) sendOtpBtn.addEventListener('click', sendOTP);

  const verifyOtpBtn = document.getElementById('verifyOtpBtn');
  if (verifyOtpBtn) verifyOtpBtn.addEventListener('click', verifyOTP);

  // Commission calculator
  const calcInput = document.getElementById('calcInput');
  if (calcInput) calcInput.addEventListener('input', updateCalc);
  const calcType = document.getElementById('calcType');
  if (calcType) calcType.addEventListener('change', updateCalc);

  // Modals
  const logIntroBtn = document.getElementById('logIntroBtn');
  if (logIntroBtn) logIntroBtn.addEventListener('click', () => openModal('intro'));

  // Bug fix: 'logTPBtn' doesn't exist in HTML — touchpoint buttons are rendered dynamically
  // in renderTouchpointMonitor() with direct onclick handlers

  const modalCloseBtn = document.getElementById('modalCloseBtn');
  if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeModal);

  const modalSaveBtn = document.getElementById('modalSaveBtn');
  if (modalSaveBtn) modalSaveBtn.addEventListener('click', modalAction);

  const genRptBtn = document.getElementById('genRptBtn');
  if (genRptBtn) genRptBtn.addEventListener('click', submitKPIReport);

  const overlay = document.getElementById('modal-overlay');
  if(overlay) overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
});

// ── Init ──
(function init() {
  const s = getSession();
  const authOverlay = document.getElementById('authOverlay');
  const appShell    = document.getElementById('appShell');

  if (s.email && s.csrf) {
    _email = s.email; _csrf = s.csrf; _name = s.name;
    bootApp();
  } else {
    if (authOverlay) authOverlay.style.display = 'flex';
    if (appShell)    appShell.style.display    = 'none';
  }
})();
