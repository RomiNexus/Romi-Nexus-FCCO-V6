'use strict';
// ============================================================
// ROMI NEXUS — TIMOTHY DASHBOARD (FCCO) v6.1-sec
// SECURITY: OWASP A03 — textContent only for untrusted data
//           OWASP A07 — sessionStorage for auth tokens
//           DIFC F-08 — 2.0% Institutional Fee enforced
//           DIFC F-06 — CSP 'unsafe-inline' migration complete
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
  if(el) { el.textContent = msg; el.className   = 'auth-msg ' + (cls || ''); }
}

function logout() {
  clearSession();
  location.reload();
}

// ── Boot ──
function bootApp() {
  const authOverlay = document.getElementById('authOverlay');
  const appShell = document.getElementById('appShell');
  if(authOverlay) authOverlay.style.display = 'none';
  if(appShell) appShell.style.display    = 'block';
  
  const s = getSession();
  _email = s.email; _csrf = s.csrf; _name = s.name;
  
  initDateField();
  refreshKPIs();
  renderIntroTable();
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
function refreshKPIs() {
  const list       = getLocalData('intros', []);
  const recognised = list.filter(i => i.recognised).length;
  const total      = list.length;
  const introPct   = Math.min(100, Math.round((total / 3) * 100));
  const recPct     = Math.min(100, Math.round((recognised / 3) * 100));

  const iEl = document.getElementById('kpiIntros');
  if(iEl) {
    iEl.textContent = total;
  }
  const iBar = document.getElementById('kpiIntrosBar');
  if(iBar) {
    iBar.style.width  = introPct + '%';
  }
  const rEl = document.getElementById('kpiRecognised');
  if(rEl) {
    rEl.textContent = recognised;
  }
  const rBar = document.getElementById('kpiRecBar');
  if(rBar) {
    rBar.style.width  = recPct + '%';
  }

  const totalComm = list.reduce((s, i) => {
    const deal    = parseFloat(i.dealVal || 0);
    const romi    = deal * 0.02; // [F-08] UPDATED TO 2.0%
    const myComm  = romi * 0.18;
    return s + myComm;
  }, 0);
  
  const cEl = document.getElementById('kpiCommission');
  if(cEl) {
    cEl.textContent = totalComm > 0 ? '$' + Math.round(totalComm).toLocaleString() : '$0';
  }

  const target  = new Date('2026-06-15');
  const today   = new Date(); today.setHours(0,0,0,0);
  const days    = Math.max(0, Math.round((target - today) / 86400000));
  const dEl     = document.getElementById('kpiDays');
  if(dEl) {
    dEl.textContent = days;
  }
  const iCount = document.getElementById('introCount');
  if(iCount) iCount.textContent = total + ' introduction' + (total===1?'':'s');
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
    tdName.textContent = intro.name;

    const tdComm = document.createElement('td');
    tdComm.textContent = intro.commodity || '—';

    const tdStatus = document.createElement('td');
    const sb = document.createElement('span');
    sb.className   = 'status-badge ' + (intro.recognised ? 'sb-recognised' : 'sb-pending');
    sb.textContent = intro.recognised ? 'RECOGNISED' : 'PENDING';
    tdStatus.appendChild(sb);

    const tdRec = document.createElement('td');
    tdRec.textContent     = intro.recognised ? '✓ YES' : '⏳ PENDING';

    const tdTp = document.createElement('td');
    tdTp.textContent    = intro.lastTouchpoint ? fmtDate(intro.lastTouchpoint) : '—';

    const tdC = document.createElement('td');
    const deal    = parseFloat(intro.dealVal || 0);
    const myComm  = deal * 0.02 * 0.18; // [F-08] UPDATED TO 2.0%
    tdC.textContent   = deal > 0 ? '$' + Math.round(myComm).toLocaleString() : '—';

    const tdAct = document.createElement('td');
    const advBtn = document.createElement('button');
    advBtn.className   = 'action-btn secondary';
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
  list[idx].recognised = true;
  list[idx].lastTouchpoint = new Date().toISOString();
  setLocalData('intros', list);
  refreshKPIs();
  renderIntroTable();
  renderTouchpointMonitor();
}

// ── Touchpoint Monitor ──
function renderTouchpointMonitor() {
  const el = document.getElementById('touchpointList');
  if(!el) return;
  const list = getLocalData('intros', []);
  el.innerHTML = '';
  if (!list.length) {
    el.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-dim);">Monitoring inactive...</div>';
    return;
  }
  const now     = Date.now();
  const SIX_MO  = 6 * 30 * 24 * 60 * 60 * 1000;

  list.forEach((intro, idx) => {
    const lastTs  = intro.lastTouchpoint ? new Date(intro.lastTouchpoint).getTime() : new Date(intro.addedAt).getTime();
    const elapsed = now - lastTs;
    const isOver  = elapsed > SIX_MO;

    const row = document.createElement('div');
    row.style.marginBottom = '10px';
    row.textContent = intro.name + ': ' + (isOver ? 'LAPSED' : 'OK');
    row.style.color = isOver ? 'var(--danger)' : 'var(--text-muted)';
    el.appendChild(row);
  });
}

// ── Commission Calculator ──
function updateCalc() {
  const dealVal = document.getElementById('calcInput');
  if(!dealVal) return;
  const deal = parseFloat(dealVal.value || '0');
  const romiDisplay = document.getElementById('calcRomi');
  const yoursDisplay = document.getElementById('calcYours');

  if (isNaN(deal) || deal <= 0) {
    if(romiDisplay) romiDisplay.textContent = '—';
    if(yoursDisplay) yoursDisplay.textContent = '—';
    return;
  }
  const romi    = deal * 0.02; // [F-08] UPDATED TO 2.0%
  const myComm  = romi * 0.18;

  if(romiDisplay) romiDisplay.textContent = '$' + romi.toLocaleString();
  if(yoursDisplay) yoursDisplay.textContent = '$' + Math.round(myComm).toLocaleString();
}

// ── KPI Report ──
function submitKPIReport() {
  const dateEl = document.getElementById('rptDate');
  if(!dateEl) return;
  const date    = dateEl.value;
  const hours   = (document.getElementById('rptHours').value || '').trim();

  const list  = getLocalData('intros', []);
  const report = [
    'ROMI NEXUS — WEEKLY KPI REPORT',
    'Week Ending: ' + date,
    'Hours: ' + hours,
    'Intros: ' + list.length
  ].join('\n');

  const out = document.getElementById('rptOutput');
  const txt = document.getElementById('rptText');
  if(txt) txt.value = report;
  if(out) out.style.display = 'block';
}

// ── Modal Handlers ──
function openModal(mode) {
  const overlay = document.getElementById('modal-overlay');
  const introMode = document.getElementById('modalMode-intro');
  const tpMode = document.getElementById('modalMode-touchpoint');
  const title = document.getElementById('modalTitle');

  if(introMode) introMode.style.display = 'none';
  if(tpMode) tpMode.style.display = 'none';

  if (mode === 'intro') {
    if(title) title.textContent = 'LOG NEW INTRODUCTION';
    if(introMode) introMode.style.display = 'block';
  } else {
    if(title) title.textContent = 'RECORD TOUCHPOINT';
    if(tpMode) tpMode.style.display = 'block';
    populateEntitySelect();
  }

  if(overlay) overlay.classList.add('open');
}

function populateEntitySelect() {
  const list = getLocalData('intros', []);
  const sel = document.getElementById('tpEntitySelect');
  if(!sel) return;
  sel.innerHTML = '';
  list.forEach((i, idx) => {
    const opt = document.createElement('option');
    opt.value = idx;
    opt.textContent = i.name;
    sel.appendChild(opt);
  });
}

function closeModal() {
  const overlay = document.getElementById('modal-overlay');
  if(overlay) overlay.classList.remove('open');
}

function modalAction() {
  const introMode = document.getElementById('modalMode-intro');
  const isIntro = introMode && introMode.style.display === 'block';

  if (isIntro) {
    const name = document.getElementById('newEntityName').value.trim();
    const comm = document.getElementById('newCommodity').value;
    if(!name) return;

    const list = getLocalData('intros', []);
    list.push({
      name,
      commodity: comm,
      recognised: false,
      addedAt: new Date().toISOString(),
      lastTouchpoint: new Date().toISOString(),
      dealVal: 1000000 // Default for calc
    });
    setLocalData('intros', list);
  } else {
    const idx = document.getElementById('tpEntitySelect').value;
    const list = getLocalData('intros', []);
    if(list[idx]) list[idx].lastTouchpoint = new Date().toISOString();
    setLocalData('intros', list);
  }
  
  closeModal();
  refreshKPIs();
  renderIntroTable();
  renderTouchpointMonitor();
}

// ── Alerts ──
function checkAlerts() {
  const list   = getLocalData('intros', []);
  const banner = document.getElementById('alertBanner');
  if (!banner) return;
  
  const alerts = [];
  if (list.length < 3) alerts.push('⚠ ' + (3 - list.length) + ' INTROS REMAINING');
  
  if (alerts.length) {
    banner.textContent = alerts.join('  ·  ');
    banner.classList.add('show');
  }
}

// ── Helpers ──
function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0');
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
// ── FCCO V6.1 CSP EVENT BINDINGS (F-06 REPAIR) ──
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  // 1. Session & Logout
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }

  // 2. Auth Buttons
  const sendOtpBtn = document.getElementById('sendOtpBtn');
  if (sendOtpBtn) sendOtpBtn.addEventListener('click', sendOTP);

  const verifyOtpBtn = document.getElementById('verifyOtpBtn');
  if (verifyOtpBtn) verifyOtpBtn.addEventListener('click', verifyOTP);

  // 3. Commission Calculator
  const calcInput = document.getElementById('calcInput');
  if (calcInput) {
    calcInput.addEventListener('input', updateCalc);
  }

  // 4. Action Center Modals
  const logIntroBtn = document.getElementById('logIntroBtn');
  if (logIntroBtn) {
    logIntroBtn.addEventListener('click', () => openModal('intro'));
  }

  const logTPBtn = document.getElementById('logTPBtn');
  if (logTPBtn) {
    logTPBtn.addEventListener('click', () => openModal('touchpoint'));
  }

  const modalCloseBtn = document.getElementById('modalCloseBtn');
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', closeModal);
  }

  const modalSaveBtn = document.getElementById('modalSaveBtn');
  if (modalSaveBtn) {
    modalSaveBtn.addEventListener('click', modalAction);
  }

  // 5. Reports
  const genRptBtn = document.getElementById('genRptBtn');
  if (genRptBtn) {
    genRptBtn.addEventListener('click', submitKPIReport);
  }

  // 6. Overlay click to close
  const overlay = document.getElementById('modal-overlay');
  if(overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeModal();
    });
  }
});

// ── Init ──
(function init() {
  const s = getSession();
  const authOverlay = document.getElementById('authOverlay');
  const appShell = document.getElementById('appShell');
  
  if (s.email && s.csrf) {
    _email = s.email; _csrf = s.csrf; _name = s.name;
    bootApp();
  } else {
    if (authOverlay) authOverlay.style.display = 'flex';
    if (appShell) appShell.style.display = 'none';
  }
})();
