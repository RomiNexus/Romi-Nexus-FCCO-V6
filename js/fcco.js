'use strict';
// ============================================================
// ROMI NEXUS — TIMOTHY DASHBOARD v1.0 -> v6.1 (HYBRID)
// SECURITY: OWASP A03 — textContent only for untrusted data
//           OWASP A07 — sessionStorage for auth tokens
//           DIFC F-08 — 2.0% Commission standard enforced
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
  document.getElementById('sendOtpBtn').disabled = true;
  try {
    const res  = await fetch(API_URL, {
      method:  'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body:    'action=sendOTP&email=' + encodeURIComponent(email)
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
  const otpInput = document.getElementById('authOTP');
  if(!otpInput) return;
  const otp = (otpInput.value || '').trim();
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
  
  const topbarName = document.getElementById('topbarName');
  if(topbarName) topbarName.textContent = _name || _email;
  
  initDateField();
  refreshKPIs();
  renderIntroTable();
  renderQSlots();
  renderTouchpointMonitor();
  checkAlerts();
  
  // Also trigger V6.1 render if those elements exist
  if (typeof refreshV6Dashboard === 'function') refreshV6Dashboard();
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
    iEl.className   = 'dh-val ' + (total >= 3 ? 'success' : total >= 2 ? 'warn' : 'danger');
  }
  const iBar = document.getElementById('kpiIntrosBar');
  if(iBar) {
    iBar.style.width  = introPct + '%';
    iBar.className    = 'progress-fill ' + (total >= 3 ? 'success' : total >= 1 ? 'warn' : 'danger');
  }
  const rEl = document.getElementById('kpiRecognised');
  if(rEl) {
    rEl.textContent = recognised;
    rEl.className   = 'dh-val ' + (recognised >= 3 ? 'success' : recognised >= 2 ? '' : 'warn');
  }
  const rBar = document.getElementById('kpiRecBar');
  if(rBar) {
    rBar.style.width  = recPct + '%';
    rBar.className    = 'progress-fill ' + (recognised >= 3 ? 'success' : 'warn');
  }

  const totalComm = list.reduce((s, i) => {
    const deal    = parseFloat(i.dealVal || 0);
    const romi    = deal * 0.02; // F-08 FIX: Updated from 0.015 to 0.02
    const myComm  = romi * 0.18;
    const onboard = (i.principalType === 'standard') ? 360 : 0;
    return s + myComm + onboard;
  }, 0);
  
  const cEl = document.getElementById('kpiCommission');
  if(cEl) {
    cEl.textContent = totalComm > 0 ? '$' + Math.round(totalComm).toLocaleString() : '$0';
    cEl.className   = 'dh-val ' + (totalComm > 0 ? '' : 'warn');
  }

  const target  = new Date('2026-06-15');
  const today   = new Date(); today.setHours(0,0,0,0);
  const days    = Math.max(0, Math.round((target - today) / 86400000));
  const dEl     = document.getElementById('kpiDays');
  if(dEl) {
    dEl.textContent = days;
    dEl.className   = 'dh-val ' + (days > 30 ? '' : days > 14 ? 'warn' : 'danger');
  }
  const iCount = document.getElementById('introCount');
  if(iCount) iCount.textContent = total + ' introduction' + (total===1?'':'s');
}

// ── Q1 Slots ──
function renderQSlots() {
  const el = document.getElementById('qSlots');
  if(!el) return;
  const list  = getLocalData('intros', []);
  el.innerHTML = '';
  for (let i = 0; i < 3; i++) {
    const intro = list[i];
    const slot  = document.createElement('div');
    slot.className = 'q-slot ' + (intro ? 'filled' : 'empty');

    const num = document.createElement('div');
    num.className   = 'q-slot-num';
    num.textContent = i + 1;

    const name = document.createElement('div');
    name.className   = 'q-slot-name';
    name.textContent = intro ? intro.name : '— SLOT OPEN';

    const status = document.createElement('div');
    status.className = 'q-slot-status';
    if (intro) {
      status.textContent = intro.recognised ? '✓ RECOGNISED' : '⏳ PENDING RECOGNITION';
      status.style.color = intro.recognised ? 'var(--success)' : 'var(--warning)';
    }

    slot.appendChild(num);
    slot.appendChild(name);
    slot.appendChild(status);
    el.appendChild(slot);
  }
}

// ── Intro Table ──
function renderIntroTable() {
  const body = document.getElementById('introTableBody');
  if(!body) return;
  const list = getLocalData('intros', []);
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="7"><div class="empty-state">NO INTRODUCTIONS — LOG YOUR FIRST</div></td></tr>';
    return;
  }
  body.innerHTML = '';
  list.forEach((intro, idx) => {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    const nameDiv = document.createElement('div');
    nameDiv.textContent = intro.name;
    const contactDiv = document.createElement('div');
    contactDiv.style.cssText = 'font-size:9px;color:var(--text-muted);margin-top:2px;';
    contactDiv.textContent = intro.contact || '';
    tdName.appendChild(nameDiv);
    if (intro.contact) tdName.appendChild(contactDiv);

    const tdComm = document.createElement('td');
    tdComm.textContent = intro.commodity || '—';

    const tdStatus = document.createElement('td');
    const sb = document.createElement('span');
    const statusMap = {
      PENDING:    ['sb-pending',    'PENDING'],
      SUBMITTED:  ['sb-submitted',  'SUBMITTED'],
      RECOGNISED: ['sb-recognised', 'RECOGNISED'],
      ONBOARDING: ['sb-onboarding', 'ONBOARDING'],
      CLOSED:     ['sb-closed',     'CLOSED'],
      LAPSED:     ['sb-lapsed',     'LAPSED'],
    };
    const [cls, lbl] = statusMap[intro.status] || ['sb-pending', 'PENDING'];
    sb.className   = 'status-badge ' + cls;
    sb.textContent = lbl;
    tdStatus.appendChild(sb);

    const tdRec = document.createElement('td');
    const recEl = document.createElement('span');
    recEl.style.color     = intro.recognised ? 'var(--success)' : 'var(--warning)';
    recEl.textContent     = intro.recognised ? '✓ YES' : '⏳ PENDING';
    tdRec.appendChild(recEl);

    const tdTp = document.createElement('td');
    tdTp.style.color    = 'var(--text-muted)';
    tdTp.style.fontSize = '9px';
    tdTp.textContent    = intro.lastTouchpoint ? fmtDate(intro.lastTouchpoint) : '—';

    const tdC = document.createElement('td');
    const deal    = parseFloat(intro.dealVal || 0);
    const myComm  = deal * 0.02 * 0.18; // F-08 FIX: Updated from 0.015 to 0.02
    const onboard = intro.principalType === 'standard' ? 360 : 0;
    tdC.style.cssText = 'color:var(--gold);font-size:10px;';
    tdC.textContent   = deal > 0 ? '$' + Math.round(myComm + onboard).toLocaleString() : '—';

    const tdAct = document.createElement('td');
    tdAct.style.cssText = 'display:flex;gap:4px;';

    const tpBtn = document.createElement('button');
    tpBtn.className   = 'action-btn';
    tpBtn.textContent = 'TOUCHPOINT';
    tpBtn.onclick     = () => openTouchpoint(idx);

    const advBtn = document.createElement('button');
    advBtn.className   = 'action-btn';
    advBtn.textContent = intro.recognised ? 'ADVANCE' : 'MARK REC.';
    advBtn.onclick     = () => advanceIntro(idx);

    tdAct.appendChild(tpBtn);
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
  const intro = list[idx];
  if (!intro.recognised) {
    intro.recognised = true;
    intro.status = 'RECOGNISED';
    intro.recognisedAt = new Date().toISOString();
  } else {
    const stageOrder = ['PENDING','SUBMITTED','RECOGNISED','ONBOARDING','CLOSED'];
    const ci = stageOrder.indexOf(intro.status);
    if (ci >= 0 && ci < stageOrder.length - 1) {
      intro.status = stageOrder[ci + 1];
    }
  }
  intro.lastTouchpoint = new Date().toISOString();
  setLocalData('intros', list);
  refreshKPIs();
  renderIntroTable();
  renderQSlots();
  renderTouchpointMonitor();
  if (typeof refreshV6Dashboard === 'function') refreshV6Dashboard();
}

// ── Touchpoint Monitor ──
function renderTouchpointMonitor() {
  const el = document.getElementById('touchpointList');
  if(!el) return;
  const list = getLocalData('intros', []);
  el.innerHTML = '';
  if (!list.length) {
    const empty = document.createElement('div');
    empty.className   = 'empty-state';
    empty.textContent = 'NO INTRODUCTIONS TO MONITOR';
    el.appendChild(empty);
    return;
  }
  const now     = Date.now();
  const SIX_MO  = 6 * 30 * 24 * 60 * 60 * 1000;
  const WARN_MO = 4 * 30 * 24 * 60 * 60 * 1000;

  list.forEach((intro, idx) => {
    const lastTs  = intro.lastTouchpoint ? new Date(intro.lastTouchpoint).getTime() : new Date(intro.addedAt).getTime();
    const elapsed = now - lastTs;
    const isOver  = elapsed > SIX_MO;
    const isWarn  = elapsed > WARN_MO;

    const row = document.createElement('div');
    row.className = 'tp-row';

    const left = document.createElement('div');
    const name = document.createElement('div');
    name.className   = 'tp-name';
    name.textContent = intro.name;
    const detail = document.createElement('div');
    detail.className   = 'tp-detail';
    const daysElapsed  = Math.round(elapsed / 86400000);
    detail.textContent = 'Last contact: ' + fmtDate(intro.lastTouchpoint || intro.addedAt) + ' (' + daysElapsed + 'd ago)';
    detail.style.color = isOver ? 'var(--danger)' : isWarn ? 'var(--warning)' : 'var(--text-muted)';
    left.appendChild(name);
    left.appendChild(detail);

    const right = document.createElement('div');
    right.style.cssText = 'display:flex;flex-direction:column;align-items:flex-end;gap:4px;';
    const statusTp = document.createElement('div');
    statusTp.style.cssText = 'font-size:8px;font-weight:700;letter-spacing:1px;text-transform:uppercase;';
    statusTp.style.color   = isOver ? 'var(--danger)' : isWarn ? 'var(--warning)' : 'var(--success)';
    statusTp.textContent   = isOver ? 'LAPSED' : isWarn ? 'DUE SOON' : 'OK';

    const tpBtn = document.createElement('button');
    tpBtn.className   = 'action-btn';
    tpBtn.textContent = 'LOG';
    tpBtn.onclick     = () => openTouchpoint(idx);

    right.appendChild(statusTp);
    right.appendChild(tpBtn);
    row.appendChild(left);
    row.appendChild(right);
    el.appendChild(row);
  });
}

// ── Commission Calculator ──
function updateCalc() {
  const dealVal = document.getElementById('calcDealVal');
  if(!dealVal) return;
  const deal = parseFloat(dealVal.value || '0');
  const type = document.getElementById('calcType').value;
  if (isNaN(deal) || deal <= 0) {
    ['calcRomi','calcYours','calcOnboard','calcTotal'].forEach(id => {
      const el = document.getElementById(id);
      if(el) el.textContent = '—';
    });
    return;
  }
  const romi    = deal * 0.02; // F-08 FIX: Updated from 0.015 to 0.02
  const myComm  = romi * 0.18;
  const onboard = type === 'standard' ? 360 : 0;
  const total   = myComm + onboard;

  document.getElementById('calcRomi').textContent    = '$' + fmt(romi);
  document.getElementById('calcYours').textContent   = '$' + fmt(myComm);
  document.getElementById('calcOnboard').textContent = type === 'standard' ? '$360' : '$0 (Founding)';
  document.getElementById('calcTotal').textContent   = '$' + fmt(total);
}

function fmt(n) {
  return n.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2});
}

// ── KPI Report ──
function submitKPIReport() {
  const dateEl = document.getElementById('rptDate');
  if(!dateEl) return;
  const date    = dateEl.value;
  const hours   = (document.getElementById('rptHours').value || '').trim();
  const contacts= (document.getElementById('rptContacts').value || '').trim();
  const intros  = (document.getElementById('rptIntros').value || '').trim();
  const recs    = (document.getElementById('rptRecognitions').value || '').trim();
  const notes   = (document.getElementById('rptNotes').value || '').trim().substring(0, 500);

  if (!date) { setStatus('rptStatus', 'DATE REQUIRED', 'err'); return; }

  const list  = getLocalData('intros', []);
  const recCount = list.filter(i => i.recognised).length;
  const total    = list.length;

  const report = [
    'ROMI NEXUS — WEEKLY KPI REPORT',
    'From: Timothy Mawonera (Fractional CCO)',
    'To: Viel Bayani (CEO)',
    'Week Ending: ' + date,
    '',
    '--- ACTIVITY SUMMARY ---',
    'Hours logged this week: ' + (hours || 'N/A'),
    'Approved outreach contacts made: ' + (contacts || 'N/A'),
    'Introductions submitted to Viel: ' + (intros || 'N/A'),
    'Viel written recognition received: ' + (recs || 'N/A'),
    '',
    '--- Q1 PIPELINE STATUS ---',
    'Total introductions logged (dashboard): ' + total + ' / 3 required',
    'Recognised by Viel (dashboard): ' + recCount + ' / 3 required',
    '',
    '--- INTRODUCTION DETAILS ---',
    ...list.map((i, idx) => {
      return (idx+1) + '. ' + i.name +
        ' (' + (i.commodity||'—') + ', ' + (i.type||'—') + ')' +
        ' — Status: ' + i.status +
        ' | Recognised: ' + (i.recognised ? 'YES' : 'PENDING') +
        ' | Last touchpoint: ' + (i.lastTouchpoint ? fmtDate(i.lastTouchpoint) : 'N/A');
    }),
    '',
    '--- COMPLIANCE OBSERVATIONS ---',
    notes || 'None to report.',
    '',
    'FCCO §3.5 compliance: ' + (total >= 3 && recCount >= 3 ? 'ON TRACK' : 'ATTENTION REQUIRED'),
    '---',
  ].join('\n');

  const out = document.getElementById('rptOutput');
  const txt = document.getElementById('rptText');
  txt.value     = report;
  out.style.display = 'block';
  setStatus('rptStatus', '✓ DRAFT READY — COPY AND SEND TO VIEL BY 5PM', 'ok');
}

// ── Add Intro Modal ──
let _modalMode  = 'addIntro';
let _modalTPIdx = -1;

function openAddIntro() {
  _modalMode = 'addIntro';
  const mTitle = document.getElementById('modalTitle');
  if(mTitle) mTitle.textContent = 'LOG INTRODUCTION';
  
  const mIntro = document.getElementById('modalMode-addIntro');
  if(mIntro) mIntro.style.display = 'block';
  
  const mTP = document.getElementById('modalMode-touchpoint');
  if(mTP) mTP.style.display = 'none';
  
  const mBtn = document.getElementById('modalActionBtn');
  if(mBtn) mBtn.textContent = 'SAVE INTRODUCTION';
  
  ['newName','newContact','newNotes'].forEach(id => { 
    const el = document.getElementById(id);
    if(el) el.value=''; 
  });
  const nComm = document.getElementById('newCommodity');
  if(nComm) nComm.value = '';
  const nDeal = document.getElementById('newDealVal');
  if(nDeal) nDeal.value = '';
  
  ['chkEmailSent','chkRecognised','chkScreened','chkCRM'].forEach(id => {
    const el = document.getElementById(id);
    if(el) el.checked = false;
  });
  
  const mStat = document.getElementById('modalStatus');
  if(mStat) mStat.textContent = '';
  
  const over = document.getElementById('modal-overlay');
  if(over) over.classList.add('open');
}

function openTouchpoint(idx) {
  _modalMode  = 'touchpoint';
  _modalTPIdx = idx;
  const list  = getLocalData('intros', []);
  const intro = list[idx] || {};
  
  const mTitle = document.getElementById('modalTitle');
  if(mTitle) mTitle.textContent = 'LOG TOUCHPOINT — ' + (intro.name || '');
  
  const mIntro = document.getElementById('modalMode-addIntro');
  if(mIntro) mIntro.style.display = 'none';
  
  const mTP = document.getElementById('modalMode-touchpoint');
  if(mTP) mTP.style.display = 'block';
  
  const mBtn = document.getElementById('modalActionBtn');
  if(mBtn) mBtn.textContent = 'SAVE TOUCHPOINT';
  
  const tDesc = document.getElementById('tpDesc');
  if(tDesc) tDesc.value = '';
  
  const mStat = document.getElementById('modalStatus');
  if(mStat) mStat.textContent = '';
  
  const over = document.getElementById('modal-overlay');
  if(over) over.classList.add('open');
}

function closeModal() {
  const over = document.getElementById('modal-overlay');
  if(over) over.classList.remove('open');
  _modalTPIdx = -1;
}

function modalAction() {
  if (_modalMode === 'addIntro') {
    const nameEl = document.getElementById('newName');
    const name = nameEl ? (nameEl.value || '').trim() : '';
    const commEl = document.getElementById('newCommodity');
    const comm = commEl ? commEl.value : '';
    const typeEl = document.getElementById('newType');
    const type = typeEl ? typeEl.value : '';
    const dealEl = document.getElementById('newDealVal');
    const deal = dealEl ? dealEl.value : '';
    const contactEl = document.getElementById('newContact');
    const contact= contactEl ? (contactEl.value || '').trim().substring(0,100) : '';
    const notesEl = document.getElementById('newNotes');
    const notes  = notesEl ? (notesEl.value || '').trim().substring(0,500) : '';
    
    const emailSent = document.getElementById('chkEmailSent') ? document.getElementById('chkEmailSent').checked : false;
    const recvd     = document.getElementById('chkRecognised') ? document.getElementById('chkRecognised').checked : false;
    const screened  = document.getElementById('chkScreened') ? document.getElementById('chkScreened').checked : false;
    const crmDone   = document.getElementById('chkCRM') ? document.getElementById('chkCRM').checked : false;

    if (!name || name.length < 2) { setStatus('modalStatus','COUNTERPARTY NAME REQUIRED','err'); return; }
    if (!comm) { setStatus('modalStatus','SELECT COMMODITY','err'); return; }
    if (!screened) { setStatus('modalStatus','SANCTIONS PRE-SCREEN REQUIRED (FCCO §15.1)','err'); return; }
    if (!emailSent) { setStatus('modalStatus','INTRODUCTION EMAIL MUST BE SENT TO VIEL FIRST','err'); return; }
    if (!crmDone) { setStatus('modalStatus','CRM ENTRY MUST BE CREATED WITHIN 24 HOURS','err'); return; }

    const list = getLocalData('intros', []);
    if (list.length >= 20) { setStatus('modalStatus','PIPELINE FULL — ARCHIVE OLD ENTRIES FIRST','err'); return; }

    list.push({
      id:            Date.now().toString(36),
      name,
      commodity:     comm,
      type,
      dealVal:       parseFloat(deal)||0,
      principalType: 'founding',
      contact,
      notes,
      status:        recvd ? 'RECOGNISED' : 'SUBMITTED',
      recognised:    recvd,
      emailSent,
      screened,
      crmDone,
      addedAt:       new Date().toISOString(),
      lastTouchpoint: new Date().toISOString(),
      recognisedAt:  recvd ? new Date().toISOString() : null,
    });
    setLocalData('intros', list);

    setStatus('modalStatus','✓ LOGGED — ENSURE CRM ENTRY IS COMPLETE','ok');
    setTimeout(closeModal, 1400);
    refreshKPIs();
    renderIntroTable();
    renderQSlots();
    renderTouchpointMonitor();
    if (typeof refreshV6Dashboard === 'function') refreshV6Dashboard();

  } else if (_modalMode === 'touchpoint') {
    const descEl = document.getElementById('tpDesc');
    const desc = descEl ? (descEl.value || '').trim() : '';
    if (!desc || desc.length < 5) { setStatus('modalStatus','DESCRIPTION REQUIRED','err'); return; }

    const list = getLocalData('intros', []);
    if (list[_modalTPIdx]) {
      list[_modalTPIdx].lastTouchpoint = new Date().toISOString();
      setLocalData('intros', list);
    }
    setStatus('modalStatus','✓ TOUCHPOINT LOGGED','ok');
    setTimeout(closeModal, 1000);
    renderIntroTable();
    renderTouchpointMonitor();
    if (typeof refreshV6Dashboard === 'function') refreshV6Dashboard();
  }
}

// ── Alerts ──
function checkAlerts() {
  const list   = getLocalData('intros', []);
  const total  = list.length;
  const isFri  = new Date().getDay() === 5;
  const alerts = [];

  if (total === 0 && new Date() > new Date('2026-04-07')) {
    alerts.push('⚠ CRITICAL — NO INTRODUCTIONS LOGGED. SECTION 6D MAY APPLY.');
  }
  if (total < 3 && new Date() > new Date('2026-05-01')) {
    alerts.push('⚠ ' + (3-total) + ' INTRODUCTION(S) STILL NEEDED BEFORE JUNE 15');
  }
  if (isFri) {
    alerts.push('⚠ FRIDAY — KPI REPORT DUE TO VIEL BY 5PM');
  }

  const now    = Date.now();
  const SIX_MO = 6 * 30 * 24 * 60 * 60 * 1000;
  list.forEach(intro => {
    const lastTs  = intro.lastTouchpoint ? new Date(intro.lastTouchpoint).getTime() : new Date(intro.addedAt).getTime();
    if (now - lastTs > SIX_MO) {
      alerts.push('⚠ ATTRIBUTION LAPSE RISK: ' + intro.name + ' — 6 MONTHS WITHOUT DOCUMENTED TOUCHPOINT (FCCO §8.1)');
    }
  });

  const banner = document.getElementById('alertBanner');
  if (banner && alerts.length) {
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

function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '—';
  return d.getFullYear() + '-' +
    String(d.getMonth()+1).padStart(2,'0') + '-' +
    String(d.getDate()).padStart(2,'0');
}

// ── Clock ──
function updateClock() {
  const gst = new Date(Date.now() + 4 * 60 * 60 * 1000);
  const timeStr = String(gst.getUTCHours()).padStart(2,'0') + ':' +
                  String(gst.getUTCMinutes()).padStart(2,'0') + ':' +
                  String(gst.getUTCSeconds()).padStart(2,'0') + ' GST';
                  
  const v1Clock = document.getElementById('clock');
  const v6Clock = document.getElementById('dashClock'); // Added for V6.1 support
  
  if (v1Clock) v1Clock.textContent = timeStr;
  if (v6Clock) v6Clock.textContent = timeStr;
}
setInterval(updateClock, 1000);
updateClock();

// Close modal on overlay click
const modalOverlay = document.getElementById('modal-overlay');
if(modalOverlay) {
  modalOverlay.addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });
}

window.updateCalculator = function() {
  const inputEl = document.getElementById('calcInput');
  if (!inputEl) return;
  const inputVal = parseFloat(inputEl.value);
  const romiDisplay = document.getElementById('calcRomi');
  const yoursDisplay = document.getElementById('calcYours');

  if (isNaN(inputVal) || inputVal <= 0) {
    if(romiDisplay) romiDisplay.textContent = '—'; 
    if(yoursDisplay) yoursDisplay.textContent = '—'; 
    return;
  }

  const romiFee = inputVal * 0.02;       // F-08 FIX: 2.0% Institutional Fee
  const fccoCut = romiFee * 0.18;        // 18% FCCO Entitlement

  if(romiDisplay) romiDisplay.textContent = '$' + romiFee.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
  if(yoursDisplay) yoursDisplay.textContent = '$' + fccoCut.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
};

window.openModal = function(mode) {
  const modeIntro = document.getElementById('modalMode-intro');
  const modeTP = document.getElementById('modalMode-touchpoint');
  
  if(modeIntro) modeIntro.style.display = 'none';
  if(modeTP) modeTP.style.display = 'none';

  if (mode === 'intro') {
    const mTitle = document.getElementById('modalTitle');
    if(mTitle) mTitle.textContent = 'LOG NEW INTRODUCTION';
    if(modeIntro) modeIntro.style.display = 'block';
    
    // Clear inputs
    const elNames = ['newEntityName','newContactInfo','newNotes'];
    elNames.forEach(id => { if(document.getElementById(id)) document.getElementById(id).value=''; });
    if(document.getElementById('newCommodity')) document.getElementById('newCommodity').value = 'GOLD';
    if(document.getElementById('chkCRM')) document.getElementById('chkCRM').checked = false;
  } else if (mode === 'touchpoint') {
    const mTitle = document.getElementById('modalTitle');
    if(mTitle) mTitle.textContent = 'RECORD TOUCHPOINT';
    if(modeTP) modeTP.style.display = 'block';
    
    if(document.getElementById('tpDesc')) document.getElementById('tpDesc').value = '';
    populateV6Select();
  }
  const mod = document.getElementById('fccoModal');
  if(mod) mod.classList.add('open');
};

window.closeModalV6 = function() {
  const mod = document.getElementById('fccoModal');
  if(mod) mod.classList.remove('open');
};

// Bind to window to satisfy CSP HTML extraction
window.closeModal = window.closeModalV6; 

window.submitModalAction = function() {
  const list = getLocalData('intros', []);
  const modeIntro = document.getElementById('modalMode-intro');
  const mode = (modeIntro && modeIntro.style.display === 'block') ? 'intro' : 'touchpoint';

  if (mode === 'intro') {
    const nameEl = document.getElementById('newEntityName');
    if(!nameEl) return;
    const name = nameEl.value.trim();
    if(!name) { alert('Entity Name Required'); return; }

    list.push({
      id: Date.now().toString(36),
      name: name,
      contact: document.getElementById('newContactInfo') ? document.getElementById('newContactInfo').value.trim() : '',
      commodity: document.getElementById('newCommodity') ? document.getElementById('newCommodity').value : '',
      notes: document.getElementById('newNotes') ? document.getElementById('newNotes').value.trim() : '',
      status: 'PENDING',
      recognised: false,
      addedAt: new Date().toISOString(),
      lastTouchpoint: new Date().toISOString()
    });
  } else {
    const idxEl = document.getElementById('tpEntitySelect');
    const descEl = document.getElementById('tpDesc');
    if(!idxEl || !descEl) return;
    const idx = idxEl.value;
    const desc = descEl.value.trim();
    if(idx === '' || !desc) { alert('Selection and description required'); return; }
    if(list[idx]) list[idx].lastTouchpoint = new Date().toISOString();
  }

  setLocalData('intros', list);
  window.closeModalV6();
  refreshV6Dashboard();
};

function populateV6Select() {
  const list = getLocalData('intros', []);
  const select = document.getElementById('tpEntitySelect');
  if(!select) return;
  select.innerHTML = '<option value="">-- Select Active Introduction --</option>';
  list.forEach((item, index) => {
    const option = document.createElement('option');
    option.value = index;
    option.textContent = item.name;
    select.appendChild(option);
  });
}

function refreshV6Dashboard() {
  const list = getLocalData('intros', []);

  // V6 Stats Rendering
  const statIntros = document.getElementById('statActiveIntros');
  const statPending = document.getElementById('statPendingDD');
  const statClosed = document.getElementById('statClosedDeals');
  const statComm = document.getElementById('statTotalComm');

  if(statIntros) statIntros.textContent = list.length;
  if(statPending) statPending.textContent = list.filter(i => i.status === 'PENDING').length;
  if(statClosed) statClosed.textContent = list.filter(i => i.status === 'CLOSED').length;

  if(statComm) {
    const totalComm = list.reduce((s, i) => {
      const deal = parseFloat(i.dealVal || 0);
      const romi = deal * 0.02; // F-08 FIX: 2.0%
      return s + (romi * 0.18);
    }, 0);
    statComm.textContent = '$' + totalComm.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
  }

  // V6 Pipeline Table Rendering
  const tbody = document.getElementById('pipelineTbody');
  if(tbody) {
    if(!list.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:20px;">NO INTRODUCTIONS LOGGED</td></tr>';
    } else {
      tbody.innerHTML = '';
      list.forEach(item => {
        const tr = document.createElement('tr');
        const statusCls = item.status === 'ACTIVE' ? 'status-active' : (item.status === 'LAPSED' ? 'status-lapsed' : 'status-pending');
        tr.innerHTML = `
          <td>
            <div style="font-weight:600; color:var(--text);">${sanitize(item.name)}</div>
            <div style="font-size:9px; color:var(--text-muted); margin-top:2px;">${sanitize(item.contact)}</div>
          </td>
          <td>${sanitize(item.commodity)}</td>
          <td>${new Date(item.addedAt).toISOString().split('T')[0]}</td>
          <td>${item.lastTouchpoint ? new Date(item.lastTouchpoint).toISOString().split('T')[0] : '—'}</td>
          <td><span class="status-badge ${statusCls}">${sanitize(item.status)}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  // V6 Touchpoint Table Rendering
  const tpBody = document.getElementById('touchpointTbody');
  if(tpBody) {
     const sorted = [...list].sort((a,b) => new Date(b.lastTouchpoint || 0) - new Date(a.lastTouchpoint || 0)).slice(0,5);
     if(!sorted.length) {
        tpBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-dim); padding:20px;">NO TOUCHPOINT DATA...</td></tr>';
     } else {
        tpBody.innerHTML = '';
        sorted.forEach(item => {
           if(!item.lastTouchpoint) return;
           const tr = document.createElement('tr');
           tr.innerHTML = `
             <td>${new Date(item.lastTouchpoint).toISOString().split('T')[0]}</td>
             <td style="color:var(--gold);">${sanitize(item.name)}</td>
             <td>Touchpoint Logged</td>
             <td style="color:var(--text-muted);">Timothy Mawonera</td>
           `;
           tpBody.appendChild(tr);
        });
     }
  }
}

// ── Init ──
(function init() {
  const s = getSession();
  if (s.email && s.csrf) {
    _email = s.email; _csrf = s.csrf; _name = s.name;
    bootApp();
  } else {
    // Attempt non-auth initial render for testing/V6
    if (typeof refreshV6Dashboard === 'function') refreshV6Dashboard();
  }
})();
