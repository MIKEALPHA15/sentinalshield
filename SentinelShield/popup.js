/**
 * SentinelShield — popup.js
 * Controls the threat dashboard UI.
 * Communicates with background.js via chrome.runtime.sendMessage.
 */

'use strict';

// ─────────────────────────────────────────────
//  DOM REFS
// ─────────────────────────────────────────────
const scoreNum      = document.getElementById('scoreNum');
const scoreArc      = document.getElementById('scoreArc');
const scoreRingWrap = document.getElementById('scoreRingWrap');
const severityLabel = document.getElementById('severityLabel');
const pageUrlEl     = document.getElementById('pageUrl');
const lastScanEl    = document.getElementById('lastScan');
const blockedCount  = document.getElementById('blockedCount');
const threatCount   = document.getElementById('threatCount');
const sessionCount  = document.getElementById('sessionCount');
const threatsList   = document.getElementById('threatsList');
const threatBadge   = document.getElementById('threatBadge');
const btnShield     = document.getElementById('btnShield');
const btnStrict     = document.getElementById('btnStrict');
const btnReport     = document.getElementById('btnReport');
const versionBadge  = document.getElementById('versionBadge');
const disabledBanner= document.getElementById('disabledBanner');
const footerTxt     = document.getElementById('footerTxt');
const statusDot     = document.getElementById('statusDot');

// SVG arc circumference
const CIRCUMFERENCE = 2 * Math.PI * 36; // r=36 → 226.2

// ─────────────────────────────────────────────
//  COLOR MAP
// ─────────────────────────────────────────────
const SEV_COLOR = {
  SAFE:     '#00e676',
  LOW:      '#a8ff3e',
  MEDIUM:   '#ffd600',
  HIGH:     '#ff6d00',
  CRITICAL: '#ff1744',
};

// ─────────────────────────────────────────────
//  UPDATE RING
// ─────────────────────────────────────────────
function updateRing(score, severity) {
  const pct = score / 100;
  const offset = CIRCUMFERENCE * (1 - pct);
  const color = SEV_COLOR[severity] || SEV_COLOR.SAFE;

  scoreArc.style.strokeDashoffset = offset;
  scoreArc.style.stroke = color;
  scoreNum.textContent = score;
  severityLabel.textContent = severity;
  severityLabel.style.color = color;

  // Ring glow
  scoreRingWrap.classList.toggle('critical-glow', severity === 'CRITICAL');
  scoreRingWrap.classList.toggle('high-glow', severity === 'HIGH' && severity !== 'CRITICAL');
}

// ─────────────────────────────────────────────
//  FORMAT TIMESTAMP
// ─────────────────────────────────────────────
function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ─────────────────────────────────────────────
//  RENDER THREATS LIST
// ─────────────────────────────────────────────
function renderThreats(threats) {
  threatBadge.textContent = threats.length;

  if (!threats || threats.length === 0) {
    threatsList.innerHTML = '<div class="no-threats"><span>✓ No threats detected</span> on this page.</div>';
    return;
  }

  // Sort by severity
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...threats].sort((a, b) => (ORDER[a.severity] ?? 4) - (ORDER[b.severity] ?? 4));

  threatsList.innerHTML = sorted.map(t => `
    <div class="threat-item">
      <span class="threat-badge sev-${t.severity}">${t.severity}</span>
      <div class="threat-detail">
        <div class="threat-type">${escHtml(t.type || 'UNKNOWN')}</div>
        <div class="threat-desc">${escHtml(t.detail || '')}</div>
        ${t.ts ? `<div class="threat-ts">${fmtTime(t.ts)}</div>` : ''}
      </div>
    </div>
  `).join('');
}

// ─────────────────────────────────────────────
//  HTML ESCAPE (no innerHTML injection)
// ─────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─────────────────────────────────────────────
//  APPLY STATE TO UI
// ─────────────────────────────────────────────
function applyState(state) {
  if (!state) return;

  updateRing(state.score || 0, state.severity || 'SAFE');

  // URL (truncated display)
  try {
    const u = new URL(state.url || '');
    pageUrlEl.textContent = u.hostname + (u.pathname.length > 1 ? u.pathname.substring(0, 20) : '');
    pageUrlEl.title = state.url;
  } catch (_) {
    pageUrlEl.textContent = state.url || '—';
  }

  lastScanEl.textContent = 'Last scan: ' + fmtTime(state.lastScan);
  blockedCount.textContent = state.blockedCount || 0;
  threatCount.textContent = (state.threats || []).length;
  sessionCount.textContent = state.sessionBlocked || 0;

  renderThreats(state.threats || []);

  // Shield button
  const isEnabled = state.shieldEnabled !== false;
  btnShield.textContent = isEnabled ? 'Shield ✓' : 'Shield ✗';
  btnShield.classList.toggle('active', isEnabled);
  btnShield.classList.toggle('toggle-off', !isEnabled);

  disabledBanner.classList.toggle('show', !isEnabled);
  statusDot.classList.toggle('off', !isEnabled);
  footerTxt.textContent = isEnabled ? 'SENTINEL ACTIVE' : 'PROTECTION DISABLED';

  // Strict mode button
  btnStrict.classList.toggle('active', state.strictMode === true);
  btnStrict.textContent = state.strictMode ? 'Strict ✓' : 'Strict';

  // Version
  versionBadge.textContent = 'v' + (state.version || '1.0.0');
}

// ─────────────────────────────────────────────
//  LOAD STATE FROM BACKGROUND
// ─────────────────────────────────────────────
function loadState() {
  chrome.runtime.sendMessage({ type: 'GET_STATE' }, (state) => {
    if (chrome.runtime.lastError) return;
    applyState(state);
  });
}

// ─────────────────────────────────────────────
//  BUTTON HANDLERS
// ─────────────────────────────────────────────

// Toggle shield on/off
btnShield.addEventListener('click', () => {
  const isCurrentlyActive = btnShield.classList.contains('active');
  chrome.runtime.sendMessage({ type: 'SET_SHIELD', enabled: !isCurrentlyActive }, () => {
    loadState();
  });
});

// Toggle strict mode
btnStrict.addEventListener('click', () => {
  const isCurrentlyStrict = btnStrict.classList.contains('active');
  chrome.runtime.sendMessage({ type: 'SET_STRICT', enabled: !isCurrentlyStrict }, () => {
    loadState();
  });
});

// Report threat — save to storage
btnReport.addEventListener('click', () => {
  btnReport.textContent = 'Saving...';
  btnReport.disabled = true;
  chrome.runtime.sendMessage({ type: 'REPORT_THREAT' }, () => {
    btnReport.textContent = 'Reported ✓';
    setTimeout(() => {
      btnReport.textContent = 'Report';
      btnReport.disabled = false;
    }, 1500);
  });
});

// ─────────────────────────────────────────────
//  LIVE UPDATES — listen for background broadcasts
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'STATE_UPDATE') {
    applyState(message.state);
  }
});

// ─────────────────────────────────────────────
//  INIT
// ─────────────────────────────────────────────
loadState();

// Refresh every 3 seconds while popup is open
setInterval(loadState, 3000);
