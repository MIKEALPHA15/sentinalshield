/**
 * SentinelShield — background.js
 * Service Worker: Core detection engine.
 * Handles network request interception, URL analysis,
 * threat scoring, and message routing from content scripts.
 *
 * MITRE ATT&CK Coverage:
 *   T1189 (Drive-by Compromise), T1566 (Phishing),
 *   T1071 (C2 via Web Protocols), T1185 (Browser Session Hijacking),
 *   T1056 (Input Capture / Skimmer)
 */

'use strict';

// ─────────────────────────────────────────────
//  INLINE THREAT DB & ANALYZER
//  (Inlined because MV3 service workers cannot import
//   local scripts dynamically at runtime without importScripts)
// ─────────────────────────────────────────────

importScripts('utils/threatDB.js', 'utils/analyzer.js');

// ─────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────

/** In-memory session state per tab */
const tabState = new Map(); // tabId → { score, threats[], blockedCount, lastScan }

/** Session-level blocked request counter */
let sessionBlockedTotal = 0;

/** Shield enabled flag (persisted in storage) */
let shieldEnabled = true;
let strictMode = false;

// ─────────────────────────────────────────────
//  INIT — load persisted settings on startup
// ─────────────────────────────────────────────
chrome.storage.local.get(['shieldEnabled', 'strictMode'], (result) => {
  shieldEnabled = result.shieldEnabled !== false; // default true
  strictMode    = result.strictMode === true;
});

// ─────────────────────────────────────────────
//  HELPER: get or create tab state
// ─────────────────────────────────────────────
function getTabState(tabId) {
  if (!tabState.has(tabId)) {
    tabState.set(tabId, {
      score: 0,
      threats: [],
      blockedCount: 0,
      lastScan: null,
      url: '',
    });
  }
  return tabState.get(tabId);
}

// ─────────────────────────────────────────────
//  HELPER: add a threat event to a tab's state
// ─────────────────────────────────────────────
function recordThreat(tabId, threat) {
  const state = getTabState(tabId);
  // Avoid duplicates within the same page load
  const isDup = state.threats.some(t => t.type === threat.type && t.detail === threat.detail);
  if (!isDup) {
    state.threats.push({ ...threat, ts: Date.now() });
    // Keep only last 20 events per tab
    if (state.threats.length > 20) state.threats.shift();
  }
}

// ─────────────────────────────────────────────
//  HELPER: push updated state to popup (if open)
// ─────────────────────────────────────────────
function broadcastState(tabId) {
  const state = getTabState(tabId);
  chrome.runtime.sendMessage({
    type: 'STATE_UPDATE',
    tabId,
    state: {
      score: state.score,
      threats: state.threats.slice(-5), // Last 5 for popup display
      blockedCount: state.blockedCount,
      lastScan: state.lastScan,
      url: state.url,
      severity: scoreSeverity(state.score),
    },
  }).catch(() => { /* popup not open — ignore */ });
}

// ─────────────────────────────────────────────
//  TAB NAVIGATION TRACKING
//  Reset per-tab state on new page load
// ─────────────────────────────────────────────
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return; // Main frame only

  // Reset tab state for new navigation
  tabState.set(details.tabId, {
    score: 0,
    threats: [],
    blockedCount: 0,
    lastScan: null,
    url: details.url,
  });

  if (!shieldEnabled) return;

  // Analyze the URL immediately on navigation
  const { score: urlScore, findings: urlFindings } = analyzeUrl(details.url);

  // Combine threatDB URL analysis
  const { threats: dbUrlThreats } = analyzeUrl_DB(details.url);

  let pageScore = urlScore;

  for (const finding of urlFindings) {
    recordThreat(details.tabId, finding);
  }
  for (const threat of dbUrlThreats) {
    recordThreat(details.tabId, threat);
    pageScore = Math.min(pageScore + 30, 100); // Boost score for known-bad domains
  }

  // Phishing score from threatDB
  const { score: phishScore, signals } = phishingScore(details.url);
  if (phishScore >= 50) {
    pageScore = Math.max(pageScore, phishScore);
    recordThreat(details.tabId, {
      type: 'PHISHING',
      severity: phishScore >= 75 ? 'HIGH' : 'MEDIUM',
      detail: `Phishing score ${phishScore}/100 — ${signals.join(', ')}`,
      matches: signals.length,
    });
  }

  // Exploit kit URL fingerprint
  if (isExploitKit(details.url)) {
    pageScore = Math.min(pageScore + 40, 100);
    recordThreat(details.tabId, {
      type: 'EXPLOIT_KIT',
      severity: 'CRITICAL',
      detail: 'URL matches exploit kit gate/landing pattern.',
      matches: 1,
    });
  }

  getTabState(details.tabId).score = pageScore;
  getTabState(details.tabId).lastScan = Date.now();

  // Hard block if score > 85 in strict mode
  if (strictMode && pageScore >= 85) {
    blockTab(details.tabId, details.url, pageScore);
  }

  broadcastState(details.tabId);
});

// ─────────────────────────────────────────────
//  WRAPPER: analyzeUrl from threatDB
// ─────────────────────────────────────────────
function analyzeUrl_DB(url) {
  // Prefer dedicated threat DB URL analyzer when available.
  if (typeof analyzeUrlThreatDB === 'function') {
    return analyzeUrlThreatDB(url);
  }

  // Fallback: domain-only check if analyzer is unavailable.
  const result = checkDomain(url);
  if (result.matched) {
    return { threats: [{ type: result.category, severity: 'CRITICAL', detail: `Known malicious domain: ${result.domain}`, matches: 1 }] };
  }
  return { threats: [] };
}

// ─────────────────────────────────────────────
//  DECLARATIVE NET REQUEST — Dynamic rule updates
//  Adds ephemeral blocking rules for detected C2 / malware domains
// ─────────────────────────────────────────────

let dynamicRuleId = 1000; // Start above static rules.json IDs

/**
 * Dynamically block a domain via DNR.
 * @param {string} domain
 */
function blockDomainDynamic(domain) {
  chrome.declarativeNetRequest.addDynamicRules({
    addRules: [{
      id: dynamicRuleId++,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: `||${domain}^`,
        resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest', 'websocket'],
      },
    }],
  }).catch(err => console.warn('[SentinelShield] DNR dynamic rule error:', err));
}

// ─────────────────────────────────────────────
//  HARD BLOCK — redirect to warning page
// ─────────────────────────────────────────────
function blockTab(tabId, url, score) {
  const warningUrl = chrome.runtime.getURL('blocked.html') +
    `?score=${score}&url=${encodeURIComponent(url)}`;
  chrome.tabs.update(tabId, { url: warningUrl }).catch(() => {});
}

// ─────────────────────────────────────────────
//  WEB NAVIGATION — track redirects (open redirect chains)
// ─────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (!shieldEnabled || details.frameId !== 0) return;

  // Detect redirect chains (3+ redirects = suspicious)
  const state = getTabState(details.tabId);
  if (!state._redirectCount) state._redirectCount = 0;
  state._redirectCount++;

  if (state._redirectCount >= 3) {
    recordThreat(details.tabId, {
      type: 'REDIRECT_CHAIN',
      severity: 'MEDIUM',
      detail: `${state._redirectCount} redirects detected on this navigation chain.`,
      matches: state._redirectCount,
    });
    state.score = Math.min(state.score + 15, 100);
  }
});

chrome.webNavigation.onCommitted.addListener((details) => {
  // Reset redirect counter on final navigation
  if (details.frameId === 0) {
    const state = getTabState(details.tabId);
    state._redirectCount = 0;
  }
}, { urls: ['<all_urls>'] });

// ─────────────────────────────────────────────
//  MESSAGES FROM CONTENT SCRIPT
//  Handles: runtime behavior reports, DOM findings, resource scans
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender?.tab?.id;
  const tabBoundTypes = new Set(['RUNTIME_FLAGS', 'SCRIPT_CONTENT', 'BLOCKED_REQUEST']);
  if (tabBoundTypes.has(message.type) && !tabId) {
    sendResponse({ ok: false, error: 'NO_TAB_CONTEXT' });
    return false;
  }

  switch (message.type) {

    // ── Content script reports DOM/runtime threat flags ──
    case 'RUNTIME_FLAGS': {
      if (!shieldEnabled) {
        sendResponse({ ok: true, skipped: 'SHIELD_DISABLED' });
        break;
      }
      const { score: rScore, findings } = analyzeRuntimeFlags(message.flags);
      const state = getTabState(tabId);

      for (const finding of findings) recordThreat(tabId, finding);

      // Combine with existing score (runtime carries 45% weight)
      state.score = compositeScore(
        phishingScore(state.url).score,
        state._contentScore || 0,
        rScore
      );
      state.lastScan = Date.now();

      if (strictMode && state.score >= 85) {
        blockTab(tabId, state.url, state.score);
      }

      broadcastState(tabId);
      sendResponse({ ok: true });
      break;
    }

    // ── Content script reports a scanned script's content ──
    case 'SCRIPT_CONTENT': {
      if (!shieldEnabled) {
        sendResponse({ ok: true, skipped: 'SHIELD_DISABLED' });
        break;
      }
      const { score: cScore, findings } = analyzeContent(message.content, 'script');
      const state = getTabState(tabId);
      state._contentScore = Math.max(state._contentScore || 0, cScore);

      for (const finding of findings) recordThreat(tabId, finding);

      state.score = Math.max(state.score, cScore);
      state.lastScan = Date.now();
      broadcastState(tabId);
      sendResponse({ ok: true });
      break;
    }

    // ── Content script reports a blocked request ──
    case 'BLOCKED_REQUEST': {
      const state = getTabState(tabId);
      state.blockedCount++;
      sessionBlockedTotal++;
      recordThreat(tabId, {
        type: message.reason || 'BLOCKED_REQUEST',
        severity: 'HIGH',
        detail: `Blocked outgoing request to: ${message.url}`,
        matches: 1,
      });
      broadcastState(tabId);

      // Dynamically block the offending domain
      try {
        const domain = new URL(message.url).hostname;
        blockDomainDynamic(domain);
      } catch (_) {}
      sendResponse({ ok: true });
      break;
    }

    // ── Popup requests current tab state ──
    case 'GET_STATE': {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]) { sendResponse(null); return; }
        const state = getTabState(tabs[0].id);
        sendResponse({
          score: state.score,
          threats: state.threats.slice(-5),
          blockedCount: state.blockedCount,
          sessionBlocked: sessionBlockedTotal,
          lastScan: state.lastScan,
          url: state.url || tabs[0].url,
          severity: scoreSeverity(state.score),
          shieldEnabled,
          strictMode,
          version: chrome.runtime.getManifest().version,
        });
      });
      return true; // async
    }

    // ── Popup toggles shield ──
    case 'SET_SHIELD': {
      shieldEnabled = message.enabled;
      chrome.storage.local.set({ shieldEnabled });
      sendResponse({ ok: true });
      break;
    }

    // ── Popup toggles strict mode ──
    case 'SET_STRICT': {
      strictMode = message.enabled;
      chrome.storage.local.set({ strictMode });
      sendResponse({ ok: true });
      break;
    }

    // ── Report a threat (sends to storage log) ──
    case 'REPORT_THREAT': {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const activeTabId = tabs[0]?.id;
        const state = activeTabId ? getTabState(activeTabId) : { score: 0, threats: [], url: '' };
        const report = {
          ts: Date.now(),
          url: state.url || tabs[0]?.url || '',
          score: state.score,
          threats: state.threats,
        };
        chrome.storage.local.get({ threatReports: [] }, (data) => {
          const reports = data.threatReports;
          reports.push(report);
          // Keep last 100 reports
          if (reports.length > 100) reports.splice(0, reports.length - 100);
          chrome.storage.local.set({ threatReports: reports }, () => sendResponse({ ok: true }));
        });
      });
      return true; // async
    }

    default:
      sendResponse({ ok: false, error: 'UNKNOWN_MESSAGE_TYPE' });
      break;
  }
});

// ─────────────────────────────────────────────
//  TAB CLOSE — clean up state
// ─────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

console.log('[SentinelShield] Service worker initialized. Shield active.');
