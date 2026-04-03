/**
 * SentinelShield — utils/analyzer.js
 * Heuristic + signature-based threat analysis engine.
 * Scores pages 0–100. Detects XSS, obfuscation, skimmers,
 * prototype pollution, exploit kit patterns, and more.
 */

'use strict';

// ─────────────────────────────────────────────
//  XSS PAYLOAD SIGNATURES
//  Matches reflected/DOM XSS patterns in URLs and HTML strings
// ─────────────────────────────────────────────
const XSS_PATTERNS = [
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript\s*:/gi,
  /on\w+\s*=\s*["']?[^"'>]*?(alert|confirm|prompt|eval|fetch|XMLHttpRequest)/gi,
  /document\.(cookie|write|writeln)\s*\(/gi,
  /window\.(location|open)\s*=/gi,
  /<iframe[\s\S]*?src\s*=\s*["']?(javascript|data):/gi,
  /expression\s*\(.*\)/gi,                  // CSS expression (IE XSS)
  /&#x?[0-9a-fA-F]+;/g,                     // HTML entity encoding (XSS evasion)
  /%3cscript/gi,                             // URL-encoded <script
  /\x00/g,                                   // Null byte injection
];

// ─────────────────────────────────────────────
//  OBFUSCATION PATTERNS
//  Detects packed/encoded JS payloads
// ─────────────────────────────────────────────
const OBFUSCATION_PATTERNS = [
  /eval\s*\(\s*(atob|unescape|decodeURIComponent)/gi,           // eval + decode chain
  /\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/gi, // Dean Edwards p,a,c,k packer
  /String\.fromCharCode\s*\((\s*\d+\s*,?\s*){10,}\)/gi,         // charCode array (>10 items)
  /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}/gi,              // long hex escape sequences
  /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){15,}/gi,              // long unicode escape sequences
  /[A-Za-z0-9+/]{200,}={0,2}/g,                                 // long base64 blob inline
  /\[\s*(['"])\w+\1\s*\]\s*\[\s*(['"])\w+\2\s*\]/gi,           // bracket notation obfuscation
  /setTimeout\s*\(\s*["'][^"']{50,}["']/gi,                     // code-in-string execution
];

// ─────────────────────────────────────────────
//  MAGECART / CARD SKIMMER PATTERNS
//  Targets checkout form data exfiltration
// ─────────────────────────────────────────────
const SKIMMER_PATTERNS = [
  /card[\s_-]?number/gi,
  /ccnum|cc_num|cardnum/gi,
  /cvv|cvc|security[\s_-]?code/gi,
  /expir(y|ation)[\s_-]?(date|month|year)/gi,
  /new\s+Image\(\)[\s\S]{0,200}\.src\s*=/gi,          // pixel beacon exfil
  /navigator\.sendBeacon\s*\(\s*['"][^'"]{10,}/gi,    // sendBeacon exfil
  /fetch\s*\(\s*['"][^'"]{10,}['"][^)]*\bmethod\s*:\s*['"]POST/gi, // POST exfil
  /XMLHttpRequest[\s\S]{0,100}\.send\s*\(/gi,
];

// ─────────────────────────────────────────────
//  PROTOTYPE POLLUTION PATTERNS
// ─────────────────────────────────────────────
const PROTO_POLLUTION_PATTERNS = [
  /__proto__\s*\[/gi,
  /constructor\s*\[\s*["']prototype["']\s*\]/gi,
  /Object\.prototype\s*\[/gi,
  /\["__proto__"\]/gi,
];

// ─────────────────────────────────────────────
//  FINGERPRINTING PATTERNS
//  Canvas, AudioContext, WebRTC, timing attacks
// ─────────────────────────────────────────────
const FINGERPRINT_PATTERNS = [
  /toDataURL\s*\(\s*["']image\/png["']\s*\)/gi,          // Canvas fingerprint
  /getImageData\s*\(\s*0\s*,\s*0/gi,
  /AudioContext|webkitAudioContext/gi,                   // Audio fingerprint
  /createOscillator\s*\(\s*\)/gi,
  /RTCPeerConnection|webkitRTCPeerConnection/gi,         // WebRTC IP leak
  /performance\.now\s*\(\s*\)[\s\S]{0,100}performance\.now\s*\(\s*\)/gi, // Timing attack
  /screen\.(width|height|colorDepth|pixelDepth)/gi,
  /navigator\.(plugins|mimeTypes|hardwareConcurrency|deviceMemory)/gi,
];

// ─────────────────────────────────────────────
//  HEAP SPRAY / EXPLOIT PATTERNS
// ─────────────────────────────────────────────
const HEAP_SPRAY_PATTERNS = [
  /new\s+Array\s*\(\s*[0-9]{6,}\s*\)/gi,                // Huge array allocation
  /\.join\s*\(\s*["'][^"']{50,}["']\s*\)/gi,            // Long string join (NOP sled)
  /unescape\s*\(\s*["'](%u[0-9a-fA-F]{4}){20,}/gi,      // Unicode NOP sled
  /\bshellcode\b/gi,
  /CollectGarbage\s*\(\s*\)/gi,                          // IE GC trigger (exploit kit)
];

// ─────────────────────────────────────────────
//  C2 BEACON DETECTION HELPERS
//  Detects periodic XHR/fetch calls (beacon intervals)
// ─────────────────────────────────────────────
const C2_PATTERNS = [
  /setInterval\s*\([^)]{0,200}(fetch|XMLHttpRequest|sendBeacon)/gi,  // Periodic beacon
  /setTimeout\s*\([^)]{0,200}(fetch|XMLHttpRequest)[^)]{0,200}\d{4,}/gi, // Delayed C2 callback
  /WebSocket\s*\(\s*["']wss?:\/\/[^"']{5,}/gi,                      // Suspicious WS connect
];

// ─────────────────────────────────────────────
//  CLICKJACKING / BitB DETECTION
// ─────────────────────────────────────────────
const CLICKJACKING_PATTERNS = [
  /position\s*:\s*fixed[\s\S]{0,200}(top\s*:\s*0|left\s*:\s*0)/gi,  // Fixed full-cover overlay
  /opacity\s*:\s*0[\s\S]{0,100}z-index\s*:\s*[0-9]{4,}/gi,          // Invisible high-z layer
  /pointer-events\s*:\s*none[\s\S]{0,200}iframe/gi,                  // iframe + no-pointer-events
];

// ─────────────────────────────────────────────
//  MAIN ANALYSIS FUNCTION
//  Accepts raw page HTML/JS as a string
//  Returns a threat score + detailed findings
// ─────────────────────────────────────────────

/**
 * Analyze a script/HTML string for threats.
 * @param {string} content — HTML or JS content to scan
 * @param {string} [context='unknown'] — 'script', 'html', 'url'
 * @returns {{ score: number, findings: Array<{type:string, severity:string, detail:string, matches:number}> }}
 */
function analyzeContent(content, context = 'unknown') {
  if (!content || typeof content !== 'string') {
    return { score: 0, findings: [] };
  }

  const findings = [];
  let score = 0;

  // Run each category of patterns
  const checks = [
    { patterns: XSS_PATTERNS,          type: 'XSS',             weight: 20, severity: 'HIGH'     },
    { patterns: OBFUSCATION_PATTERNS,  type: 'OBFUSCATION',     weight: 15, severity: 'MEDIUM'   },
    { patterns: SKIMMER_PATTERNS,      type: 'SKIMMER',         weight: 25, severity: 'CRITICAL'  },
    { patterns: PROTO_POLLUTION_PATTERNS, type: 'PROTO_POLLUTION', weight: 20, severity: 'HIGH'  },
    { patterns: FINGERPRINT_PATTERNS,  type: 'FINGERPRINT',     weight: 10, severity: 'LOW'      },
    { patterns: HEAP_SPRAY_PATTERNS,   type: 'HEAP_SPRAY',      weight: 30, severity: 'CRITICAL' },
    { patterns: C2_PATTERNS,           type: 'C2_BEACON',       weight: 25, severity: 'HIGH'     },
    { patterns: CLICKJACKING_PATTERNS, type: 'CLICKJACKING',    weight: 20, severity: 'HIGH'     },
  ];

  for (const { patterns, type, weight, severity } of checks) {
    let matchCount = 0;
    for (const pattern of patterns) {
      const clone = new RegExp(pattern.source, pattern.flags);
      const matches = content.match(clone);
      if (matches) matchCount += matches.length;
    }
    if (matchCount > 0) {
      const contribution = Math.min(weight * Math.log2(matchCount + 1), weight);
      score += contribution;
      findings.push({ type, severity, detail: `${matchCount} match(es) in ${context}`, matches: matchCount });
    }
  }

  // Inline eval usage (not in obfuscation context — standalone eval is still risky)
  const evalCount = (content.match(/\beval\s*\(/gi) || []).length;
  if (evalCount > 0) {
    score += Math.min(evalCount * 5, 15);
    findings.push({ type: 'EVAL_USAGE', severity: 'MEDIUM', detail: `${evalCount} eval() call(s) detected`, matches: evalCount });
  }

  // document.cookie access
  const cookieCount = (content.match(/document\.cookie/gi) || []).length;
  if (cookieCount > 2) {
    score += 10;
    findings.push({ type: 'COOKIE_ACCESS', severity: 'MEDIUM', detail: `Excessive document.cookie access (${cookieCount}x)`, matches: cookieCount });
  }

  return { score: Math.min(Math.round(score), 100), findings };
}

/**
 * Analyze a URL string for XSS payloads (reflected XSS detection).
 * @param {string} url
 * @returns {{ score: number, findings: Array }}
 */
function analyzeUrl(url) {
  if (!url) return { score: 0, findings: [] };

  const decoded = (() => {
    try { return decodeURIComponent(url); } catch (_) { return url; }
  })();

  const findings = [];
  let score = 0;

  // Check URL-encoded XSS
  for (const pattern of XSS_PATTERNS) {
    const clone = new RegExp(pattern.source, pattern.flags);
    if (clone.test(decoded)) {
      score += 25;
      findings.push({ type: 'REFLECTED_XSS', severity: 'HIGH', detail: 'XSS payload detected in URL parameter', matches: 1 });
      break;
    }
  }

  // Check for open redirect
  if (/[?&](redirect|url|next|return|goto|dest|destination)\s*=\s*(https?|\/\/)/gi.test(url)) {
    score += 15;
    findings.push({ type: 'OPEN_REDIRECT', severity: 'MEDIUM', detail: 'Open redirect parameter detected in URL', matches: 1 });
  }

  // JSONP abuse
  if (/[?&]callback\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$.]*/gi.test(url)) {
    score += 10;
    findings.push({ type: 'JSONP_CALLBACK', severity: 'LOW', detail: 'JSONP callback parameter found', matches: 1 });
  }

  return { score: Math.min(score, 100), findings };
}

/**
 * Check a script's behavior flags (passed from content.js runtime observations).
 * @param {Object} flags — observed JS behaviors
 * @returns {{ score: number, findings: Array }}
 */
function analyzeRuntimeFlags(flags) {
  const findings = [];
  let score = 0;

  if (flags.evalCalled)          { score += 15; findings.push({ type: 'RUNTIME_EVAL',      severity: 'MEDIUM',   detail: 'eval() was invoked at runtime',               matches: 1 }); }
  if (flags.dynamicScript)       { score += 10; findings.push({ type: 'DYNAMIC_SCRIPT',    severity: 'MEDIUM',   detail: 'Repeated dynamic <script> injection observed', matches: 1 }); }
  if (flags.suspiciousIframe)    { score += 12; findings.push({ type: 'SUSPICIOUS_IFRAME', severity: 'MEDIUM',   detail: 'Suspicious external iframe behavior detected', matches: 1 }); }
  if (flags.canvasFingerprint)   { score += 10; findings.push({ type: 'FINGERPRINT',       severity: 'LOW',      detail: 'Canvas fingerprinting behavior observed',       matches: 1 }); }
  if (flags.audioFingerprint)    { score += 10; findings.push({ type: 'FINGERPRINT',       severity: 'LOW',      detail: 'AudioContext fingerprinting behavior observed',  matches: 1 }); }
  if (flags.webRTCLeak)          { score += 15; findings.push({ type: 'WEBRTC_LEAK',       severity: 'MEDIUM',   detail: 'WebRTC RTCPeerConnection used (possible IP leak)', matches: 1 }); }
  if (flags.cookieAccess)        { score += 10; findings.push({ type: 'COOKIE_ACCESS',     severity: 'MEDIUM',   detail: 'Suspicious document.cookie read detected',      matches: 1 }); }
  if (flags.externalBeacon)      { score += 12; findings.push({ type: 'C2_BEACON',         severity: 'MEDIUM',   detail: 'Outbound external beacon behavior observed',     matches: 1 }); }
  if (flags.sriViolation)        { score += 20; findings.push({ type: 'SRI_VIOLATION',     severity: 'HIGH',     detail: 'Script loaded without SRI hash match',          matches: 1 }); }
  if (flags.protoPollution)      { score += 25; findings.push({ type: 'PROTO_POLLUTION',   severity: 'CRITICAL', detail: '__proto__ or constructor.prototype mutation',    matches: 1 }); }
  if (flags.hiddenFormField)     { score += 15; findings.push({ type: 'HIDDEN_FORM',       severity: 'MEDIUM',   detail: 'Hidden form field injected into DOM',           matches: 1 }); }
  if (flags.passwordOnHttp)      { score += 30; findings.push({ type: 'INSECURE_FORM',     severity: 'CRITICAL', detail: 'Password field on non-HTTPS page',              matches: 1 }); }

  return { score: Math.min(score, 100), findings };
}

/**
 * Combine URL score + content score + runtime score into a final page threat score.
 * @param {number} urlScore
 * @param {number} contentScore
 * @param {number} runtimeScore
 * @returns {number} — 0–100
 */
function compositeScore(urlScore, contentScore, runtimeScore) {
  // Weighted average: runtime and content weigh more than URL alone
  return Math.min(Math.round(urlScore * 0.2 + contentScore * 0.35 + runtimeScore * 0.45), 100);
}

/**
 * Map a numeric score to a severity label.
 * @param {number} score
 * @returns {'SAFE'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'}
 */
function scoreSeverity(score) {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 15) return 'LOW';
  return 'SAFE';
}

if (typeof module !== 'undefined') {
  module.exports = { analyzeContent, analyzeUrl, analyzeRuntimeFlags, compositeScore, scoreSeverity };
}
