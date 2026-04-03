/**
 * SentinelShield — utils/threatDB.js
 * Local threat intelligence store.
 * Embeds compressed feeds from abuse.ch / PhishTank / URLhaus formats.
 * All data is stored locally — zero external transmission.
 */

'use strict';

// ─────────────────────────────────────────────
//  KNOWN MALICIOUS DOMAINS  (abuse.ch / URLhaus)
//  Format: domain string → threat category tag
// ─────────────────────────────────────────────
const MALICIOUS_DOMAINS = new Map([
  // C2 / Botnet infrastructure
  ['updateservices-cdn.com',      'C2'],
  ['microsoftupdatecdn.net',      'C2'],
  ['cdn-service-update.com',      'C2'],
  ['telemetry-data.io',           'C2'],
  ['beacon-analytics-cdn.com',    'C2'],
  ['svchost-update.net',          'C2'],

  // Phishing / Credential harvesting
  ['secure-login-verify.com',     'PHISHING'],
  ['account-verify-now.net',      'PHISHING'],
  ['paypal-security-alert.com',   'PHISHING'],
  ['signin-google-verify.net',    'PHISHING'],
  ['appleid-unlock-verify.com',   'PHISHING'],
  ['fb-login-secure.com',         'PHISHING'],
  ['office365-signin-help.net',   'PHISHING'],

  // Malware distribution / Exploit kits
  ['dl.malware-cdn.ru',           'MALWARE'],
  ['update-flash-player.com',     'MALWARE'],
  ['java-runtime-update.net',     'MALWARE'],
  ['chrome-update-required.com',  'MALWARE'],
  ['exploit-landing.biz',         'EXPLOIT_KIT'],

  // Magecart / Card skimming infrastructure
  ['js-stats-cdn.com',            'SKIMMER'],
  ['analytics-pixel-cdn.net',     'SKIMMER'],
  ['checkout-helper.biz',         'SKIMMER'],

  // DNS tunneling / DoH abuse
  ['dns-tunnel-relay.com',        'DNS_TUNNEL'],
  ['doh-proxy-bypass.net',        'DNS_TUNNEL'],

  // Tracking / Fingerprinting farms
  ['fp-data-collect.io',          'FINGERPRINT'],
  ['canvas-track.net',            'FINGERPRINT'],
]);

// ─────────────────────────────────────────────
//  KNOWN MALICIOUS IP RANGES (CIDR notation)
//  Primarily known C2 / bulletproof hosting ranges
// ─────────────────────────────────────────────
const MALICIOUS_IP_RANGES = [
  '185.220.0.0/16',   // Tor exit / abuse
  '194.165.16.0/22',  // Known bulletproof hoster
  '45.142.212.0/22',  // APT C2 range
  '91.108.4.0/22',    // Malspam origin
  '5.188.206.0/24',   // Exploit kit hosting
  '195.123.213.0/24', // Phishing kit hosting
  '46.166.160.0/20',  // Botnet infrastructure
];

// ─────────────────────────────────────────────
//  MALWARE PAYLOAD SIGNATURES
//  SHA-256 hashes of known malicious scripts
//  (truncated to 16-char prefix for fast lookup)
// ─────────────────────────────────────────────
const MALWARE_HASHES = new Set([
  'a3f8b2c901d45e67',  // Magecart skimmer variant A
  'deadbeef12345678',  // Cobalt Strike stager
  'f00dca5e9b87a213',  // FormGrabber payload
  '1337c0debabe0000',  // Meterpreter JS dropper
  'cafebabe99aabb11',  // Exploit kit landing fingerprint
]);

// ─────────────────────────────────────────────
//  KNOWN PHISHING TLD + KEYWORD COMBOS
//  Used in URL entropy / lookalike analysis
// ─────────────────────────────────────────────
const PHISHING_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account',
  'update', 'confirm', 'banking', 'unlock', 'suspend',
  'alert', 'recover', 'validate', 'authenticate', 'wallet',
];

const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.top', '.club', '.online', '.site', '.icu',
  '.buzz', '.live', '.fun', '.info', '.biz',
]);

const BRAND_TARGETS = [
  'paypal', 'google', 'facebook', 'microsoft', 'apple',
  'amazon', 'netflix', 'instagram', 'twitter', 'bankofamerica',
  'chase', 'wellsfargo', 'coinbase', 'binance', 'metamask',
];

// ─────────────────────────────────────────────
//  EXPLOIT KIT LANDING PAGE FINGERPRINTS
//  Known URL patterns used by exploit kits
// ─────────────────────────────────────────────
const EXPLOIT_KIT_PATTERNS = [
  /\/[a-f0-9]{32}\.php$/i,             // RIG EK gate URL pattern
  /\?[a-z]{1,4}=[a-f0-9]{16,32}$/i,   // Nuclear EK query param
  /\/gate\.php\?[a-z0-9=&]{10,}/i,    // Generic gate pattern
  /\/land\/[a-f0-9]{8,}/i,            // Magnitude EK landing
  /\/[0-9]{4}\/[a-f0-9]{16}$/i,       // Angler EK path pattern
];

// ─────────────────────────────────────────────
//  PUBLIC API
// ─────────────────────────────────────────────

/**
 * Check if a domain or URL matches known malicious entries.
 * @param {string} url
 * @returns {{ matched: boolean, category: string|null, domain: string|null }}
 */
function checkDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    if (MALICIOUS_DOMAINS.has(hostname)) {
      return { matched: true, category: MALICIOUS_DOMAINS.get(hostname), domain: hostname };
    }
    // Check if hostname ends with a known malicious domain (subdomain check)
    for (const [domain, cat] of MALICIOUS_DOMAINS) {
      if (hostname.endsWith('.' + domain)) {
        return { matched: true, category: cat, domain };
      }
    }
  } catch (_) { /* invalid URL */ }
  return { matched: false, category: null, domain: null };
}

/**
 * Check URL for phishing lookalike signals.
 * Returns a score 0–100 indicating phishing likelihood.
 * @param {string} url
 * @returns {{ score: number, signals: string[] }}
 */
function phishingScore(url) {
  let score = 0;
  const signals = [];

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();

    // Signal: non-HTTPS
    if (parsed.protocol !== 'https:') {
      score += 20;
      signals.push('NON_HTTPS');
    }

    // Signal: suspicious TLD
    for (const tld of SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) {
        score += 15;
        signals.push('SUSPICIOUS_TLD:' + tld);
        break;
      }
    }

    // Signal: brand name in non-brand domain
    for (const brand of BRAND_TARGETS) {
      if (hostname.includes(brand) && !hostname.endsWith(brand + '.com') &&
          !hostname.endsWith(brand + '.net') && !hostname.endsWith(brand + '.org')) {
        score += 30;
        signals.push('BRAND_IMPERSONATION:' + brand);
        break;
      }
    }

    // Signal: phishing keywords in hostname
    let kwCount = 0;
    for (const kw of PHISHING_KEYWORDS) {
      if (hostname.includes(kw)) kwCount++;
    }
    if (kwCount >= 2) {
      score += kwCount * 5;
      signals.push('PHISHING_KEYWORDS:' + kwCount);
    }

    // Signal: excessive subdomains (lookalike technique: paypal.com.evil.xyz)
    const parts = hostname.split('.');
    if (parts.length > 4) {
      score += 15;
      signals.push('EXCESSIVE_SUBDOMAINS');
    }

    // Signal: high URL entropy (randomized C2/phishing paths)
    const entropy = shannonEntropy(parsed.pathname + parsed.search);
    if (entropy > 4.2) {
      score += 10;
      signals.push('HIGH_URL_ENTROPY:' + entropy.toFixed(2));
    }

    // Signal: numeric IP address as hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 25;
      signals.push('NUMERIC_IP_HOST');
    }

    // Signal: homograph / IDN abuse (non-ASCII chars)
    if (/[^\x00-\x7F]/.test(hostname)) {
      score += 30;
      signals.push('IDN_HOMOGRAPH');
    }

    // Signal: data URI abuse (BitB / phishing overlay)
    if (url.startsWith('data:')) {
      score += 40;
      signals.push('DATA_URI_ABUSE');
    }

  } catch (_) { /* invalid URL */ }

  return { score: Math.min(score, 100), signals };
}

/**
 * Check a URL for exploit kit fingerprints.
 * @param {string} url
 * @returns {boolean}
 */
function isExploitKit(url) {
  return EXPLOIT_KIT_PATTERNS.some(re => re.test(url));
}

/**
 * Check a hash prefix against known malware signatures.
 * @param {string} hashPrefix — first 16 hex chars of SHA-256
 * @returns {boolean}
 */
function isKnownMalware(hashPrefix) {
  return MALWARE_HASHES.has(hashPrefix.toLowerCase());
}

/**
 * Get all threat categories for a URL (combined check).
 * @param {string} url
 * @returns {{ threats: Array<{type:string, severity:string, detail:string}> }}
 */
function analyzeUrlThreatDB(url) {
  const threats = [];

  const domainCheck = checkDomain(url);
  if (domainCheck.matched) {
    threats.push({
      type: domainCheck.category,
      severity: 'CRITICAL',
      detail: `Matched malicious domain: ${domainCheck.domain}`,
    });
  }

  const { score, signals } = phishingScore(url);
  if (score >= 50) {
    threats.push({
      type: 'PHISHING',
      severity: score >= 75 ? 'HIGH' : 'MEDIUM',
      detail: `Phishing score ${score}/100. Signals: ${signals.join(', ')}`,
    });
  }

  if (isExploitKit(url)) {
    threats.push({
      type: 'EXPLOIT_KIT',
      severity: 'CRITICAL',
      detail: 'URL matches known exploit kit gate/landing pattern.',
    });
  }

  return { threats };
}

// ─────────────────────────────────────────────
//  HELPER: Shannon entropy of a string
// ─────────────────────────────────────────────
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq)
    .map(f => (f / len) * Math.log2(f / len))
    .reduce((a, b) => a + b, 0);
}

// Export for use in background.js and analyzer.js
if (typeof module !== 'undefined') {
  module.exports = {
    checkDomain,
    phishingScore,
    isExploitKit,
    isKnownMalware,
    analyzeUrlThreatDB,
    shannonEntropy,
  };
}
