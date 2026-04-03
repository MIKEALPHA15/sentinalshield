# 🛡️ SentinelShield — Chrome Extension

**Advanced Browser Threat Detection & APT Defense Engine**  
Manifest V3 · Privacy-First · Zero Telemetry · MITRE ATT&CK Aligned

---

## 📦 Installation (Developer / Unpacked Mode)

1. Clone or extract this project folder.
2. Open Chrome → `chrome://extensions/`
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** → select the `SentinelShield/` folder.
5. The shield icon appears in your Chrome toolbar. Click it to open the dashboard.

> **Icons:** Place `icon16.png`, `icon48.png`, `icon128.png` in the `icons/` folder.  
> Any 16×16, 48×48, 128×128 PNG files will work during development.

---

## 🏗️ Architecture Overview

```
SentinelShield/
├── manifest.json          # MV3 config, permissions, CSP
├── background.js          # Service Worker — core detection engine
├── content.js             # Page-level behavioral monitor (runs in all frames)
├── popup.html / popup.js  # Dark HUD threat dashboard
├── blocked.html           # Hard-block warning interstitial
├── rules.json             # Declarative Net Request blocklist (20 rules)
└── utils/
    ├── threatDB.js        # Local threat intel: malicious domains, IPs, phishing signals
    └── analyzer.js        # Heuristic + signature engine: XSS, skimmers, obfuscation
```

### Data Flow

```
Page loads
    │
    ├─ background.js ← webNavigation.onCommitted
    │   ├─ URL → threatDB.analyzeUrl()   (domain check, phishing score, EK fingerprint)
    │   ├─ URL → analyzer.analyzeUrl()   (reflected XSS, open redirect, JSONP)
    │   └─ Score accumulated → broadcastState() → popup.js
    │
    ├─ content.js runs at document_start
    │   ├─ Hooks: eval, Function, document.cookie, Canvas, AudioContext, WebRTC, fetch, XHR, WebSocket, sendBeacon
    │   ├─ DOM MutationObserver: injected scripts, iframes, hidden fields
    │   ├─ Form security audit on DOMContentLoaded
    │   └─ Sends RUNTIME_FLAGS + SCRIPT_CONTENT + BLOCKED_REQUEST → background.js
    │
    └─ background.js ← content.js messages
        ├─ analyzeRuntimeFlags() → compositeScore()
        ├─ analyzeContent() on inline scripts
        └─ Dynamic DNR rules for detected C2 domains
```

---

## 🎯 Threat Model & MITRE ATT&CK Coverage

| Threat Category | Technique | MITRE ID | Severity | Detection Method |
|---|---|---|---|---|
| **C2 Callback** | Web Protocols C2 | T1071.001 | 🔴 CRITICAL | Domain reputation DB + beacon interval analysis |
| **DNS Tunneling** | DNS C2 | T1071.004 | 🔴 CRITICAL | DoH pattern matching, known tunnel domains |
| **Phishing** | Spearphishing Link | T1566.002 | 🔴 HIGH | URL entropy, brand impersonation, TLD analysis |
| **XSS (Reflected)** | Drive-by Compromise | T1189 | 🟠 HIGH | URL payload pattern matching |
| **XSS (DOM)** | DOM Manipulation | T1059.007 | 🟠 HIGH | DOM MutationObserver + script content scan |
| **Script Injection** | Command and Scripting | T1059.007 | 🟠 HIGH | Dynamic `<script>` tag detection |
| **Prototype Pollution** | Exploit Public-Facing App | T1190 | 🟠 HIGH | `__proto__` assignment hook |
| **Credential Harvesting** | Input Capture | T1056.003 | 🔴 CRITICAL | Password-on-HTTP detection, form analysis |
| **Session Hijacking** | Steal Web Session Cookie | T1539 | 🟠 HIGH | `document.cookie` access frequency hook |
| **Clickjacking** | UI Redressing | T1185 | 🟠 HIGH | Iframe overlay geometry analysis |
| **BitB Attack** | Phishing via Service | T1566 | 🟠 HIGH | Cross-origin iframe + auth URL pattern |
| **Canvas Fingerprint** | Browser Fingerprinting | T1592 | 🟡 MEDIUM | `toDataURL` / `getImageData` hook |
| **AudioContext FP** | Browser Fingerprinting | T1592 | 🟡 MEDIUM | `AudioContext` constructor proxy |
| **WebRTC IP Leak** | Network Reconnaissance | T1590 | 🟡 MEDIUM | `RTCPeerConnection` proxy |
| **Obfuscated JS** | Obfuscated Files | T1027 | 🟠 HIGH | Packer/base64/charcode pattern matching |
| **Magecart Skimmer** | Input Capture — Web | T1056 | 🔴 CRITICAL | Skimmer signature + sendBeacon exfil block |
| **SRI Violation** | Supply Chain Compromise | T1195 | 🟠 HIGH | External script without `integrity` attribute |
| **Exploit Kit** | Drive-by Compromise | T1189 | 🔴 CRITICAL | URL path/query pattern fingerprinting |
| **Heap Spray** | Exploitation | T1203 | 🔴 CRITICAL | Large array allocation + NOP sled patterns |
| **Open Redirect** | Phishing Support | T1566 | 🟡 MEDIUM | Redirect parameter detection in URLs |
| **JSONP Abuse** | Exfiltration | T1567 | 🟡 LOW | `?callback=` parameter detection |
| **Redirect Chain** | Defense Evasion | T1036 | 🟡 MEDIUM | Navigation counter in background.js |
| **External Beacon** | Exfiltration over C2 | T1041 | 🟠 HIGH | Cross-origin POST fetch/XHR interception |
| **Data URI Abuse** | Phishing Delivery | T1566 | 🟠 HIGH | `data:` URL in navigation |

---

## 🔢 Threat Scoring

| Score Range | Severity | Action |
|---|---|---|
| 0–14 | ✅ SAFE | No action |
| 15–39 | 🟡 LOW | Logged only |
| 40–64 | 🟡 MEDIUM | Popup warning |
| 65–84 | 🟠 HIGH | Popup alert + badge |
| 85–100 | 🔴 CRITICAL | Hard block (Strict Mode) |

Score composition: `URL×20% + Content×35% + Runtime×45%`

---

## ⚙️ Controls

| Button | Function |
|---|---|
| **Shield ✓/✗** | Enable or disable all detection globally |
| **Strict** | Auto-block pages scoring ≥85 (hard redirect to blocked.html) |
| **Report** | Save current page threat report to `chrome.storage.local` |

---

## 🔒 Security & Privacy

- **Manifest V3 compliant** — no remote code execution, no `eval()` in extension context
- **Strict CSP** on all extension pages: `default-src 'self'`
- **All storage** via `chrome.storage.local` only — no external servers
- **Zero telemetry** by default — no data leaves the browser
- **Minimal permissions**: `activeTab`, `declarativeNetRequest`, `storage`, `webNavigation`, `scripting`, `tabs`
- Threat reports are stored locally and never transmitted

---

## 🔄 Updating the Threat Intelligence DB

1. Edit `utils/threatDB.js` → add entries to `MALICIOUS_DOMAINS` Map
2. Edit `rules.json` → add new DNR rules (increment `id` sequentially)
3. Reload the extension at `chrome://extensions/`

---

## 🧪 Testing

To verify detection is working:

1. Navigate to a URL containing `?test=<script>alert(1)</script>` → should trigger XSS flag
2. Load a page over `http://` with a `<input type="password">` → should trigger INSECURE_FORM
3. Visit any domain in `MALICIOUS_DOMAINS` → should trigger CRITICAL immediately
4. Enable **Strict Mode** and visit a flagged URL → should redirect to `blocked.html`

---

## 📋 Permissions Rationale

| Permission | Reason |
|---|---|
| `activeTab` | Read current tab URL for analysis |
| `declarativeNetRequest` | Block requests matching threat rules |
| `declarativeNetRequestFeedback` | Know which rules fired |
| `storage` | Persist settings and threat reports locally |
| `webNavigation` | Detect navigations, redirects, and frame loads |
| `scripting` | Inject content.js into pages |
| `tabs` | Get active tab info for popup state |

---

## 📄 License

MIT License — for educational and defensive security research purposes.  
Do not deploy against systems without authorization.

---

*Built for the SentinelShield cybersecurity project. MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*
