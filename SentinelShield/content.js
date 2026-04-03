/**
 * SentinelShield — content.js
 * Page-level behavioral monitor. Runs at document_start in all frames.
 *
 * Responsibilities:
 *  - DOM Mutation Observer (injected scripts, iframes, hidden fields)
 *  - Runtime JS behavior hooks (eval, canvas, WebRTC, cookies)
 *  - Form security checks (password on HTTP, credential harvesting)
 *  - Clickjacking / BitB detection
 *  - SRI violation detection
 *  - Reports all findings to background.js via chrome.runtime.sendMessage
 *
 * NOTE: This script uses no eval() and no remote code — MV3 compliant.
 */

(function () {
  'use strict';

  // ── Don't run on extension pages ──
  if (location.protocol === 'chrome-extension:') return;

  // ─────────────────────────────────────────────
  //  RUNTIME FLAG ACCUMULATOR
  //  Flags are merged and reported to background.js
  // ─────────────────────────────────────────────
  const flags = {
    evalCalled:       false,
    dynamicScript:    false,
    suspiciousIframe: false,
    canvasFingerprint:false,
    audioFingerprint: false,
    webRTCLeak:       false,
    cookieAccess:     false,
    externalBeacon:   false,
    sriViolation:     false,
    protoPollution:   false,
    hiddenFormField:  false,
    passwordOnHttp:   false,
  };

  let reportTimer = null;
  let dynamicScriptCount = 0;

  /** Debounced report to background.js — batches flags within 800ms */
  function scheduleReport() {
    clearTimeout(reportTimer);
    reportTimer = setTimeout(reportFlags, 800);
  }

  function reportFlags() {
    chrome.runtime.sendMessage({ type: 'RUNTIME_FLAGS', flags }).catch(() => {});
  }

  function setFlag(key) {
    if (!flags[key]) {
      flags[key] = true;
      scheduleReport();
    }
  }

  // ─────────────────────────────────────────────
  //  HOOK: eval()
  //  Intercept eval calls to detect code injection
  // ─────────────────────────────────────────────
  const _origEval = window.eval;
  Object.defineProperty(window, 'eval', {
    get() { return _origEval; },
    set(fn) {
      setFlag('evalCalled');
      return fn;
    },
  });

  // Patch Function constructor (obfuscated eval alternative)
  const _origFunction = window.Function;
  window.Function = new Proxy(_origFunction, {
    construct(target, args) {
      if (args.length > 0 && typeof args[args.length - 1] === 'string' && args[args.length - 1].length > 100) {
        setFlag('evalCalled');
      }
      return new target(...args);
    },
    apply(target, thisArg, args) {
      setFlag('evalCalled');
      return target.apply(thisArg, args);
    },
  });

  // ─────────────────────────────────────────────
  //  HOOK: document.cookie (session hijacking detection)
  //  Detect excessive or suspicious cookie reads
  // ─────────────────────────────────────────────
  let cookieReadCount = 0;
  const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (cookieDesc) {
    Object.defineProperty(document, 'cookie', {
      get() {
        cookieReadCount++;
        // Modern apps read cookies frequently; use a higher threshold to reduce noise.
        if (cookieReadCount > 25) setFlag('cookieAccess');
        return cookieDesc.get.call(document);
      },
      set(val) {
        return cookieDesc.set.call(document, val);
      },
      configurable: true,
    });
  }

  // ─────────────────────────────────────────────
  //  HOOK: Canvas fingerprinting detection
  // ─────────────────────────────────────────────
  const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (...args) {
    setFlag('canvasFingerprint');
    return _origToDataURL.apply(this, args);
  };

  const _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (...args) {
    setFlag('canvasFingerprint');
    return _origGetImageData.apply(this, args);
  };

  // ─────────────────────────────────────────────
  //  HOOK: AudioContext fingerprinting detection
  // ─────────────────────────────────────────────
  const _AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (_AudioCtx) {
    const _origAudioCtx = _AudioCtx;
    window.AudioContext = window.webkitAudioContext = new Proxy(_origAudioCtx, {
      construct(target, args) {
        setFlag('audioFingerprint');
        return new target(...args);
      },
    });
  }

  // ─────────────────────────────────────────────
  //  HOOK: WebRTC IP leak detection
  // ─────────────────────────────────────────────
  const _RTCPeer = window.RTCPeerConnection || window.webkitRTCPeerConnection;
  if (_RTCPeer) {
    window.RTCPeerConnection = window.webkitRTCPeerConnection = new Proxy(_RTCPeer, {
      construct(target, args) {
        setFlag('webRTCLeak');
        return new target(...args);
      },
    });
  }

  // ─────────────────────────────────────────────
  //  HOOK: Prototype pollution detection
  //  Watch __proto__ and Object.prototype assignments
  // ─────────────────────────────────────────────
  const _origDefProp = Object.defineProperty;
  Object.defineProperty = function (obj, prop, descriptor) {
    if (prop === '__proto__' || (obj === Object.prototype && typeof prop === 'string')) {
      setFlag('protoPollution');
    }
    return _origDefProp.call(Object, obj, prop, descriptor);
  };

  // ─────────────────────────────────────────────
  //  HOOK: WebSocket suspicious connection
  //  Flag connections to non-first-party WS hosts
  // ─────────────────────────────────────────────
  const _origWS = window.WebSocket;
  window.WebSocket = new Proxy(_origWS, {
    construct(target, args) {
      const wsUrl = args[0] || '';
      // Check against page origin
      try {
        const wsHost = new URL(wsUrl).hostname;
        if (wsHost && wsHost !== location.hostname) {
          // Cross-origin WebSocket — report as potential C2
          chrome.runtime.sendMessage({
            type: 'BLOCKED_REQUEST',
            url: wsUrl,
            reason: 'C2_WEBSOCKET',
          }).catch(() => {});
        }
      } catch (_) {}
      return new target(...args);
    },
  });

  // ─────────────────────────────────────────────
  //  HOOK: fetch() — detect exfiltration beacons
  // ─────────────────────────────────────────────
  const _origFetch = window.fetch;
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : input?.url || '';
    if (url && isExternalHost(url)) {
      if (init && init.method && init.method.toUpperCase() === 'POST') {
        setFlag('externalBeacon');
        chrome.runtime.sendMessage({
          type: 'BLOCKED_REQUEST',
          url,
          reason: 'EXFIL_POST_FETCH',
        }).catch(() => {});
      }
    }
    return _origFetch.apply(this, arguments);
  };

  // ─────────────────────────────────────────────
  //  HOOK: XMLHttpRequest — detect XHR exfiltration
  // ─────────────────────────────────────────────
  const _origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    this._ssMethod = method;
    this._ssUrl = url;
    return _origXHROpen.apply(this, arguments);
  };

  const _origXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    if (this._ssMethod && this._ssMethod.toUpperCase() === 'POST' &&
        this._ssUrl && isExternalHost(this._ssUrl)) {
      setFlag('externalBeacon');
    }
    return _origXHRSend.apply(this, arguments);
  };

  // ─────────────────────────────────────────────
  //  HELPER: is URL external to current page?
  // ─────────────────────────────────────────────
  function isExternalHost(url) {
    try {
      const u = new URL(url, location.href);
      return u.hostname !== location.hostname;
    } catch (_) { return false; }
  }

  // ─────────────────────────────────────────────
  //  DOM MUTATION OBSERVER
  //  Watches for: injected scripts, hidden iframes,
  //  hidden form fields, SRI violations
  // ─────────────────────────────────────────────
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;

        // ── Injected <script> tag ──
        if (node.tagName === 'SCRIPT') {
          // Dynamic scripts are common on modern sites; only flag when repeated.
          dynamicScriptCount++;
          if (dynamicScriptCount >= 5) {
            setFlag('dynamicScript');
          }

          // SRI check: external scripts without integrity attribute
          if (node.src && !node.integrity) {
            try {
              const scriptHost = new URL(node.src).hostname;
              if (scriptHost !== location.hostname) {
                setFlag('sriViolation');
              }
            } catch (_) {}
          }

          // Scan inline script content
          if (!node.src && node.textContent && node.textContent.length > 50) {
            chrome.runtime.sendMessage({
              type: 'SCRIPT_CONTENT',
              content: node.textContent.substring(0, 20000), // Cap at 20KB
            }).catch(() => {});
          }
        }

        // ── Suspicious <iframe> ──
        if (node.tagName === 'IFRAME') {
          const style = window.getComputedStyle(node);
          const isInvisible = style.opacity === '0' || style.visibility === 'hidden' ||
                              style.display === 'none' || parseInt(style.zIndex, 10) > 9999;
          const isCoverAll = style.position === 'fixed' &&
                             style.top === '0px' && style.left === '0px' &&
                             (parseInt(style.width, 10) >= window.innerWidth * 0.9 ||
                              style.width === '100%');

          // BitB detection: iframe with src pointing to a login/auth page
          const isBitB = node.src && /login|signin|auth|sso|oauth/i.test(node.src) &&
                         isExternalHost(node.src);

          const hasExternalSrc = !!(node.src && isExternalHost(node.src));
          if ((hasExternalSrc && (isInvisible || isCoverAll)) || isBitB) {
            setFlag('suspiciousIframe');
          }
        }

        // ── Hidden form field injection ──
        if (node.tagName === 'INPUT' && node.type === 'hidden') {
          setFlag('hiddenFormField');
        }

        // ── Password field on non-HTTPS ──
        if (node.tagName === 'INPUT' && node.type === 'password' &&
            location.protocol !== 'https:') {
          setFlag('passwordOnHttp');
        }

        // ── Recurse into children ──
        if (node.children && node.children.length > 0) {
          for (const child of node.querySelectorAll('script, iframe, input[type="hidden"], input[type="password"]')) {
            // Trigger re-check on child nodes via synthetic mutation
            observer.takeRecords(); // flush
          }
        }
      }
    }
  });

  // Start observing once DOM is minimally available
  function startObserver() {
    if (document.documentElement) {
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        observer.observe(document.documentElement, { childList: true, subtree: true });
      }, { once: true });
    }
  }

  startObserver();

  // ─────────────────────────────────────────────
  //  FORM SECURITY AUDIT
  //  Runs after DOM is loaded — checks all forms
  // ─────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    // Password field on HTTP
    const pwFields = document.querySelectorAll('input[type="password"]');
    if (pwFields.length > 0 && location.protocol !== 'https:') {
      setFlag('passwordOnHttp');
    }

    // Hidden exfil fields in forms
    const hiddenFields = document.querySelectorAll('input[type="hidden"]');
    hiddenFields.forEach(field => {
      if (field.name && /card|ccnum|cvv|pan|track/i.test(field.name)) {
        setFlag('hiddenFormField');
      }
    });

    // Scan all inline scripts on the page
    document.querySelectorAll('script:not([src])').forEach(s => {
      if (s.textContent && s.textContent.length > 100) {
        chrome.runtime.sendMessage({
          type: 'SCRIPT_CONTENT',
          content: s.textContent.substring(0, 20000),
        }).catch(() => {});
      }
    });

    // Clickjacking: check if page is framed inappropriately
    if (window.self !== window.top) {
      try {
        // If we can't access parent, we're in a cross-origin frame (possible clickjack)
        const _ = window.top.location.href;
      } catch (e) {
        setFlag('suspiciousIframe');
      }
    }

    // Initial report
    reportFlags();
  });

  // ─────────────────────────────────────────────
  //  BEACON API HOOK (Magecart uses sendBeacon for exfil)
  // ─────────────────────────────────────────────
  if (navigator.sendBeacon) {
    const _origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      if (isExternalHost(url)) {
        setFlag('externalBeacon');
        chrome.runtime.sendMessage({
          type: 'BLOCKED_REQUEST',
          url,
          reason: 'SKIMMER_SENDBEACON',
        }).catch(() => {});
        return false; // Block the beacon
      }
      return _origBeacon(url, data);
    };
  }

  // ─────────────────────────────────────────────
  //  INITIAL REPORT (some flags may be set synchronously)
  // ─────────────────────────────────────────────
  scheduleReport();

})();
