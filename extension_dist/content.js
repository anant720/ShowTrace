(() => {
    'use strict';

    console.log('[ShadowTrace] Content script active');

    let behavior = {
        externalFetchDetected: false,
        externalXHRDetected: false,
        suspiciousSubmissions: [],
        pasteEvents: [],
        keyloggerDetected: false,
        unnaturalInputSpeed: false
    };
    let scanTimeout = null;
    let observer = null;

    // ── Inject in-page script (runs in page context) ─────────────────
    function inject() {
        try {
            const s = document.createElement('script');
            s.src = chrome.runtime.getURL('inject.js');
            s.onload = () => s.remove();
            (document.head || document.documentElement).appendChild(s);
            console.log('[ShadowTrace] Core protection injected');
        } catch (err) {
            console.error('[ShadowTrace] Injection failed:', err);
        }
    }

    // ── Receive data from injected page-context script ───────────────
    window.addEventListener('message', e => {
        if (e.source !== window || !e.data || e.data.type !== 'ST_INJECT_DATA') return;
        const p = e.data.payload;

        if (p.kind === 'external_fetch') {
            behavior.externalFetchDetected = true;
        } else if (p.kind === 'external_xhr') {
            behavior.externalXHRDetected = true;
        } else if (p.kind === 'credential_bearing_request') {
            console.warn('[ShadowTrace] Suspicious submission detected');
            behavior.suspiciousSubmissions.push({
                type: 'credential_bearing',
                destination: p.destination,
                method: p.method,
                timestamp: p.timestamp
            });
        }
    });

    // ── Behavioral fingerprinting ─────────────────────────────────────
    document.addEventListener('paste', e => {
        const target = e.target;
        if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
            try {
                const text = e.clipboardData.getData('text');
                behavior.pasteEvents.push({
                    length: text.length,
                    timestamp: new Date().toISOString(),
                    isPassword: target.type === 'password'
                });
            } catch (_) { }
        }
    }, true);

    let lastKeyPress = 0;
    document.addEventListener('keydown', () => {
        const now = Date.now();
        if (lastKeyPress && (now - lastKeyPress < 20)) {
            behavior.unnaturalInputSpeed = true;
        }
        lastKeyPress = now;
    }, true);

    // ── Core scan functions ───────────────────────────────────────────
    async function performScan() {
        try {
            if (typeof STSignals === 'undefined') {
                console.warn('[ShadowTrace] STSignals not loaded yet, skipping scan');
                return;
            }

            const domain = STSignals.extractDomainSignals(window.location.href);
            const forms = STSignals.scanForLoginForms();

            console.log(`[ShadowTrace] Scanning: ${domain.hostname}`);

            chrome.runtime.sendMessage({
                type: 'ST_SIGNAL_REPORT',
                payload: STSignals.buildPayload(domain, forms, behavior)
            });
        } catch (err) {
            console.error('[ShadowTrace] Scan error:', err);
        }
    }

    function triggerScan(delay = 1000) {
        clearTimeout(scanTimeout);
        scanTimeout = setTimeout(performScan, delay);
    }

    function setupObserver() {
        if (observer) observer.disconnect();
        observer = new MutationObserver(() => triggerScan(1500));
        if (document.body) {
            observer.observe(document.body, { childList: true, subtree: true });
        }
    }

    // ── Manual scan trigger from popup ───────────────────────────────
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (msg.type === 'ST_MANUAL_SCAN') {
            console.log('[ShadowTrace] Manual scan triggered');
            inject();
            // Wait a bit for inject.js to load, then scan
            setTimeout(() => {
                performScan().then(() => sendResponse({ status: 'ok' }));
            }, 300);
            return true;
        } else if (msg.type === 'ST_UPDATE_POLICY') {
            window.postMessage({ type: 'ST_SET_POLICY', policy: msg.policy }, '*');
        }
    });

    // ── Boot sequence ─────────────────────────────────────────────────
    inject();           // Inject page-context script immediately
    triggerScan(800);   // Auto-scan after 800ms (wait for DOM to settle)
    setupObserver();    // Watch for DOM changes (SPAs, navigation)

    console.log('[ShadowTrace] Real-time protection active.');
})();
