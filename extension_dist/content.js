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
    async function performScan(retryCount = 0) {
        try {
            if (typeof STSignals === 'undefined') {
                if (retryCount < 10) {
                    console.warn('[ShadowTrace] STSignals not ready, retrying... (' + (retryCount + 1) + ')');
                    setTimeout(() => performScan(retryCount + 1), 200);
                } else {
                    console.error('[ShadowTrace] STSignals failed to load after 10 attempts');
                }
                return;
            }

            const domain = STSignals.extractDomainSignals(window.location.href);
            const forms = STSignals.scanForLoginForms();
            const payload = STSignals.buildPayload(domain, forms, behavior);

            console.log(`[ShadowTrace] Scanning: ${domain.hostname}`);

            chrome.runtime.sendMessage({
                type: 'ST_SIGNAL_REPORT',
                payload: payload
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
        } else {
            // Wait for body to be available if running at document_start
            const bodyCheck = setInterval(() => {
                if (document.body) {
                    clearInterval(bodyCheck);
                    observer.observe(document.body, { childList: true, subtree: true });
                }
            }, 100);
            // Safety timeout after 5s
            setTimeout(() => clearInterval(bodyCheck), 5000);
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
    inject();           // Inject page-context script immediately (critical at document_start)
    setupObserver();    // Start watching early

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => triggerScan(600));
    } else {
        triggerScan(800);
    }

    console.log('[ShadowTrace] Real-time protection active.');
})();
