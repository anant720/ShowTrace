(() => {
    'use strict';

    console.log('[ShadowTrace] Content script active');

    let behavior = { externalFetchDetected: false, externalXHRDetected: false, suspiciousSubmissions: [] };
    let scanTimeout = null;
    let observer = null;

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

    window.addEventListener('message', e => {
        if (e.source !== window || !e.data || e.data.type !== 'ST_INJECT_DATA') return;
        const p = e.data.payload;

        if (p.kind === 'external_fetch') {
            behavior.externalFetchDetected = true;
            triggerScan(1000);
        } else if (p.kind === 'external_xhr') {
            behavior.externalXHRDetected = true;
            triggerScan(1000);
        } else if (p.kind === 'credential_bearing_request') {
            console.warn('[ShadowTrace] Suspicious submission detected');
            behavior.suspiciousSubmissions.push({
                type: 'credential_bearing',
                destination: p.destination,
                method: p.method,
                timestamp: p.timestamp
            });
            triggerScan(0);
        }
    });

    function triggerScan(delay = 1000) {
        clearTimeout(scanTimeout);
        scanTimeout = setTimeout(performScan, delay);
    }

    async function performScan() {
        try {
            if (typeof STSignals === 'undefined') {
                console.error('[ShadowTrace] Signal engine missing');
                return;
            }

            const domain = STSignals.extractDomainSignals(window.location.href);
            const forms = STSignals.scanForLoginForms();

            console.log(`[ShadowTrace] Scanning ${domain.hostname}...`);

            chrome.runtime.sendMessage({
                type: 'ST_SIGNAL_REPORT',
                payload: STSignals.buildPayload(domain, forms, behavior)
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error('[ShadowTrace] Comm error:', chrome.runtime.lastError.message);
                }
            });
        } catch (err) {
            console.error('[ShadowTrace] Scan error:', err);
        }
    }

    // React to page changes (SPAs, dynamic forms)
    function setupObserver() {
        if (observer) observer.disconnect();
        observer = new MutationObserver((mutations) => {
            const significant = mutations.some(m => m.addedNodes.length > 0);
            if (significant) triggerScan(1500); // Wait for content to settle
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }

    // Start
    inject();
    triggerScan(1000); // Initial scan

    if (document.body) setupObserver();
    else document.addEventListener('DOMContentLoaded', setupObserver);

})();
