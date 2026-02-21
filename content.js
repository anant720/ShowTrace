(() => {
    'use strict';
    let behavior = { externalFetchDetected: false, externalXHRDetected: false, suspiciousSubmissions: [] };
    let timeout = null;

    function inject() {
        const s = document.createElement('script');
        s.src = chrome.runtime.getURL('inject.js');
        s.onload = () => s.remove();
        (document.head || document.documentElement).appendChild(s);
    }

    window.addEventListener('message', e => {
        if (e.source !== window || !e.data || e.data.type !== 'ST_INJECT_DATA') return;
        const p = e.data.payload;
        if (p.kind === 'credential_bearing_request') {
            behavior.suspiciousSubmissions.push({ type: 'credential_bearing', destination: p.destination });
            report();
        }
    });

    function report() {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            const domain = STSignals.extractDomainSignals(window.location.href);
            const forms = STSignals.scanForLoginForms();
            chrome.runtime.sendMessage({
                type: 'ST_SIGNAL_REPORT',
                payload: STSignals.buildPayload(domain, forms, behavior)
            });
        }, 500);
    }

    inject();
    setTimeout(report, 1000);
})();
