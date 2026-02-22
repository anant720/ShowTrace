

(() => {
    'use strict';

    const $ = (id) => document.getElementById(id);

    const els = {
        version: $('version'),
        protocol: $('protocol'),
        hostname: $('hostname'),
        riskCard: $('riskCard'),
        ringFill: $('ringFill'),
        scoreNumber: $('scoreNumber'),
        levelBadge: $('levelBadge'),
        reasonsList: $('reasonsList'),
        sigProtocol: $('sigProtocol'),
        sigForms: $('sigForms'),
        sigLogin: $('sigLogin'),
        sigSource: $('sigSource'),
        statusDot: $('statusDot'),
        statusText: $('statusText'),
    };

    const RING_CIRCUMFERENCE = 2 * Math.PI * 52;

    async function init() {

        const manifest = chrome.runtime.getManifest();
        els.version.textContent = `v${manifest.version}`;


        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
            setError('No active tab detected');
            return;
        }


        chrome.runtime.sendMessage(
            { type: 'ST_GET_RISK', tabId: tab.id },
            (data) => {
                if (chrome.runtime.lastError) {
                    setError('Extension error');
                    return;
                }

                if (!data) {
                    setScanning(tab);
                    return;
                }

                renderRiskData(data);
            }
        );
    }


    function renderRiskData(data) {
        const container = document.querySelector('.st-container');
        const riskLevel = data.risk_level || 'unknown';
        const riskScore = typeof data.risk_score === 'number' ? data.risk_score : 0;


        container.setAttribute('data-risk', riskLevel);


        if (data.domain) {
            const domain = data.domain;
            els.protocol.textContent = domain.protocol?.toUpperCase() || '—';
            els.protocol.className = `st-protocol ${domain.isHTTPS ? 'secure' : 'insecure'}`;
            els.hostname.textContent = domain.hostname || 'Unknown';
        } else {
            els.hostname.textContent = data.hostname || 'Unknown';
            els.protocol.textContent = '—';
        }


        const offset = RING_CIRCUMFERENCE - (riskScore / 100) * RING_CIRCUMFERENCE;
        els.ringFill.style.strokeDashoffset = offset;
        els.scoreNumber.textContent = riskScore || 0;

        // Risk level badge
        const levelLabels = { low: 'LOW RISK', medium: 'MEDIUM RISK', high: 'HIGH RISK' };
        els.levelBadge.textContent = levelLabels[riskLevel] || 'UNKNOWN';

        // Reasons list
        const reasons = data.reasons || [];
        if (reasons.length > 0) {
            els.reasonsList.innerHTML = reasons
                .map(r => `<li>${escapeHTML(r)}</li>`)
                .join('');
        } else {
            els.reasonsList.innerHTML = '<li class="st-reason-empty">No threats detected</li>';
        }

        // Signal summary grid
        if (data.domain || data.forms) {
            const domain = data.domain || {};
            const forms = data.forms || {};

            els.sigProtocol.textContent = domain.isHTTPS ? 'HTTPS' : 'HTTP';
            els.sigProtocol.style.color = domain.isHTTPS
                ? 'var(--st-green)' : 'var(--st-red)';

            els.sigForms.textContent = forms.formCount ?? '—';
            els.sigLogin.textContent = forms.hasLoginForm ? 'YES' : 'NO';
            els.sigLogin.style.color = forms.hasLoginForm
                ? 'var(--st-amber)' : 'var(--st-text-primary)';
        }

        // Source indicator
        els.sigSource.textContent = data.source === 'backend' ? 'API' : 'LOCAL';

        // Status footer
        if (data.source === 'backend') {
            els.statusDot.className = 'st-status-dot online';
            els.statusText.textContent = 'Connected to ShadowTrace API';
        } else {
            els.statusDot.className = 'st-status-dot offline';
            els.statusText.textContent = 'Local analysis (API offline)';
        }
    }

    // ── Scanning State ──────────────────────────────────────────────
    function setScanning(tab) {
        const container = document.querySelector('.st-container');
        container.setAttribute('data-state', 'scanning');
        try {
            const url = new URL(tab.url);
            els.hostname.textContent = url.hostname;
            els.protocol.textContent = url.protocol.replace(':', '').toUpperCase();
            els.protocol.className = `st-protocol ${url.protocol === 'https:' ? 'secure' : 'insecure'}`;
        } catch {
            els.hostname.textContent = 'Unknown page';
        }

        els.scoreNumber.textContent = '—';
        els.levelBadge.textContent = 'SCANNING';
        els.statusDot.className = 'st-status-dot';
        els.statusText.textContent = 'Waiting for analysis...';
    }

    // ── Error State ─────────────────────────────────────────────────
    function setError(message) {
        els.hostname.textContent = 'Error';
        els.scoreNumber.textContent = '!';
        els.levelBadge.textContent = 'ERROR';
        els.statusText.textContent = message;
    }

    // ── Utility ─────────────────────────────────────────────────────
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Run
    init();
})();
