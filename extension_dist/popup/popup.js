

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
        networkList: $('networkList'),
        openMonitor: $('openMonitor'),
        scanButton: $('scanButton'),
        protectionToggle: $('protectionToggle'),
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

        // ── Phase 1: Ready State ──────────────────────────
        setReady(tab);

        // ── Phase 2: Check Permissions & Session ───────────
        await updateProtectionState();

        chrome.runtime.sendMessage(
            { type: 'ST_GET_RISK', tabId: tab.id },
            async (data) => {
                if (data) {
                    renderRiskData(data);
                }
                startNetworkPoller(tab.id);
            }
        );
    }

    async function updateProtectionState() {
        // <all_urls> is now in host_permissions — always active
        if (els.protectionToggle) {
            els.protectionToggle.checked = true;
            els.protectionToggle.disabled = true;
        }
    }

    async function handleProtectionToggle() {
        // No-op: protection is always active since <all_urls> is a fixed host permission
        await updateProtectionState();
    }

    async function handleManualScan() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) return;

        setScanning(tab);

        // Attempt to message existing script
        chrome.tabs.sendMessage(tab.id, { type: 'ST_MANUAL_SCAN' }, async (response) => {
            if (chrome.runtime.lastError) {
                console.log('Content script not found, injecting on-demand...');

                try {
                    // Inject dependencies first, then content script
                    await chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        files: ['utils/constants.js', 'utils/signals.js', 'content.js']
                    });

                    // Wait a moment for script to initialize its listeners
                    setTimeout(() => {
                        chrome.tabs.sendMessage(tab.id, { type: 'ST_MANUAL_SCAN' }, (resp) => {
                            if (chrome.runtime.lastError) {
                                setError('Failed to initialize scan engine.');
                            } else {
                                pollForResult(tab.id);
                            }
                        });
                    }, 200);
                } catch (err) {
                    console.error('Injection failed:', err);
                    setError('Refused to scan this page (Restricted site).');
                }
            } else {
                pollForResult(tab.id);
            }
        });
    }

    function pollForResult(tabId, attempts = 0) {
        if (attempts > 10) {
            setError('Analysis timed out. Try refreshing the page.');
            return;
        }

        setTimeout(() => {
            chrome.runtime.sendMessage({ type: 'ST_GET_RISK', tabId: tabId }, (data) => {
                // We consider data valid if it has a risk_level set (meaning handleSignalReport finished)
                if (data && data.risk_level) {
                    renderRiskData(data);
                } else {
                    pollForResult(tabId, attempts + 1);
                }
            });
        }, 1000);
    }

    function startNetworkPoller(tabId) {
        const poll = () => {
            chrome.runtime.sendMessage({ type: 'ST_GET_RISK', tabId: tabId }, (data) => {
                if (data && data.requests) {
                    renderNetworkRequests(data.requests);
                }
            });
        };
        poll();
        setInterval(poll, 1500);
    }

    function renderRiskData(data) {
        const container = document.querySelector('.st-container');
        const riskLevel = data.risk_level || 'unknown';
        const riskScore = typeof data.risk_score === 'number' ? data.risk_score : 0;

        // Exit scanning state
        container.removeAttribute('data-state');
        container.setAttribute('data-risk', riskLevel);

        if ($('scoreLabel')) $('scoreLabel').textContent = 'RISK SCORE';
        if ($('scoreLabel')) $('scoreLabel').style.animation = 'none';


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

        if (data.requests) renderNetworkRequests(data.requests);

        if (data.timestamp) {
            const time = formatTime(data.timestamp);
            els.statusText.textContent = `${els.statusText.textContent} • Last Scan: ${time}`;
        }
    }

    function renderNetworkRequests(requests) {
        if (!els.networkList) return;

        if (!requests || requests.length === 0) {
            els.networkList.innerHTML = '<div class="st-network-empty">Monitoring active tab traffic...</div>';
            return;
        }

        const html = requests.map(req => {
            const shortUrl = req.url.split('?')[0];
            const time = formatTime(req.timestamp);
            return `
                <div class="st-network-item">
                    <span class="st-method ${req.method}">${req.method}</span>
                    <span class="st-url" title="${req.url}">${shortUrl}</span>
                    <span style="font-size: 8.5px; opacity: 0.5; font-family: var(--st-font-mono)">${time}</span>
                </div>
            `;
        }).join('');

        els.networkList.innerHTML = html;
    }

    // ── Ready State ───────────────────────────────────────────────
    function setReady(tab) {
        const container = document.querySelector('.st-container');
        container.removeAttribute('data-state');
        try {
            const url = new URL(tab.url);
            els.hostname.textContent = url.hostname;
            els.protocol.textContent = url.protocol.replace(':', '').toUpperCase();
            els.protocol.className = `st-protocol ${url.protocol === 'https:' ? 'secure' : 'insecure'}`;
        } catch {
            els.hostname.textContent = 'Welcome to ShadowTrace';
        }

        els.levelBadge.textContent = 'READY TO SCAN';
        els.statusText.textContent = 'Click below to analyze this page';
    }

    // ── Scanning State ──────────────────────────────────────────────
    function setScanning(tab) {
        const container = document.querySelector('.st-container');
        container.setAttribute('data-state', 'scanning');

        els.scoreNumber.textContent = '—';
        els.scoreLabel.textContent = 'ANALYZING';
        els.levelBadge.textContent = 'NEURAL SCAN ACTIVE';
        els.statusDot.className = 'st-status-dot';
        els.statusText.textContent = 'Performing forensic analysis...';
    }

    // ── Error State ─────────────────────────────────────────────────
    function setError(message) {
        els.hostname.textContent = 'Error';
        els.scoreNumber.textContent = '!';
        els.levelBadge.textContent = 'ERROR';
        els.statusText.textContent = message;
    }

    function formatTime(ts) {
        if (!ts) return '';
        const d = new Date(ts);
        const h = String(d.getHours()).padStart(2, '0');
        const m = String(d.getMinutes()).padStart(2, '0');
        const s = String(d.getSeconds()).padStart(2, '0');
        const ms = String(d.getMilliseconds()).padStart(3, '0');
        return `${h}:${m}:${s}.${ms}`;
    }

    // Utility
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Event Listeners
    if (els.openMonitor) {
        els.openMonitor.addEventListener('click', async () => {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const url = chrome.runtime.getURL(`monitor/monitor.html?tabId=${tab?.id}`);
            chrome.tabs.create({ url });
        });
    }

    if (els.scanButton) {
        els.scanButton.addEventListener('click', handleManualScan);
    }

    if (els.protectionToggle) {
        els.protectionToggle.addEventListener('change', handleProtectionToggle);
    }

    // ── Org Key Management ────────────────────────────────────────────
    function initOrgKey() {
        chrome.runtime.sendMessage({ type: 'ST_GET_ORG_INFO' }, (resp) => {
            if (resp && resp.memberKey && resp.orgInfo) {
                showOrgActive(resp.orgInfo);
            } else {
                showOrgSetup();
            }
        });

        const activateBtn = $('activateKeyBtn');
        if (activateBtn) {
            activateBtn.addEventListener('click', () => {
                const key = $('orgKeyInput')?.value?.trim();
                const email = $('orgEmailInput')?.value?.trim();
                if (!key) {
                    $('keyStatus').textContent = '✗ Please paste your org key';
                    $('keyStatus').style.color = '#ef4444';
                    return;
                }
                if (!email) {
                    $('keyStatus').textContent = '✗ Please enter your invited email';
                    $('keyStatus').style.color = '#ef4444';
                    return;
                }
                $('keyStatus').textContent = 'Validating...';
                $('keyStatus').style.color = '#94a3b8';
                chrome.runtime.sendMessage({ type: 'ST_ACTIVATE_KEY', key, email }, (resp) => {
                    if (resp?.success) {
                        $('keyStatus').textContent = '';
                        showOrgActive({ org_name: resp.org_name, email: resp.email });
                    } else {
                        $('keyStatus').textContent = `✗ ${resp?.error || 'Invalid key'}`;
                        $('keyStatus').style.color = '#ef4444';
                    }
                });
            });
        }

        const clearBtn = $('clearKeyBtn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                chrome.storage.local.remove(['st_member_key', 'st_org_info'], () => {
                    showOrgSetup();
                });
            });
        }
    }

    function showOrgActive(info) {
        const active = $('orgActiveView');
        const setup = $('orgSetupView');
        if (active) { active.style.display = 'block'; }
        if (setup) { setup.style.display = 'none'; }
        if ($('orgNameDisplay')) $('orgNameDisplay').textContent = info.org_name || '—';
        if ($('orgEmailDisplay')) $('orgEmailDisplay').textContent = info.email || '—';
    }

    function showOrgSetup() {
        const active = $('orgActiveView');
        const setup = $('orgSetupView');
        if (active) { active.style.display = 'none'; }
        if (setup) { setup.style.display = 'block'; }
        if ($('orgKeyInput')) $('orgKeyInput').value = '';
        if ($('keyStatus')) $('keyStatus').textContent = '';
    }

    // Run
    init();
    initOrgKey();
})();
