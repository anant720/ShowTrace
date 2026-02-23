(() => {
    'use strict';

    function extractSensitiveData(req) {
        const sensitive = [];
        const body = (req.requestBody || '').toLowerCase();
        const headers = (req.requestHeaders || []);

        // Passwords & Credentials
        const credPatterns = ['pass', 'password', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'auth', 'bearer', 'session', 'sid', 'jwt'];

        // Check Body (Form or JSON)
        credPatterns.forEach(pattern => {
            if (body.includes(pattern)) {
                // Try to extract value from JSON or Form
                const match = body.match(new RegExp(`"${pattern}"\\s*:\\s*"([^"]+)"`)) ||
                    body.match(new RegExp(`${pattern}=([^&]+)`));
                if (match) sensitive.push({ type: 'CREDENTIAL', field: pattern, value: match[1] });
            }
        });

        // Check Headers (Auth / Cookies)
        headers.forEach(h => {
            const name = h.name.toLowerCase();
            const val = h.value.toLowerCase();

            // Authorization Headers
            if (name === 'authorization' || name === 'x-api-key' || name === 'x-auth-token') {
                sensitive.push({ type: 'AUTH_HEADER', field: h.name, value: h.value });
            }

            // Session Cookies
            if (name === 'cookie') {
                // More aggressive session cookie regex (matches common ones like connect.sid, PHPSESSID, etc.)
                const sessionPatterns = [
                    /(sess|session|sid|id|jwt|auth|token)=([^;]+)/gi,
                    /(phpsessid|jsessionid|aspsessionid|connect\.sid|laravel_session|sessionid)=([^;]+)/gi
                ];
                sessionPatterns.forEach(regex => {
                    const sessionMatches = h.value.match(regex);
                    if (sessionMatches) {
                        sessionMatches.forEach(m => sensitive.push({ type: 'SESSION_ID', field: 'Cookie', value: m }));
                    }
                });
            }
        });

        return sensitive;
    }

    const $ = (id) => document.getElementById(id);
    const body = $('requestBody');
    const tabInfo = $('tabInfo');
    const statCount = $('statCount');
    const statPost = $('statPost');
    const clearBtn = $('clearBtn');
    const inspector = $('inspector');
    const inspectorContent = $('inspectorContent');
    const closeInspector = $('closeInspector');

    let currentTabId = null;
    let allRequests = [];
    let selectedRequestId = null;

    async function init() {
        const urlParams = new URLSearchParams(window.location.search);
        const urlTabId = urlParams.get('tabId');

        if (urlTabId) {
            currentTabId = parseInt(urlTabId);
            chrome.tabs.get(currentTabId, (tab) => {
                if (chrome.runtime.lastError || !tab) {
                    tabInfo.textContent = `Target Tab ID: ${currentTabId} (Inactive)`;
                } else {
                    const url = new URL(tab.url);
                    tabInfo.textContent = `Active Tab: ${url.hostname}`;
                }
            });
        } else {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab) {
                currentTabId = tab.id;
                const url = new URL(tab.url);
                tabInfo.textContent = `Active Tab: ${url.hostname}`;
            }
        }

        pollRequests();
        setInterval(pollRequests, 1000);
    }

    async function pollRequests() {
        if (!currentTabId) return;

        chrome.runtime.sendMessage({ type: 'ST_GET_RISK', tabId: currentTabId }, (data) => {
            if (data && data.requests) {
                allRequests = data.requests;
                renderTable(data.requests);
                if (selectedRequestId) updateInspector();
            }
        });
    }

    function renderTable(requests) {
        if (!requests || requests.length === 0) {
            body.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 40px;">No traffic detected yet. Ensure the tab is active.</td></tr>';
            return;
        }

        statCount.textContent = requests.length;
        const postCount = requests.filter(r => r.method === 'POST').length;
        statPost.textContent = `${Math.round((postCount / requests.length) * 100)}%`;

        body.innerHTML = '';
        requests.forEach(req => {
            const time = formatTime(req.timestamp);
            const status = req.statusCode || (req.error ? 'FAILED' : 'PENDING');
            const statusClass = (status === 'FAILED' || status >= 400) ? 'error' : status >= 300 ? 'redirect' : 'success';
            const isSelected = req.id === selectedRequestId;

            // Format type for better readability
            let displayType = req.type.toUpperCase();
            if (displayType === 'XMLHTTPREQUEST') displayType = 'API/XHR';
            if (displayType === 'IMAGE') displayType = 'ASSET/IMG';
            if (displayType === 'SCRIPT') displayType = 'ASSET/JS';

            const tr = document.createElement('tr');
            if (isSelected) tr.classList.add('selected');
            tr.style.cursor = 'pointer';
            tr.innerHTML = `
                <td>${time}</td>
                <td><span class="m-method ${req.method}">${req.method}</span></td>
                <td class="m-type">${displayType}</td>
                <td class="m-url" title="${req.url}">${req.url}</td>
                <td style="font-weight: 700; font-size: 11px;">
                    <span class="m-status-pill ${statusClass}">${status}</span>
                </td>
            `;

            tr.addEventListener('click', () => {
                selectedRequestId = req.id;
                inspector.classList.add('open');
                renderTable(allRequests); // Refresh to show selection
                updateInspector(req);
            });

            body.appendChild(tr);
        });
    }

    function updateInspector(manualReq = null) {
        const req = manualReq || allRequests.find(r => String(r.id) === String(selectedRequestId));
        if (!req) {
            console.warn('[ShadowTrace] No request found for ID:', selectedRequestId);
            return;
        }

        console.log('[ShadowTrace] Inspecting request:', req.id, req.url);

        const statusClass = req.statusCode >= 400 ? 'error' : req.statusCode >= 300 ? 'redirect' : 'success';
        const safeReqHeaders = req.requestHeaders || [];
        const safeResHeaders = req.responseHeaders || [];
        const findings = extractSensitiveData(req);

        // Enterprise Security Findings (from Backend)
        const securityScore = req.security_score;
        const securityFindings = req.security_findings || [];

        let alertHtml = '';
        if (findings.length > 0) {
            alertHtml = `
                <div class="m-sensitive-alert">
                    <div class="m-alert-badge">⚠️ Sensitive Data Detected</div>
                    ${findings.map(f => `
                        <div class="m-alert-item">
                            <span class="m-alert-label">${f.field}:</span>
                            <span class="m-alert-value">${f.value}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        let securityHtml = '';
        if (securityScore !== undefined) {
            securityHtml = `
                <div class="m-security-score-banner">
                    <div class="m-score-circle">${Math.round(securityScore)}</div>
                    <div>
                        <div style="font-weight: 800; font-size: 14px; color: var(--m-text);">Security Posture Score</div>
                        <div style="font-size: 12px; color: var(--m-text-muted);">Passive configuration & vuln audit</div>
                    </div>
                </div>
            `;
        }

        if (securityFindings.length > 0) {
            securityHtml += `
                <div class="m-section-title">Vulnerability Findings</div>
                <div class="m-security-findings">
                    ${securityFindings.map(f => `
                        <div class="m-finding-card">
                            <div class="m-finding-header">
                                <span class="m-finding-title">${f.title}</span>
                                <span class="m-severity-tag ${f.severity}">${f.severity}</span>
                            </div>
                            <div class="m-finding-desc">${f.description}</div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        inspectorContent.innerHTML = `
            ${securityHtml}
            ${alertHtml}
            <div class="m-section-title">Request Status</div>
            <div class="m-status-pill ${statusClass}" style="margin-bottom: 20px;">STATUS ${req.statusCode || 'FAILED'} ${req.method}</div>
            
            <div class="m-section-title">Request URL</div>
            <div class="m-header-list" style="word-break: break-all; margin-bottom: 20px; color: #3b82f6;">${req.url}</div>

            <div class="m-section-title">Request Body (Payload)</div>
            <div class="m-header-list" style="background: rgba(16, 185, 129, 0.05); border-color: rgba(16, 185, 129, 0.2); color: #10b981;">
                <pre style="white-space: pre-wrap; word-break: break-all;">${(() => {
                if (!req.requestBody) return '<span style="opacity: 0.5;">No payload captured (GET/Empty)</span>';
                try {
                    // Attempt to pretty-print JSON
                    const parsed = JSON.parse(req.requestBody);
                    return JSON.stringify(parsed, null, 4);
                } catch (e) {
                    return req.requestBody; // Fallback to raw text
                }
            })()}</pre>
            </div>

            <div class="m-section-title">Request Headers</div>
            <div class="m-header-list">
                ${safeReqHeaders.length > 0 ? safeReqHeaders.map(h => `
                    <div class="m-header-item">
                        <span class="m-header-name">${h.name}:</span>
                        <span class="m-header-value">${h.value}</span>
                    </div>
                `).join('') : '<div style="color: #94a3b8">No headers captured</div>'}
            </div>

            <div class="m-section-title">Response Headers</div>
            <div class="m-header-list" style="border-color: #10b981;">
                ${safeResHeaders.length > 0 ? safeResHeaders.map(h => `
                    <div class="m-header-item">
                        <span class="m-header-name" style="color: #10b981">${h.name}:</span>
                        <span class="m-header-value">${h.value}</span>
                    </div>
                `).join('') : '<div style="color: #94a3b8">No headers captured</div>'}
            </div>

            <div class="m-section-title">Forensic Metadata</div>
            <div class="m-header-list">
                <div class="m-header-item"><span class="m-header-name">Remote Address:</span> <span class="m-header-value" style="color: #f59e0b; font-family: 'JetBrains Mono';">${req.ip || 'Inferred via Proxy/Tunnel'}</span></div>
                <div class="m-header-item"><span class="m-header-name">Destination Port:</span> <span class="m-header-value" style="color: #f59e0b;">${req.destPort || (req.url.startsWith('https') ? '443' : '80')}</span></div>
                <div class="m-header-item"><span class="m-header-name">Type:</span> <span class="m-header-value">${req.type}</span></div>
                <div class="m-header-item"><span class="m-header-name">Timestamp:</span> <span class="m-header-value">${new Date(req.timestamp).toISOString()}</span></div>
                <div class="m-header-item"><span class="m-header-name">Request ID:</span> <span class="m-header-value">${String(req.id)}</span></div>
                ${req.error ? `<div class="m-header-item" style="color: #ef4444"><span class="m-header-name">Error:</span> <span class="m-header-value">${req.error}</span></div>` : ''}
            </div>
        `;
    }

    closeInspector.addEventListener('click', () => {
        inspector.classList.remove('open');
        selectedRequestId = null;
        renderTable(allRequests);
    });

    function formatTime(ts) {
        const d = new Date(ts);
        const h = String(d.getHours()).padStart(2, '0');
        const m = String(d.getMinutes()).padStart(2, '0');
        const s = String(d.getSeconds()).padStart(2, '0');
        const ms = String(d.getMilliseconds()).padStart(3, '0');
        return `${h}:${m}:${s}.${ms}`;
    }

    clearBtn.addEventListener('click', () => {
        if (!currentTabId) return;
        chrome.storage.session.remove(`reqs_${currentTabId}`);
        allRequests = [];
        body.innerHTML = '';
        inspector.classList.remove('open');
    });

    init();
})();
