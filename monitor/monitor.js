(() => {
    'use strict';

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
                updateInspector();
            });

            body.appendChild(tr);
        });
    }

    function updateInspector() {
        const req = allRequests.find(r => r.id === selectedRequestId);
        if (!req) return;

        const statusClass = req.statusCode >= 400 ? 'error' : req.statusCode >= 300 ? 'redirect' : 'success';

        inspectorContent.innerHTML = `
            <div class="m-status-pill ${statusClass}" style="margin-bottom: 20px;">STATUS ${req.statusCode} ${req.method}</div>
            
            <div class="m-section-title">Request URL</div>
            <div class="m-header-list" style="word-break: break-all; margin-bottom: 20px; color: #3b82f6;">${req.url}</div>

            <div class="m-section-title">Request Body (Payload)</div>
            <div class="m-header-list" style="background: rgba(16, 185, 129, 0.05); border-color: rgba(16, 185, 129, 0.2); color: #10b981;">
                <pre style="white-space: pre-wrap; word-break: break-all;">${req.requestBody ? req.requestBody : '<span style="opacity: 0.5;">No payload captured (GET/Empty)</span>'}</pre>
            </div>

            <div class="m-section-title">Request Headers</div>
            <div class="m-header-list">
                ${req.requestHeaders.length > 0 ? req.requestHeaders.map(h => `
                    <div class="m-header-item">
                        <span class="m-header-name">${h.name}:</span>
                        <span class="m-header-value">${h.value}</span>
                    </div>
                `).join('') : '<div style="color: #94a3b8">No headers captured</div>'}
            </div>

            <div class="m-section-title">Response Headers</div>
            <div class="m-header-list" style="border-color: #10b981;">
                ${req.responseHeaders.length > 0 ? req.responseHeaders.map(h => `
                    <div class="m-header-item">
                        <span class="m-header-name" style="color: #10b981">${h.name}:</span>
                        <span class="m-header-value">${h.value}</span>
                    </div>
                `).join('') : '<div style="color: #94a3b8">No headers captured</div>'}
            </div>

            <div class="m-section-title">Forensic Metadata</div>
            <div class="m-header-list">
                <div class="m-header-item"><span class="m-header-name">Type:</span> <span class="m-header-value">${req.type}</span></div>
                <div class="m-header-item"><span class="m-header-name">Timestamp:</span> <span class="m-header-value">${new Date(req.timestamp).toISOString()}</span></div>
                <div class="m-header-item"><span class="m-header-name">Request ID:</span> <span class="m-header-value">${req.id}</span></div>
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
