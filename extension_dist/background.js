const CONFIG = {
    API_ENDPOINT: 'https://showtrace.onrender.com/analyze',
    API_KEY: 'st_api_kG9vX2mN8pL4wR5tZ1yQ7jS4nB0hF3d_',
    API_TIMEOUT_MS: 5000,
    API_RETRY_LIMIT: 2,
    MSG_TYPE: {
        SIGNAL_REPORT: 'ST_SIGNAL_REPORT',
        BEHAVIOR_ALERT: 'ST_BEHAVIOR_ALERT',
        RISK_RESULT: 'ST_RISK_RESULT',
        GET_RISK: 'ST_GET_RISK',
    },
    RISK_LEVELS: { Safe: 'low', Suspicious: 'medium', Dangerous: 'high' },
    MAX_REQUESTS_LOGGED: 50
};

// ── Network Monitor (Burp Suite Mode - Suspension Tolerant) ─────────────────

async function getFromBuffer(requestId) {
    const key = `buf_${requestId}`;
    const data = await chrome.storage.session.get(key);
    return data[key];
}

async function saveToBuffer(requestId, data) {
    await chrome.storage.session.set({ [`buf_${requestId}`]: data });
}

async function finalizeRequest(requestId, tabId, updates = {}) {
    const key = `buf_${requestId}`;
    const bufferData = await getFromBuffer(requestId);
    if (!bufferData) return;

    const finalizedReq = { ...bufferData, ...updates };

    // Move to persistent tab logs
    const logKey = `reqs_${tabId}`;
    const storageData = await chrome.storage.session.get(logKey);
    const reqs = storageData[logKey] || [];

    reqs.unshift(finalizedReq);
    if (reqs.length > CONFIG.MAX_REQUESTS_LOGGED) reqs.pop();

    await chrome.storage.session.set({ [logKey]: reqs });
    await chrome.storage.session.remove(key);
}

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.tabId <= 0) return;

        let rawBody = null;
        if (details.requestBody) {
            if (details.requestBody.raw) {
                try {
                    const decoder = new TextDecoder("utf-8");
                    rawBody = decoder.decode(details.requestBody.raw[0].bytes);
                } catch (e) { rawBody = "[Binary/Unparseable Data]"; }
            } else if (details.requestBody.formData) {
                rawBody = JSON.stringify(details.requestBody.formData);
            }
        }

        const initialData = {
            id: details.requestId,
            url: details.url,
            method: details.method,
            type: details.type,
            tabId: details.tabId,
            timestamp: Date.now(),
            requestBody: rawBody,
            requestHeaders: [],
            responseHeaders: [],
            statusCode: 0
        };
        saveToBuffer(details.requestId, initialData);
    },
    { urls: ["<all_urls>"] },
    ["requestBody"]
);

chrome.webRequest.onBeforeSendHeaders.addListener(
    async (details) => {
        const req = await getFromBuffer(details.requestId);
        if (req) {
            req.requestHeaders = details.requestHeaders || [];
            await saveToBuffer(details.requestId, req);
        }
    },
    { urls: ["<all_urls>"] },
    ["requestHeaders", "extraHeaders"]
);

chrome.webRequest.onHeadersReceived.addListener(
    async (details) => {
        const req = await getFromBuffer(details.requestId);
        if (req) {
            req.responseHeaders = details.responseHeaders || [];
            req.statusCode = details.statusCode;
            await saveToBuffer(details.requestId, req);
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
);

chrome.webRequest.onCompleted.addListener(
    (details) => {
        finalizeRequest(details.requestId, details.tabId);
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
);

chrome.webRequest.onErrorOccurred.addListener(
    (details) => {
        finalizeRequest(details.requestId, details.tabId, {
            statusCode: 0,
            error: details.error || 'Request Interrupted'
        });
    },
    { urls: ["<all_urls>"] }
);

// ── Message Listener ────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.type) return;

    const tabId = sender?.tab?.id;

    if (message.type === CONFIG.MSG_TYPE.SIGNAL_REPORT) {
        if (!tabId) return;
        handleSignalReport(tabId, message.payload);
        sendResponse({ received: true });
    } else if (message.type === 'ST_WARM_UP') {
        fetch(CONFIG.API_ENDPOINT, { method: 'HEAD' }).catch(() => { });
        return false;
    } else if (message.type === CONFIG.MSG_TYPE.GET_RISK) {
        chrome.storage.session.get([`tab_${message.tabId}`, `reqs_${message.tabId}`]).then(data => {
            const riskData = data[`tab_${message.tabId}`] || null;
            const reqs = data[`reqs_${message.tabId}`] || [];
            sendResponse({ ...riskData, requests: reqs });
        });
        return true; // Keep channel open for async response
    }
    return true;
});

// ── Scan Handler ────────────────────────────────────────────────────
async function handleSignalReport(tabId, payload) {
    console.log(`[ShadowTrace] Received signal from tab ${tabId}: ${payload.domain.hostname}`);

    // Immediate clear to avoid stale data
    await chrome.storage.session.remove([`tab_${tabId}`, `reqs_${tabId}`]);

    // Enhance payload with captured requests
    const sessionData = await chrome.storage.session.get(`reqs_${tabId}`);
    payload.network_requests = sessionData[`reqs_${tabId}`] || [];

    let risk;
    try {
        risk = await sendToBackend(payload);
    } catch (err) {
        console.warn('[ShadowTrace] Backend unreachable, using local fallback:', err.message);
        risk = {
            risk_score: 0,
            risk_level: 'low',
            reasons: ['Analysis engine unreachable (check network)'],
            source: 'local'
        };
    }

    await chrome.storage.session.set({ [`tab_${tabId}`]: { ...risk, ...payload } });
    updateBadge(tabId, risk.risk_level);
}

// ── Google Identity ─────────────────────────────────────────────────
async function getAuthToken(interactive = false) {
    return new Promise((resolve) => {
        if (!chrome.identity) return resolve(null);

        chrome.identity.getAuthToken({ interactive }, (token) => {
            if (chrome.runtime.lastError) {
                if (interactive) console.warn('[ShadowTrace] Auth Error:', chrome.runtime.lastError.message);
                resolve(null);
            } else {
                resolve(token);
            }
        });
    });
}

// ── Backend Communication ───────────────────────────────────────────
async function sendToBackend(payload, retry = 0) {
    try {
        const token = await getAuthToken(false);
        const headers = { 'Content-Type': 'application/json' };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        } else {
            headers['X-API-Key'] = CONFIG.API_KEY;
        }

        const res = await fetch(CONFIG.API_ENDPOINT, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            if (res.status === 401 && token) {
                chrome.identity.removeCachedAuthToken({ token }, () => { });
                if (retry < CONFIG.API_RETRY_LIMIT) return sendToBackend(payload, retry + 1);
            }
            const errDetail = await res.text().catch(() => 'No detail');
            throw new Error(`API Error ${res.status}: ${errDetail}`);
        }

        const data = await res.json();
        const levelMap = { 'Safe': 'low', 'Suspicious': 'medium', 'Dangerous': 'high' };

        return {
            risk_score: data.risk_score,
            risk_level: levelMap[data.risk_level] || 'low',
            reasons: data.reasons || [],
            source: 'backend'
        };
    } catch (err) {
        if (retry < CONFIG.API_RETRY_LIMIT) return sendToBackend(payload, retry + 1);
        throw err;
    }
}

// ── UI Updates ──────────────────────────────────────────────────────
function updateBadge(tabId, level) {
    const colors = { low: '#22C55E', medium: '#F59E0B', high: '#EF4444' };
    const text = level === 'low' ? '✓' : level === 'medium' ? '!' : '✕';

    try {
        chrome.action.setBadgeBackgroundColor({ tabId, color: colors[level] || '#6B7280' });
        chrome.action.setBadgeText({ tabId, text });
    } catch (e) {
        // Tab might be closed during async processing
    }
}

// ── Lifecycle ───────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(id => {
    try {
        chrome.storage.session.remove([`tab_${id}`, `reqs_${id}`]);
    } catch (e) { }
});

chrome.tabs.onUpdated.addListener((id, change) => {
    if (change.status === 'loading') {
        try {
            chrome.action.setBadgeText({ tabId: id, text: '' });
            chrome.storage.session.remove(`reqs_${id}`); // Clear on new page load
        } catch (e) { }
    }
});
