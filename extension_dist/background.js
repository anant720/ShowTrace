/**
 * ShadowTrace — Background Service Worker  (Phase 1.5)
 *
 * Phase 1.5 improvements over Phase 1:
 *   ① Canonical JSON serializer (RFC 8785) — byte-level deterministic signing
 *   ② Offscreen signer — HMAC computation off the SW event loop
 *   ③ Hash chain — every event carries prev_hash; deletion becomes detectable
 *   ④ Hardware-backed installation_id — TPM → platformKeys → derived fallback
 *   ⑤ Nonce sent to backend for dedup (replay immunity enforced server-side)
 */

'use strict';

// ── Config ───────────────────────────────────────────────────────────
const CONFIG = {
    API_ENDPOINT: 'https://showtrace.onrender.com/analyze',
    POLICY_SYNC_ENDPOINT: 'https://showtrace.onrender.com/policies/sync',
    HEARTBEAT_ENDPOINT: 'https://showtrace.onrender.com/persistence/heartbeat',
    ACTIVATE_ENDPOINT: 'https://showtrace.onrender.com/organizations/activate',
    API_KEY: 'st_api_kG9vX2mN8pL4wR5tZ1yQ7jS4nB0hF3d_',
    API_TIMEOUT_MS: 5000,
    API_RETRY_LIMIT: 2,
    POLICY_SYNC_INTERVAL_MS: 5 * 60 * 1000,
    HEARTBEAT_INTERVAL_MS: 2 * 60 * 1000,
    STORAGE_KEYS: {
        INTEGRITY_KEY: 'st_integrity_key',
        LAST_SEQ: 'st_last_seq',
        LAST_HASH: 'st_last_hash',
        DEVICE_ID: 'st_device_id',
        MEMBER_KEY: 'st_member_key',  // org member key entered by user
        ORG_INFO: 'st_org_info',       // {org_id, org_name, email} from activation
    },
    OFFSCREEN_URL: 'offscreen/signer.html',
    ENVELOPE_VERSION: '1.2',
    MSG_TYPE: {
        SIGNAL_REPORT: 'ST_SIGNAL_REPORT',
        BEHAVIOR_ALERT: 'ST_BEHAVIOR_ALERT',
        RISK_RESULT: 'ST_RISK_RESULT',
        GET_RISK: 'ST_GET_RISK',
        ACTIVATE_KEY: 'ST_ACTIVATE_KEY',  // popup → background: validate + store key
        GET_ORG_INFO: 'ST_GET_ORG_INFO',  // popup → background: get current org context
    },
    RISK_LEVELS: { Safe: 'low', Suspicious: 'medium', Dangerous: 'high' },
    MAX_REQUESTS_LOGGED: 50,
    EXCLUDED_DOMAINS: [
        'showtrace.onrender.com',
        'localhost',
        'shadow-trace-dashboard.vercel.app'
    ]
};

// ── Fleet Policy Engine ──────────────────────────────────────────────
let activePolicy = { blocked_domains: [], dlp_rules: [] };

async function syncPolicies() {
    try {
        const token = await getAuthToken(false);
        const headers = token
            ? { 'Authorization': `Bearer ${token}` }
            : { 'X-API-Key': CONFIG.API_KEY };
        const res = await fetch(CONFIG.POLICY_SYNC_ENDPOINT, { headers });
        if (res.ok) {
            activePolicy = await res.json();
            await chrome.storage.session.set({ 'active_fleet_policy': activePolicy });
        }
    } catch (err) {
        console.warn('[ShadowTrace] Policy sync failed:', err.message);
    }
}

syncPolicies();
setInterval(syncPolicies, CONFIG.POLICY_SYNC_INTERVAL_MS);

// ── Heartbeat ────────────────────────────────────────────────────────
async function sendHeartbeat() {
    try {
        const token = await getAuthToken(false);
        const tabs = await chrome.tabs.query({});
        const manifest = chrome.runtime.getManifest();
        const payload = {
            user_id: (await chrome.storage.local.get('st_user'))?.st_user?.email || 'unknown',
            extension_version: manifest.version,
            tab_count: tabs.length,
            timestamp: new Date().toISOString()
        };
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        else headers['X-API-Key'] = CONFIG.API_KEY;
        await fetch(CONFIG.HEARTBEAT_ENDPOINT, { method: 'POST', headers, body: JSON.stringify(payload) });
    } catch (err) {
        console.warn('[ShadowTrace] Heartbeat failed:', err.message);
    }
}

sendHeartbeat();
setInterval(sendHeartbeat, CONFIG.HEARTBEAT_INTERVAL_MS);

// ── Network Monitor ──────────────────────────────────────────────────

function isExcluded(url) {
    try {
        const hostname = new URL(url).hostname;
        return CONFIG.EXCLUDED_DOMAINS.some(d => hostname.includes(d));
    } catch (e) { return false; }
}

async function getFromBuffer(requestId) {
    const key = `buf_${requestId}`;
    const data = await chrome.storage.session.get(key);
    return data[key];
}

async function saveToBuffer(requestId, data) {
    await chrome.storage.session.set({ [`buf_${requestId}`]: data });
}

async function getUserEmail() {
    return new Promise((resolve) => {
        try {
            chrome.identity.getProfileUserInfo({ privilege: 'enabled' }, (info) => {
                resolve(info.email || 'anonymous-user@shadowtrace.local');
            });
        } catch (e) {
            resolve('system-identity@shadowtrace.local');
        }
    });
}

async function finalizeRequest(requestId, tabId, updates = {}) {
    const bufferData = await getFromBuffer(requestId);
    if (!bufferData) return;
    const key = `reqs_${tabId}`;
    const storageData = await chrome.storage.session.get(key);
    const reqs = storageData[key] || [];
    reqs.unshift({ ...bufferData, ...updates });
    if (reqs.length > CONFIG.MAX_REQUESTS_LOGGED) reqs.pop();
    await chrome.storage.session.set({ [key]: reqs });
    await chrome.storage.session.remove(`buf_${requestId}`);
}

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.tabId <= 0 || isExcluded(details.url)) return;
        let rawBody = null;
        if (details.requestBody?.raw) {
            try {
                let combined = new Uint8Array(0);
                for (const chunk of details.requestBody.raw) {
                    if (chunk.bytes) {
                        const tmp = new Uint8Array(combined.length + chunk.bytes.byteLength);
                        tmp.set(combined); tmp.set(new Uint8Array(chunk.bytes), combined.length);
                        combined = tmp;
                    }
                }
                rawBody = new TextDecoder('utf-8').decode(combined);
            } catch (e) { rawBody = '[Binary/Unparseable Data]'; }
        } else if (details.requestBody?.formData) {
            rawBody = Object.entries(details.requestBody.formData)
                .map(([k, v]) => `${k}=${v.join(',')}`)
                .join('&');
        }
        saveToBuffer(details.requestId, {
            id: details.requestId, url: details.url,
            method: details.method, type: details.type,
            tabId: details.tabId, timestamp: Date.now(),
            requestBody: rawBody, headers: [], responseHeaders: [], statusCode: 0
        });
    },
    { urls: ['<all_urls>'] },
    ['requestBody']
);

chrome.webRequest.onBeforeSendHeaders.addListener(
    async (details) => {
        const req = await getFromBuffer(details.requestId);
        if (req) { req.headers = details.requestHeaders || []; await saveToBuffer(details.requestId, req); }
    },
    { urls: ['<all_urls>'] },
    ['requestHeaders', 'extraHeaders']
);

chrome.webRequest.onHeadersReceived.addListener(
    async (details) => {
        const req = await getFromBuffer(details.requestId);
        if (req) {
            req.responseHeaders = details.responseHeaders || [];
            req.statusCode = details.statusCode;
            if (details.ip) req.ip = details.ip;
            try {
                const u = new URL(details.url);
                req.destPort = u.port || (u.protocol === 'https:' ? '443' : '80');
            } catch (e) { req.destPort = 'Unknown'; }
            await saveToBuffer(details.requestId, req);
        }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onCompleted.addListener(
    (d) => finalizeRequest(d.requestId, d.tabId),
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onErrorOccurred.addListener(
    (d) => finalizeRequest(d.requestId, d.tabId, { statusCode: 0, error: d.error || 'Request Interrupted' }),
    { urls: ['<all_urls>'] }
);

// ── Message Listener ─────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.type) return;
    const tabId = sender?.tab?.id;

    if (message.type === CONFIG.MSG_TYPE.SIGNAL_REPORT) {
        if (!tabId) return;
        handleSignalReport(tabId, message.payload);
        sendResponse({ received: true });

    } else if (message.type === CONFIG.MSG_TYPE.ACTIVATE_KEY) {
        // Popup is asking us to validate + store an org member key
        const key = message.key;
        fetch(`${CONFIG.ACTIVATE_ENDPOINT}/${key}`)
            .then(r => r.json())
            .then(async (info) => {
                if (info.valid) {
                    await chrome.storage.local.set({
                        [CONFIG.STORAGE_KEYS.MEMBER_KEY]: key,
                        [CONFIG.STORAGE_KEYS.ORG_INFO]: info
                    });
                    sendResponse({ success: true, org_name: info.org_name, email: info.email });
                } else {
                    sendResponse({ success: false, error: 'Key not recognized' });
                }
            })
            .catch(err => sendResponse({ success: false, error: err.message }));
        return true; // async

    } else if (message.type === CONFIG.MSG_TYPE.GET_ORG_INFO) {
        chrome.storage.local.get([CONFIG.STORAGE_KEYS.MEMBER_KEY, CONFIG.STORAGE_KEYS.ORG_INFO])
            .then(data => sendResponse({
                memberKey: data[CONFIG.STORAGE_KEYS.MEMBER_KEY] || null,
                orgInfo: data[CONFIG.STORAGE_KEYS.ORG_INFO] || null
            }));
        return true;

    } else if (message.type === 'ST_WARM_UP') {
        fetch(CONFIG.API_ENDPOINT, { method: 'HEAD' }).catch(() => { });
        return false;

    } else if (message.type === CONFIG.MSG_TYPE.GET_RISK) {
        chrome.storage.session.get([`tab_${message.tabId}`, `reqs_${message.tabId}`]).then(data => {
            const riskData = data[`tab_${message.tabId}`] || null;
            const reqs = data[`reqs_${message.tabId}`] || [];
            sendResponse({ ...riskData, requests: reqs });
        });
        return true;
    }
    return true;
});

// ── Signal Handler ────────────────────────────────────────────────────
async function handleSignalReport(tabId, payload) {
    await chrome.storage.session.remove([`tab_${tabId}`, `reqs_${tabId}`]);
    const sessionData = await chrome.storage.session.get(`reqs_${tabId}`);
    payload.network_requests = sessionData[`reqs_${tabId}`] || [];
    const email = await getUserEmail();
    if (!payload.meta) payload.meta = {};
    payload.meta.user_email = email;
    payload.meta.extensionVersion = chrome.runtime.getManifest().version;
    payload.meta.userAgent = navigator.userAgent;

    let risk;
    try {
        risk = await sendToBackend(payload);
    } catch (err) {
        console.warn('[ShadowTrace] Backend unreachable, using local fallback:', err.message);
        risk = {
            risk_score: 0, risk_level: 'low',
            reasons: ['Analysis engine unreachable (check network)'],
            source: 'local'
        };
    }

    const storageData = await chrome.storage.session.get('active_fleet_policy');
    const fleetPolicy = storageData.active_fleet_policy || activePolicy;
    if (risk.intelligence_policy || fleetPolicy) {
        chrome.tabs.sendMessage(tabId, {
            type: 'ST_UPDATE_POLICY',
            policy: {
                ...risk.intelligence_policy,
                fleetBlockedDomains: fleetPolicy.blocked_domains,
                fleetDLPRules: fleetPolicy.dlp_rules
            }
        });
    }

    await chrome.storage.session.set({ [`tab_${tabId}`]: { ...risk, ...payload } });
    updateBadge(tabId, risk.risk_level);
}

// ── Google Identity ──────────────────────────────────────────────────
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

// ═══════════════════════════════════════════════════════════════════════
// ── § INTEGRITY LAYER ──────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

// ── §A: HMAC Key Management ──────────────────────────────────────────
async function getIntegrityKey() {
    let keyData = (await chrome.storage.local.get(CONFIG.STORAGE_KEYS.INTEGRITY_KEY))[CONFIG.STORAGE_KEYS.INTEGRITY_KEY];
    if (!keyData) {
        const raw = crypto.getRandomValues(new Uint8Array(32));
        keyData = Array.from(raw).map(b => b.toString(16).padStart(2, '0')).join('');
        await chrome.storage.local.set({ [CONFIG.STORAGE_KEYS.INTEGRITY_KEY]: keyData });
    }
    return keyData; // 64-char hex string = 32 raw bytes
}

// ── §B: Monotonic Sequence Counter ──────────────────────────────────
async function getNextSeq() {
    let seq = (await chrome.storage.local.get(CONFIG.STORAGE_KEYS.LAST_SEQ))[CONFIG.STORAGE_KEYS.LAST_SEQ] || 0;
    seq++;
    await chrome.storage.local.set({ [CONFIG.STORAGE_KEYS.LAST_SEQ]: seq });
    return seq;
}

// ── §C: Hardware-Backed Installation Identity ───────────────────────
/**
 * Returns a stable installation_id bound to hardware where possible.
 *
 * Priority:
 *   1. chrome.enterprise.platformKeys (TPM-backed, non-exportable)
 *   2. chrome.platformKeys            (OS user keychain)
 *   3. Derived fallback               (extension_id + UUID, stored in local)
 *
 * In fallback mode the id is NOT hardware-backed but is still stable
 * across browser restarts.  The server differentiates by the `id_tier`
 * field in the header and applies appropriate trust level.
 */
async function getInstallationId() {
    // Tier 1: Enterprise TPM
    try {
        if (chrome.enterprise?.platformKeys) {
            return await _enterpriseKeyId();
        }
    } catch (_) { /* Enterprise API not available */ }

    // Tier 2: Platform keychain
    try {
        if (chrome.platformKeys) {
            return await _platformKeyId();
        }
    } catch (_) { /* platformKeys not permitted */ }

    // Tier 3: Stable derived fallback
    return { id: await _fallbackId(), tier: 'derived' };
}

async function _bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function _enterpriseKeyId() {
    const tokens = await new Promise(r => chrome.enterprise.platformKeys.getTokens(r));
    const sysToken = tokens.find(t => t.id === 'system') || tokens[0];
    if (!sysToken) throw new Error('No enterprise token');
    const keys = await sysToken.subtleCrypto.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'
        },
        false, ['sign']
    );
    const spki = await sysToken.subtleCrypto.exportKey('spki', keys.publicKey);
    const hash = await crypto.subtle.digest('SHA-256', spki);
    return { id: await _bufToHex(hash), tier: 'enterprise_tpm' };
}

async function _platformKeyId() {
    const keys = await new Promise(r => chrome.platformKeys.getKeyPairs({}, r));
    if (keys && keys.length > 0) {
        const spki = await crypto.subtle.exportKey('spki', keys[0].publicKey);
        const hash = await crypto.subtle.digest('SHA-256', spki);
        return { id: await _bufToHex(hash), tier: 'platform_keychain' };
    }
    throw new Error('No platform keys');
}

async function _fallbackId() {
    const stored = (await chrome.storage.local.get(CONFIG.STORAGE_KEYS.DEVICE_ID))[CONFIG.STORAGE_KEYS.DEVICE_ID];
    if (stored) return stored;
    // Derive from extension_id (fixed per install) + strong entropy
    const raw = `${chrome.runtime.id}:${crypto.randomUUID()}:${Date.now()}`;
    const enc = new TextEncoder().encode(raw);
    const hash = await crypto.subtle.digest('SHA-256', enc);
    const id = await _bufToHex(hash);
    await chrome.storage.local.set({ [CONFIG.STORAGE_KEYS.DEVICE_ID]: id });
    return id;
}

// ── §D: Offscreen Signer ─────────────────────────────────────────────
let _offscreenReady = false;

async function ensureOffscreenSigner() {
    if (_offscreenReady) return;
    try {
        const contexts = await chrome.offscreen.getContexts();
        const exists = contexts.some(c => c.documentUrl?.includes('signer.html'));
        if (!exists) {
            await chrome.offscreen.createDocument({
                url: CONFIG.OFFSCREEN_URL,
                reasons: ['WORKERS'],
                justification: 'HMAC-SHA-256 signing offloaded from service worker thread'
            });
        }
        _offscreenReady = true;
    } catch (err) {
        console.warn('[ShadowTrace] Offscreen signer unavailable:', err.message);
        // Will fallback to inline signing
    }
}

/**
 * Send the envelope to the offscreen signer and get back hmac + envelopeHash.
 * Falls back to inline HMAC if offscreen is unavailable (e.g. dev environment).
 */
async function signViaOffscreen(envelopeSansHmac, keyHex) {
    if (_offscreenReady) {
        try {
            return await new Promise((resolve, reject) => {
                chrome.runtime.sendMessage(
                    { type: 'ST_SIGN', envelope: envelopeSansHmac, keyHex },
                    (resp) => {
                        if (chrome.runtime.lastError || resp?.error) {
                            reject(new Error(resp?.error || chrome.runtime.lastError?.message));
                        } else {
                            resolve(resp);
                        }
                    }
                );
            });
        } catch (err) {
            console.warn('[ShadowTrace] Offscreen sign failed, using inline fallback:', err.message);
        }
    }

    // ── Inline fallback (no offscreen) ──────────────────────────────
    const canonical = _inlineCanonicalBytes(envelopeSansHmac);
    const keyBytes = new Uint8Array(keyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, canonical);
    const hmac = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    // envelope hash for chain
    const hmacBytes = new TextEncoder().encode(hmac);
    const combined = new Uint8Array(canonical.byteLength + hmacBytes.byteLength);
    combined.set(canonical, 0); combined.set(hmacBytes, canonical.byteLength);
    const hashBuf = await crypto.subtle.digest('SHA-256', combined);
    const envelopeHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    return { hmac, envelopeHash };
}

// Minimal inline canonical serializer (mirrors utils/canonicalize.js — kept
// here so background.js has no import dependencies, only used as fallback).
function _inlineCanonical(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(_inlineCanonical).join(',') + ']';
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + _inlineCanonical(value[k])).join(',') + '}';
}
function _inlineCanonicalBytes(value) {
    return new TextEncoder().encode(_inlineCanonical(value));
}

// ── §E: Hash Chain Persistence ─────────────────────────────────────
async function getPrevHash() {
    const stored = await chrome.storage.local.get(CONFIG.STORAGE_KEYS.LAST_HASH);
    return stored[CONFIG.STORAGE_KEYS.LAST_HASH] || 'GENESIS';
}

async function persistEnvelopeHash(hash) {
    await chrome.storage.local.set({ [CONFIG.STORAGE_KEYS.LAST_HASH]: hash });
}

// ── §F: Build Forensic Envelope ─────────────────────────────────────
/**
 * Master function: builds the complete hardened envelope and returns it
 * ready to POST.  Guarantees:
 *   • Canonical HMAC-SHA-256 over RFC 8785 canonical form
 *   • prev_hash links to previous event (forensic chain)
 *   • nonce is per-event UUIDv4 (backend dedup enforces replay immunity)
 *   • installation_id is hardware-backed where available
 *   • Signing runs in offscreen thread (no UI blocking)
 */
async function buildSignedEnvelope(data) {
    await ensureOffscreenSigner();

    const [integrityKey, seq, prevHash, identity] = await Promise.all([
        getIntegrityKey(),
        getNextSeq(),
        getPrevHash(),
        getInstallationId()
    ]);

    const isGenesis = (seq === 1);

    // Build header WITHOUT hmac — this is what gets signed
    const headerSansHmac = {
        version: CONFIG.ENVELOPE_VERSION,
        seq,
        nonce: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        installation_id: identity.id,
        id_tier: identity.tier,
        prev_hash: prevHash,
        genesis: isGenesis,
    };

    const envelopeSansHmac = { header: headerSansHmac, payload: data };

    // Sign via offscreen worker (or inline fallback)
    const { hmac, envelopeHash } = await signViaOffscreen(envelopeSansHmac, integrityKey);

    // Persist hash for next event's prev_hash BEFORE returning
    await persistEnvelopeHash(envelopeHash);

    return {
        header: { ...headerSansHmac, hmac },
        payload: data
    };
}

// ── Backend Transport ────────────────────────────────────────────────
async function sendToBackend(data, retry = 0) {
    try {
        const envelope = await buildSignedEnvelope(data);
        const headers = { 'Content-Type': 'application/json' };

        // Priority 1: Org member key (user pasted from dashboard)
        const stored = await chrome.storage.local.get(CONFIG.STORAGE_KEYS.MEMBER_KEY);
        const memberKey = stored[CONFIG.STORAGE_KEYS.MEMBER_KEY];

        if (memberKey) {
            headers['X-Member-Key'] = memberKey;
        } else {
            // Priority 2: Google OAuth (silent — no popup)
            const token = await getAuthToken(false);
            if (token) headers['Authorization'] = `Bearer ${token}`;
            // Priority 3: Community API key (anonymous fallback)
            else headers['X-API-Key'] = CONFIG.API_KEY;
        }

        const response = await fetch(CONFIG.API_ENDPOINT, {
            method: 'POST',
            headers,
            body: JSON.stringify(envelope)
        });

        if (!response.ok) {
            const errDetail = await response.text().catch(() => 'No detail');
            throw new Error(`Server returned ${response.status}: ${errDetail}`);
        }

        const result = await response.json();
        return {
            risk_score: result.risk_score,
            risk_level: result.risk_level,
            security_findings: result.security_findings || [],
            intelligence_policy: result.intelligence_policy,
            source: 'backend'
        };
    } catch (err) {
        if (retry < CONFIG.API_RETRY_LIMIT) return sendToBackend(data, retry + 1);
        throw err;
    }
}

// ── UI Updates ───────────────────────────────────────────────────────
function updateBadge(tabId, level) {
    const colors = { low: '#22C55E', medium: '#F59E0B', high: '#EF4444' };
    const text = level === 'low' ? '✓' : level === 'medium' ? '!' : '✕';
    try {
        chrome.action.setBadgeBackgroundColor({ tabId, color: colors[level] || '#6B7280' });
        chrome.action.setBadgeText({ tabId, text });
    } catch (e) { /* Tab may be closed */ }
}

// ── Lifecycle ────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(id => {
    chrome.storage.session.remove([`tab_${id}`, `reqs_${id}`]).catch(() => { });
});

chrome.tabs.onUpdated.addListener((id, change) => {
    if (change.status === 'loading') {
        chrome.action.setBadgeText({ tabId: id, text: '' }).catch(() => { });
        chrome.storage.session.remove(`reqs_${id}`).catch(() => { });
    }
});
