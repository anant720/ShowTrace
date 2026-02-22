(() => {
    'use strict';

    const MSG_KEY = 'ST_INJECT_DATA';
    const pageHostname = window.location.hostname;

    function isExternalDomain(urlString) {
        try {
            const url = new URL(urlString, window.location.href);
            return url.hostname !== pageHostname;
        } catch {
            return true; // Malformed URLs are suspicious
        }
    }

    function looksLikeCredentials(body) {
        if (!body) return false;

        let searchable = '';

        if (typeof body === 'string') {
            searchable = body.toLowerCase();
        } else if (body instanceof URLSearchParams) {
            searchable = body.toString().toLowerCase();
        } else if (body instanceof FormData) {
            // Check FormData keys only
            for (const key of body.keys()) {
                if (isCredentialKey(key)) return true;
            }
            return false;
        } else if (typeof body === 'object') {
            try {
                searchable = JSON.stringify(Object.keys(body)).toLowerCase();
            } catch {
                return false;
            }
        }

        const credentialPatterns = [
            'password', 'passwd', 'pwd', 'pass',
            'credential', 'secret', 'token',
            'login', 'signin', 'auth',
        ];

        return credentialPatterns.some(pattern => searchable.includes(pattern));
    }

    function isCredentialKey(key) {
        const k = key.toLowerCase();
        const patterns = ['password', 'passwd', 'pwd', 'pass', 'credential', 'secret', 'token'];
        return patterns.some(p => k.includes(p));
    }

    function dispatchSignal(kind, destination, extras = {}) {
        window.postMessage({
            type: MSG_KEY,
            payload: {
                kind,
                destination,
                timestamp: new Date().toISOString(),
                ...extras,
            },
        }, '*');
    }

    const originalFetch = window.fetch;

    window.fetch = function (input, init = {}) {
        try {
            const url = (typeof input === 'string')
                ? input
                : (input instanceof Request ? input.url : String(input));

            const method = (init.method || 'GET').toUpperCase();

            if (isExternalDomain(url)) {
                dispatchSignal('external_fetch', url, { method });

                if (init.body && looksLikeCredentials(init.body)) {
                    dispatchSignal('credential_bearing_request', url, { method });
                }
            }
        } catch {
            // Fail silently — never break page functionality
        }

        return originalFetch.apply(this, arguments);
    };


    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        this.__st_method = method;
        this.__st_url = url;
        return originalOpen.apply(this, [method, url, ...rest]);
    };

    XMLHttpRequest.prototype.send = function (body) {
        try {
            if (this.__st_url && isExternalDomain(this.__st_url)) {
                dispatchSignal('external_xhr', this.__st_url, {
                    method: (this.__st_method || 'GET').toUpperCase(),
                });

                if (body && looksLikeCredentials(body)) {
                    dispatchSignal('credential_bearing_request', this.__st_url, {
                        method: (this.__st_method || 'GET').toUpperCase(),
                    });
                }
            }
        } catch {
            // Fail silently
        }

        return originalSend.apply(this, arguments);
    };

    // ── Form Submit Interception ─────────────────────────────────────

    document.addEventListener('submit', (event) => {
        try {
            const form = event.target;
            if (!(form instanceof HTMLFormElement)) return;

            const action = form.getAttribute('action') || '';
            if (action && isExternalDomain(action)) {
                const hasPassword = form.querySelector('input[type="password"]') !== null;
                if (hasPassword) {
                    dispatchSignal('credential_bearing_request', action, {
                        method: (form.method || 'GET').toUpperCase(),
                        source: 'form_submit',
                    });
                }
            }
        } catch {
            // Fail silently
        }
    }, true); // Capture phase to detect before any preventDefault

})();
