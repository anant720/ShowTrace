/**
 * ShadowTrace — Signal Extraction Utilities
 * 
 * Pure functions for extracting security-relevant signals from
 * the DOM and URL context. No side effects, no DOM mutations.
 */

const STSignals = (() => {

    /**
     * Extract domain-level signals from the current page URL.
     * @param {string} href - window.location.href
     * @returns {Object} Domain signal bundle
     */
    function extractDomainSignals(href) {
        let url;
        try {
            url = new URL(href);
        } catch {
            return {
                hostname: 'unknown',
                protocol: 'unknown',
                isHTTPS: false,
                isIPBased: false,
                isPunycode: false,
                tld: 'unknown',
                isSuspiciousTLD: false,
                fullURL: href,
            };
        }

        const hostname = url.hostname;
        const protocol = url.protocol.replace(':', '');
        const isHTTPS = protocol === 'https';

        // IP-based URL detection (IPv4 or IPv6)
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
        const isIPBased = ipv4Regex.test(hostname) || ipv6Regex.test(hostname);

        // Punycode detection (internationalized domain names)
        const isPunycode = hostname.includes('xn--');

        // TLD extraction
        const parts = hostname.split('.');
        const tld = parts.length > 1 ? parts[parts.length - 1] : '';
        const isSuspiciousTLD = ST_CONFIG.SUSPICIOUS_TLDS.includes(tld.toLowerCase());

        return {
            hostname,
            protocol,
            isHTTPS,
            isIPBased,
            isPunycode,
            tld,
            isSuspiciousTLD,
            fullURL: href,
            entropy: calculateEntropy(hostname),
        };
    }

    /**
     * Calculate Shannon Entropy of a string to detect DGA/Randomness.
     */
    function calculateEntropy(str) {
        const len = str.length;
        if (len === 0) return 0;
        const frequencies = {};
        for (let char of str) frequencies[char] = (frequencies[char] || 0) + 1;
        return Object.values(frequencies).reduce((sum, f) => {
            const p = f / len;
            return sum - p * Math.log2(p);
        }, 0);
    }

    /**
     * Scan for indicators of JavaScript obfuscation or malicious scripting.
     */
    function analyzeJSObfuscation() {
        const scripts = Array.from(document.scripts);
        let evalCount = 0;
        let largeHexCount = 0;
        let totalScriptSize = 0;

        scripts.forEach(s => {
            const content = s.textContent || '';
            totalScriptSize += content.length;
            if (content.includes('eval(')) evalCount++;
            if ((content.match(/0x[0-9a-fA-F]{4,}/g) || []).length > 5) largeHexCount++;
        });

        return {
            scriptCount: scripts.length,
            totalScriptSize,
            evalCount,
            largeHexCount,
            hasSuspiciousFunctions: evalCount > 0 || largeHexCount > 0
        };
    }

    /**
     * Analyze event listeners and form interaction behaviors.
     */
    function monitorEventListeners() {
        const inputs = Array.from(document.querySelectorAll('input'));
        let suspiciousHandlers = 0;

        inputs.forEach(input => {
            if (input.hasAttribute('onpaste') || input.hasAttribute('oncopy') || input.hasAttribute('oninput')) {
                suspiciousHandlers++;
            }
        });

        return {
            inputCount: inputs.length,
            suspiciousHandlerCount: suspiciousHandlers,
            hasGlobalKeylogger: !!document.onkeydown || !!document.onkeypress
        };
    }

    /**
     * Detect hidden DOM elements used for phishing (off-screen forms, hidden inputs).
     */
    function collectFormTraps() {
        const hiddenForms = Array.from(document.querySelectorAll('form')).filter(f => {
            const style = window.getComputedStyle(f);
            return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0';
        });

        const offscreenElements = Array.from(document.querySelectorAll('input, form')).filter(el => {
            const rect = el.getBoundingClientRect();
            return rect.left < 0 || rect.top < 0 || rect.width === 0 || rect.height === 0;
        });

        return {
            hiddenFormCount: hiddenForms.length,
            offscreenElementCount: offscreenElements.length
        };
    }

    /**
     * Analyze a single <form> element for security-relevant signals.
     * @param {HTMLFormElement} form
     * @param {string} pageHostname - hostname of the current page
     * @returns {Object} Form signal bundle
     */
    function analyzeForm(form, pageHostname) {
        const inputs = form.querySelectorAll('input');
        const passwordFields = form.querySelectorAll('input[type="password"]');
        const hiddenInputs = form.querySelectorAll('input[type="hidden"]');

        // Form action analysis
        const rawAction = form.getAttribute('action') || '';
        let actionURL = '';
        let actionHostname = '';
        let isCrossDomainAction = false;

        if (rawAction) {
            try {
                const resolved = new URL(rawAction, window.location.href);
                actionURL = resolved.href;
                actionHostname = resolved.hostname;
                isCrossDomainAction = actionHostname !== pageHostname;
            } catch {
                actionURL = rawAction;
                // Malformed URL in action is itself suspicious
                isCrossDomainAction = true;
            }
        }

        return {
            hasPasswordField: passwordFields.length > 0,
            passwordFieldCount: passwordFields.length,
            inputCount: inputs.length,
            hiddenInputCount: hiddenInputs.length,
            formAction: actionURL,
            formActionHostname: actionHostname,
            isCrossDomainAction,
            formMethod: (form.method || 'GET').toUpperCase(),
        };
    }

    /**
     * Scan the entire document for login-relevant forms.
     * @returns {Object} Aggregated form signals
     */
    function scanForLoginForms() {
        const forms = document.querySelectorAll('form');
        const standalonePasswords = document.querySelectorAll(
            'input[type="password"]:not(form input[type="password"])'
        );
        const pageHostname = window.location.hostname;

        const formSignals = [];
        let hasLoginForm = false;

        forms.forEach(form => {
            const signals = analyzeForm(form, pageHostname);
            if (signals.hasPasswordField) {
                hasLoginForm = true;
            }
            formSignals.push(signals);
        });

        // Check for password fields outside forms (common in SPAs)
        if (standalonePasswords.length > 0) {
            hasLoginForm = true;
        }

        return {
            hasLoginForm,
            formCount: forms.length,
            standalonePasswordFields: standalonePasswords.length,
            forms: formSignals,
        };
    }

    /**
     * Build the complete signal payload for backend transmission.
     * @param {Object} domainSignals
     * @param {Object} formSignals
     * @param {Object} behaviorSignals
     * @returns {Object} Structured payload
     */
    function buildPayload(domainSignals, formSignals, behaviorSignals) {
        return {
            timestamp: new Date().toISOString(),
            fullURL: window.location.href,
            domain: domainSignals,
            forms: formSignals,
            behavior: behaviorSignals,
            ml_behavior: analyzeJSObfuscation(),
            interaction: monitorEventListeners(),
            traps: collectFormTraps(),
            meta: {
                extensionVersion: chrome.runtime.getManifest().version,
                userAgent: navigator.userAgent,
            },
        };
    }

    // Public API
    return {
        extractDomainSignals,
        analyzeForm,
        scanForLoginForms,
        buildPayload,
    };

})();
