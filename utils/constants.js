

const ST_CONFIG = Object.freeze({
  // Backend API
  API_ENDPOINT: 'http://localhost:8000/analyze',
  API_TIMEOUT_MS: 5000,
  API_RETRY_LIMIT: 2,

  // Message types (content <-> background)
  MSG_TYPE: Object.freeze({
    SIGNAL_REPORT: 'ST_SIGNAL_REPORT',
    BEHAVIOR_ALERT: 'ST_BEHAVIOR_ALERT',
    RISK_RESULT: 'ST_RISK_RESULT',
    GET_RISK: 'ST_GET_RISK',
  }),

  // Injected script message identifier (page context <-> content script)
  INJECT_MSG_KEY: '__SHADOWTRACE_INJECT__',

  // Risk level thresholds (0-100 score)
  RISK_THRESHOLDS: Object.freeze({
    LOW: 30,   // 0–30 = low risk
    MEDIUM: 65,   // 31–65 = medium risk
    // 66–100 = high risk
  }),

  // Risk level labels
  RISK_LEVELS: Object.freeze({
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
  }),

  // Badge colors (RGB arrays for chrome.action.setBadgeBackgroundColor)
  BADGE_COLORS: Object.freeze({
    low: '#22C55E',  // green
    medium: '#F59E0B',  // amber
    high: '#EF4444',  // red
    unknown: '#6B7280',  // gray
  }),

  // Timing
  DEBOUNCE_MS: 800,            // Debounce for MutationObserver
  SCAN_DELAY_MS: 300,          // Delay before initial scan

  // Local scoring weights (fallback when backend is unreachable)
  LOCAL_SCORING: Object.freeze({
    HTTP_PENALTY: 20,
    IP_URL_PENALTY: 25,
    PUNYCODE_PENALTY: 30,
    LOGIN_FORM_BASE: 10,
    CROSS_DOMAIN_ACTION: 35,
    HIDDEN_INPUTS_PENALTY: 5,   // per hidden input, capped at 15
    HIDDEN_INPUTS_CAP: 15,
    EXTERNAL_SUBMISSION: 40,
    SUSPICIOUS_TLD_PENALTY: 15,
  }),

  // TLDs commonly associated with phishing
  SUSPICIOUS_TLDS: Object.freeze([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club',
    'work', 'buzz', 'surf', 'cam', 'icu', 'monster',
  ]),
});
