# ShadowTrace

**Real-Time Browser-Based Phishing & Credential Exfiltration Detection Engine**

A Chrome extension (Manifest V3) that acts as a client-side threat sensor, monitoring visited domains, detecting login forms, analyzing form submission endpoints, and flagging suspicious credential exfiltration attempts in real time.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser Tab                                                    │
│  ┌──────────────────────┐    ┌──────────────────────┐          │
│  │  inject.js            │    │  content.js           │          │
│  │  (Page Context)       │───→│  (Isolated World)     │          │
│  │  • fetch() intercept  │    │  • Domain analysis    │          │
│  │  • XHR intercept      │    │  • Form scanning      │          │
│  │  • Form submit hook   │    │  • MutationObserver   │          │
│  └──────────────────────┘    └──────────┬───────────┘          │
│                                          │ chrome.runtime       │
│                                          │ .sendMessage()       │
└──────────────────────────────────────────┼─────────────────────┘
                                           │
           ┌───────────────────────────────▼──────────────────┐
           │  background.js (Service Worker)                   │
           │  • Signal aggregation                             │
           │  • Backend API communication (POST /analyze)      │
           │  • Local fallback scoring                         │
           │  • Badge management (green/yellow/red)            │
           │  • Session storage management                     │
           └───────────────────────────────┬──────────────────┘
                                           │
           ┌───────────────────────────────▼──────────────────┐
           │  popup/  (Action Popup)                           │
           │  • Reads cached risk data from session storage    │
           │  • Renders risk score ring, level badge           │
           │  • Lists detected threat signals                  │
           └──────────────────────────────────────────────────┘
```

### Design Decisions

| Decision | Rationale |
|---|---|
| **Content script as passive sensor** | Clean separation — DOM analysis only, no API calls, no CORS concerns |
| **Page-context injection (`inject.js`)** | Content scripts run in an isolated world and cannot intercept `fetch()`/`XHR` calls made by the page. Monkey-patching must happen in page context. |
| **`window.postMessage` bridge** | Only reliable IPC between page context and content script isolated world |
| **Session storage for popup** | Popup is ephemeral; reading cached data avoids redundant API calls and keeps it stateless |
| **Local fallback scoring** | Extension remains functional when backend is unreachable |
| **Debounced MutationObserver** | Handles SPA-injected login forms without performance degradation |

---

## Folder Structure

```
Shadow Trace/
├── manifest.json           # Extension configuration (Manifest V3)
├── background.js           # Service worker — intelligence hub
├── content.js              # Content script — DOM sensor
├── inject.js               # Page-context behavioral monitor
├── popup/
│   ├── popup.html          # Popup UI structure
│   ├── popup.css           # Dark cybersecurity theme
│   └── popup.js            # Popup controller
├── utils/
│   ├── constants.js        # Shared configuration & thresholds
│   └── signals.js          # Signal extraction helpers
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   └── generate_icons.html # Icon generation utility
└── README.md
```

---

## Setup & Installation

### Prerequisites
- Google Chrome (version 88+)

### Loading the Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right corner)
3. Click **Load unpacked**
4. Select the `Shadow Trace` folder
5. The ShadowTrace icon should appear in your toolbar

### Generating Icons (First Time Only)

1. Open `icons/generate_icons.html` in Chrome
2. Three PNG files will automatically download (`icon16.png`, `icon48.png`, `icon128.png`)
3. Move the downloaded files into the `icons/` directory
4. Reload the extension from `chrome://extensions/`

---

## Signal Detection Capabilities

### Domain-Level
| Signal | Detection Method |
|---|---|
| HTTP vs HTTPS | `location.protocol` check |
| IP-based URLs | IPv4/IPv6 regex on hostname |
| Punycode domains | `xn--` prefix detection |
| Suspicious TLDs | Lookup against known phishing TLD list |

### Form-Level
| Signal | Detection Method |
|---|---|
| Password fields | `input[type="password"]` selector |
| Cross-domain `form.action` | Comparing action URL hostname vs page hostname |
| Hidden inputs | `input[type="hidden"]` count |
| Input enumeration | Form input count analysis |

### Behavioral
| Signal | Detection Method |
|---|---|
| External `fetch()` calls | Monkey-patched `window.fetch` |
| External `XHR` calls | Monkey-patched `XMLHttpRequest.open/send` |
| Credential-bearing requests | Key name pattern matching (never reads values) |
| Form submission to external domain | Submit event listener in capture phase |

---

## Risk Scoring

### Local Fallback Heuristic

When the backend API is unreachable, a local scoring engine runs:

| Signal | Points |
|---|---|
| HTTP (no encryption) | +20 |
| IP-based URL | +25 |
| Punycode domain | +30 |
| Suspicious TLD | +15 |
| Login form present | +10 |
| Cross-domain form action | +35 |
| Hidden inputs | +5 each (cap: 15) |
| External credential submission | +40 |

**Levels:** 0–30 = LOW (green) · 31–65 = MEDIUM (amber) · 66–100 = HIGH (red)

---

## Testing

### Manual Verification Checklist

| Test Case | Steps | Expected |
|---|---|---|
| Safe HTTPS site | Visit `https://www.google.com` | Green badge, low risk score |
| HTTP site | Visit `http://example.com` | HTTP flagged, score increases |
| Login form detection | Visit `https://accounts.google.com` | "Login form detected" in signals |
| IP-based URL | Visit `http://142.250.80.46` | IP-based URL flagged |
| No forms page | Visit `https://www.wikipedia.org` | Form count = 0 |
| Extension popup | Click extension icon | Risk score ring, domain info, reasons list visible |
| Console logs | Open DevTools on any page | `[ShadowTrace]` prefixed logs |
| Service worker logs | `chrome://extensions/` → service worker link | `[ShadowTrace:BG]` prefixed logs |

---

## Security Considerations

- **No credential capture**: `inject.js` checks key names in request payloads (e.g., "password"), never reads actual values
- **Message origin validation**: Content script validates `window.postMessage` source and type identifier
- **Response schema validation**: Backend responses are validated before processing
- **Session-only storage**: `chrome.storage.session` is ephemeral — no persistent credential data
- **Minimal permissions**: Only `activeTab`, `storage`, `scripting` — no `tabs`, `webRequest`, or `cookies`

---

## Backend API Contract

The extension sends `POST` requests to the configured endpoint (default: `http://localhost:8000/analyze`).

### Request Payload
```json
{
  "timestamp": "2026-02-21T23:10:00.000Z",
  "domain": {
    "hostname": "example.com",
    "protocol": "https",
    "isHTTPS": true,
    "isIPBased": false,
    "isPunycode": false,
    "tld": "com",
    "isSuspiciousTLD": false,
    "fullURL": "https://example.com/login"
  },
  "forms": {
    "hasLoginForm": true,
    "formCount": 1,
    "standalonePasswordFields": 0,
    "forms": [{ "hasPasswordField": true, "inputCount": 3, "..." : "..." }]
  },
  "behavior": {
    "externalFetchDetected": false,
    "externalXHRDetected": false,
    "suspiciousSubmissions": []
  },
  "meta": {
    "extensionVersion": "1.0.0",
    "userAgent": "..."
  }
}
```

### Expected Response
```json
{
  "risk_score": 45,
  "risk_level": "medium",
  "reasons": [
    "Login form detected on page",
    "Page served over HTTP"
  ]
}
```

---

## Known Limitations

1. **No live backend** — Currently uses local fallback scoring only
2. **Monkey-patch conflicts** — `inject.js` may conflict with sites that override `fetch`/`XHR`
3. **SPA performance** — `MutationObserver` has a ceiling on DOM-heavy single-page apps
4. **Punycode detection** — Pattern-based (`xn--`), not full IDN normalization
5. **No persistent history** — Risk data is session-only by design
6. **Single tab scope** — Content script runs in `all_frames: false` (top frame only)

---

## Future Integration Points

This extension is designed for modular expansion:

- **Domain similarity engine** — Feed `domain.hostname` for typosquatting/homograph analysis
- **DOM fingerprinting** — Extend `content.js` signal collection for visual similarity detection
- **Credential exfiltration analyzer** — Enhance `inject.js` interception pipeline
- **Risk scoring system** — Replace local heuristic with ML-based backend scoring
- **Threat intelligence database** — Enrich domain signals with historical threat data

---

## License

Proprietary — ShadowTrace Project
