# ShadowTrace Privacy Policy

**Effective Date**: February 23, 2026

ShadowTrace ("we", "our", or "the Extension") is committed to protecting your privacy while providing advanced threat intelligence. This policy explains how we handle data within the ShadowTrace ecosystem.

## 1. Data Collection & Usage

ShadowTrace is an enterprise security tool. It collects the following information only when an **On-Demand Scan** is triggered by the user:

- **Identity Information**: Your authenticated Google Email address (Gmail ID) is collected via `chrome.identity` to provide user-level attribution for forensic logs in your organization's dashboard.
- **Network Signals**: The Extension intercepts URLs, request headers, and request bodies of the active tab being scanned. This data is used to analyze phishing risks and identify credential exfiltration attempts.
- **Metadata**: Extension version and browser User Agent are recorded to assist in forensic auditing and system troubleshooting.

## 2. On-Demand Privacy Model
ShadowTrace **does not** scan your browsing activity automatically in the background. Data is only processed and sent to your configured backend when you explicitly click the "SCAN THIS PAGE" button in the extension popup.

## 3. Data Protection & Redaction
We implement high-fidelity security measures to ensure your sensitive data is protected:
- **Server-Side Scrubbing**: All captured network payloads are automatically "scrubbed" on the backend before persistent storage. We use regex-based redaction to strip plain-text passwords, JWT tokens, and API keys.
- **Infrastructure Privacy Shield**: The extension is configured to ignore traffic directed towards ShadowTrace's own infrastructure, preventing the capture of internal authentication tokens.
- **UI Masking**: Sensitive credentials detected during a scan are obfuscated in the extension monitor and dashboard interface.

## 4. Data Sharing & Storage
- Your data is transmitted exclusively to your organization's ShadowTrace backend API (e.g., `showtrace.onrender.com`).
- We **do not** sell, trade, or share your data with any third-party services.
- Data is stored in your private forensic database for security audit purposes.

## 5. Your Rights
- **Access & Deletion**: You can view all captured forensic logs via the ShadowTrace Enterprise Dashboard. Analyst users may delete scan logs at any time.
- **Revocation**: You can stop all data collection by disabling or removing the extension from your browser.

## 6. Contact
For questions regarding this privacy policy or the technical implementation of our data protections, please contact your organization's ShadowTrace administrator.
