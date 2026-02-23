from typing import Dict, List, Any
import re

class SecurityAuditor:
    """
    ShadowTrace Enterprise Security Auditor v1.0
    Performs passive audits of HTTP headers and non-intrusive vulnerability detection.
    """

    @staticmethod
    def audit_headers(headers: List[Dict[str, str]]) -> Dict[str, Any]:
        """Analyzes response headers for security misconfigurations."""
        h_map = {h['name'].lower(): h['value'] for h in headers}
        
        findings = []
        
        # 1. CSP Check
        if 'content-security-policy' not in h_map:
            findings.append({
                "id": "MISSING_CSP",
                "severity": "medium",
                "title": "Missing Content Security Policy",
                "description": "CSP target headers are absent, facilitating XSS and data injection."
            })
            
        # 2. HSTS Check
        if 'strict-transport-security' not in h_map:
            findings.append({
                "id": "MISSING_HSTS",
                "severity": "low",
                "title": "Missing HSTS",
                "description": "HTTP Strict Transport Security is not enforced, allowing downgrade attacks."
            })

        # 3. Secure Cookies
        if 'set-cookie' in h_map:
            cookie_val = h_map['set-cookie'].lower()
            if 'secure' not in cookie_val or 'httponly' not in cookie_val:
                findings.append({
                    "id": "INSECURE_COOKIE",
                    "severity": "medium",
                    "title": "Insecure Cookie Configuration",
                    "description": "Sensitive cookies detected without Secure/HttpOnly flags."
                })

        # 4. Clickjacking (X-Frame-Options)
        if 'x-frame-options' not in h_map and 'frame-ancestors' not in h_map.get('content-security-policy', ''):
            findings.append({
                "id": "CLICKJACKING_RISK",
                "severity": "medium",
                "title": "Missing Clickjacking Protection",
                "description": "X-Frame-Options is not set, allowing the site to be embedded in malicious iframes."
            })

        # 5. Feature/Permissions Policy
        if 'permissions-policy' not in h_map and 'feature-policy' not in h_map:
             findings.append({
                "id": "MISSING_PERMISSIONS_POLICY",
                "severity": "low",
                "title": "Insecure Permissions Policy",
                "description": "Missing browser feature controls (camera, microphone, geolocation)."
            })

        # 6. CORS Check
        if h_map.get('access-control-allow-origin') == '*':
            findings.append({
                "id": "PERMISSIVE_CORS",
                "severity": "medium",
                "title": "Overly Permissive CORS Policy",
                "description": "Access-Control-Allow-Origin is set to '*', violating same-origin principles."
            })

        # Calculate Score (0-100, 100 is best)
        severity_weights = {"high": 30, "medium": 15, "low": 5}
        penalty = sum(severity_weights.get(f['severity'], 0) for f in findings)
        score = max(0, 100 - penalty)
        
        return {
            "score": score,
            "findings": findings
        }

    @staticmethod
    def detect_vulnerabilities(network_reqs: List[Dict]) -> List[Dict]:
        """Passively detects misconfigurations in observed traffic."""
        findings = []
        
        for req in network_reqs:
            url = req.get('url', '').lower()
            
            # 1. Exposed Secret Detect (Passive URLs)
            if any(ext in url for ext in ['.env', '.git', '.aws', '.config', '.sql', '.backup']):
                findings.append({
                    "id": "SENSITIVE_FILE_EXPOSURE",
                    "severity": "high",
                    "title": "Sensitive File Exposure",
                    "description": f"Observed suspicious request to: {url}"
                })
            
            # 2. Insecure Methods (Passive)
            if req.get('method') in ['TRACE', 'TRACK', 'DEBUG'] and req.get('statusCode') == 200:
                findings.append({
                    "id": "INSECURE_METHOD",
                    "severity": "medium",
                    "title": f"Dangerous HTTP Method: {req.get('method')}",
                    "description": f"Endpoint {url} allows administrative/diagnostic methods."
                })
            
            # 3. Credential Leakage in URL
            if any(key in url for key in ['api_key=', 'apikey=', 'secret=', 'password=', 'passwd=']):
                 findings.append({
                    "id": "CREDENTIAL_LEAK_URL",
                    "severity": "high",
                    "title": "Credential Leakage in URL",
                    "description": "Sensitive tokens or credentials observed in plaintext URL parameters."
                })
                
        return findings
