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
                "description": "CSP is not configured, increasing the risk of XSS attacks."
            })
            
        # 2. HSTS Check
        if 'strict-transport-security' not in h_map:
            findings.append({
                "id": "MISSING_HSTS",
                "severity": "low",
                "title": "Missing HSTS",
                "description": "HTTP Strict Transport Security is not enabled."
            })

        # 3. Secure Cookies
        if 'set-cookie' in h_map:
            cookie_val = h_map['set-cookie'].lower()
            if 'secure' not in cookie_val or 'httponly' not in cookie_val:
                findings.append({
                    "id": "INSECURE_COOKIE",
                    "severity": "medium",
                    "title": "Insecure Cookie Configuration",
                    "description": "Cookies detected without 'Secure' or 'HttpOnly' flags."
                })

        # 4. CORS Check
        if h_map.get('access-control-allow-origin') == '*':
            findings.append({
                "id": "PERMISSIVE_CORS",
                "severity": "medium",
                "title": "Overly Permissive CORS Policy",
                "description": "Access-Control-Allow-Origin is set to '*', allowing any domain to read responses."
            })

        # Calculate Score (0-100, 100 is best)
        missing_penalty = len([f for f in findings if f['severity'] in ['medium', 'high']]) * 20
        score = max(0, 100 - missing_penalty)
        
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
            if any(ext in url for ext in ['.env', '.git', '.aws', '.config']):
                findings.append({
                    "id": "SENSITIVE_FILE_EXPOSURE",
                    "severity": "high",
                    "title": "Sensitive File Exposure",
                    "description": f"Observed request to potentially sensitive file: {url}"
                })
            
            # 2. Insecure Methods (Passive)
            if req.get('method') in ['TRACE', 'OPTIONS'] and req.get('statusCode') == 200:
                findings.append({
                    "id": "INSECURE_METHOD",
                    "severity": "low",
                    "title": f"Insecure HTTP Method {req.get('method')}",
                    "description": f"Endpoint {url} allows {req.get('method')}."
                })
                
        return findings
