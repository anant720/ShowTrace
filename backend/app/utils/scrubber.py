import re
import json

class CredentialScrubber:
    """Utility to redact sensitive information from forensic payloads."""
    
    PATTERNS = [
        # Authorization Headers
        (re.compile(r'(Authorization:\s*Bearer\s+)[^ \n\r]+', re.I), r'\1[REDACTED_JWT]'),
        (re.compile(r'(X-API-Key:\s*)[^ \n\r]+', re.I), r'\1[REDACTED_KEY]'),
        (re.compile(r'(X-Auth-Token:\s*)[^ \n\r]+', re.I), r'\1[REDACTED_TOKEN]'),
        
        # JSON / Form Fields
        (re.compile(r'("(?:password|pass|secret|token|apikey|jwt|sid)")\s*:\s*"[^"]+"', re.I), r'\1:"[REDACTED]"'),
        (re.compile(r'((?:password|pass|secret|token|apikey|jwt|sid)=)([^&]+)', re.I), r'\1[REDACTED]'),
        
        # JWT raw patterns in text
        (re.compile(r'eyJ[a-zA-Z0-0_-]+\.eyJ[a-zA-Z0-0_-]+\.[a-zA-Z0-0_-]+'), '[REDACTED_JWT_BLOB]')
    ]

    @classmethod
    def scrub_text(cls, text: str) -> str:
        if not text:
            return text
        
        scrubbed = text
        for pattern, replacement in cls.PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
            
        return scrubbed

    @classmethod
    def scrub_requests(cls, requests: list) -> list:
        if not requests:
            return []
        
        scrubbed_reqs = []
        for req in requests:
            new_req = req.copy()
            
            # Scrub Request Body
            if "requestBody" in new_req and isinstance(new_req["requestBody"], str):
                new_req["requestBody"] = cls.scrub_text(new_req["requestBody"])
            
            # Scrub URL Parameters
            if "url" in new_req and isinstance(new_req["url"], str):
                new_req["url"] = cls.scrub_text(new_req["url"])
            
            # Scrub Headers
            if "requestHeaders" in new_req and isinstance(new_req["requestHeaders"], list):
                new_headers = []
                for h in new_req["requestHeaders"]:
                    h_name = h.get("name", "").lower()
                    if h_name in ["authorization", "x-api-key", "x-auth-token", "cookie"]:
                        new_headers.append({
                            "name": h["name"],
                            "value": cls.scrub_text(h["value"])
                        })
                    else:
                        new_headers.append(h)
                new_req["requestHeaders"] = new_headers
                
            scrubbed_reqs.append(new_req)
            
        return scrubbed_reqs
