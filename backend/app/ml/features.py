import re
import math
from typing import Dict, Any
from urllib.parse import urlparse

class FeatureEngineer:
    """
    Transforms raw telemetry signals from the browser extension 
    into a numerical feature vector suitable for ML layers.
    """

    @staticmethod
    def extract_all(payload: Dict[str, Any]) -> Dict[str, float]:
        domain_sigs = payload.get("domain", {})
        ml_behavior = payload.get("ml_behavior", {})
        interaction = payload.get("interaction", {})
        traps = payload.get("traps", {})
        forms = payload.get("forms", {})
        behavior = payload.get("behavior", {})
        network_reqs = payload.get("network_requests", [])
        
        full_url = payload.get("full_url", "")
        
        features = {}
        
        # --- Layer 1: Lexical Features ---
        features.update(FeatureEngineer.lexical_features(full_url, domain_sigs))
        
        # --- Layer 2: Behavioral Features ---
        features["eval_count"] = float(ml_behavior.get("evalCount", 0))
        features["large_hex_count"] = float(ml_behavior.get("largeHexCount", 0))
        features["suspicious_handlers"] = float(interaction.get("suspiciousHandlerCount", 0))
        features["form_traps"] = float(traps.get("hiddenFormCount", 0) + traps.get("offscreenElementCount", 0))
        features["has_keylogger"] = 1.0 if interaction.get("hasGlobalKeylogger") else 0.0
        features["has_login"] = 1.0 if forms.get("hasLoginForm") else 0.0
        
        # --- Injection Signals ---
        features["external_fetch_detected"] = 1.0 if behavior.get("externalFetchDetected") else 0.0
        features["external_xhr_detected"] = 1.0 if behavior.get("externalXHRDetected") else 0.0
        features["suspicious_submission_count"] = float(len(behavior.get("suspiciousSubmissions", [])))
        
        # --- Network-Level features (New) ---
        req_count = len(network_reqs)
        features["network_request_count"] = float(req_count)
        
        if req_count > 0:
            posts = [r for r in network_reqs if r.get("method") == "POST"]
            features["post_ratio"] = len(posts) / req_count
            
            # Identify requests to domains other than the landing domain
            landing_host = urlparse(full_url).netloc
            external = [r for r in network_reqs if urlparse(r.get("url", "")).netloc != landing_host]
            features["external_request_ratio"] = len(external) / req_count
        else:
            features["post_ratio"] = 0.0
            features["external_request_ratio"] = 0.0
            
        return features

    @staticmethod
    def lexical_features(url: str, domain_sigs: Dict[str, Any]) -> Dict[str, float]:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        return {
            "url_length": float(len(url)),
            "host_length": float(len(hostname)),
            "dot_count": float(hostname.count(".")),
            "special_char_count": float(len(re.findall(r"[@\-_=%&?]", url))),
            "subdomain_depth": float(len(hostname.split(".")) - 2) if "." in hostname else 0.0,
            "is_ip": 1.0 if domain_sigs.get("isIPBased") else 0.0,
            "is_https": 1.0 if domain_sigs.get("isHTTPS") else 0.0,
            "entropy": float(domain_sigs.get("entropy", 0.0))
        }

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text: return 0.0
        probs = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs)
