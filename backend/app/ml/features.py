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
        signals = payload.get("signals", {})
        domain_sigs = signals.get("domain", {})
        ml_behavior = signals.get("ml_behavior", {})
        interaction = signals.get("interaction", {})
        traps = signals.get("traps", {})
        
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
