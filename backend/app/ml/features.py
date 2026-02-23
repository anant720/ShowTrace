import re
import math
from typing import Dict, Any, List
from urllib.parse import urlparse
import Levenshtein

class FeatureEngineer:
    """
    ShadowTrace Enterprise Engine — Advanced Forensic Signal Extraction v5.0
    Implements a 5-dimension signal matrix for high-fidelity threat detection.
    """

    # High-risk sector targets for context-aware scoring
    SENSITIVE_SECTORS = {
        "finance": ["chase", "wells fargo", "bankofamerica", "paypal", "binance", "coinbase", "stripe"],
        "productivity": ["google", "microsoft", "outlook", "office", "github", "dropbox", "dropbox"],
        "commerce": ["amazon", "walmart", "target", "ebay", "shopify"],
        "social": ["facebook", "instagram", "twitter", "linkedin", "tiktok", "snapchat"]
    }

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
        parsed_url = urlparse(full_url)
        hostname = parsed_url.netloc
        
        features = {}
        
        # --- Layer 1: Lexical & Structural ---
        features.update(FeatureEngineer.lexical_features(full_url, domain_sigs))
        
        # --- Layer 2: Brand/Deception Metrics ---
        brand_sim, sector = FeatureEngineer.calculate_brand_and_sector(hostname)
        features["brand_similarity"] = brand_sim
        features["target_sector_criticality"] = 1.0 if sector in ["finance", "productivity"] else 0.5 if sector else 0.0
        
        # --- Layer 3: Behavioral & JS Anomaly ---
        features["eval_count"] = float(ml_behavior.get("evalCount", 0))
        features["large_hex_count"] = float(ml_behavior.get("largeHexCount", 0))
        features["event_listener_density"] = float(interaction.get("suspiciousHandlerCount", 0))
        
        # Structural Complexity Indicator (Sign of complex phishing kits)
        features["dom_node_count"] = float(payload.get("meta", {}).get("domNodeCount", 1000)) 
        features["obfuscation_score"] = (features["eval_count"] * 15) + (features["large_hex_count"] * 8)
        
        # --- Layer 4: Forensic Indicators ---
        features["has_keylogger"] = 1.0 if interaction.get("hasGlobalKeylogger") else 0.0
        features["has_login"] = 1.0 if forms.get("hasLoginForm") else 0.0
        features["has_hidden_inputs"] = 1.0 if forms.get("stats", {}).get("hiddenFieldCount", 0) > 5 else 0.0
        
        # Advanced Network depth
        features["external_exfiltration_ratio"] = FeatureEngineer.calculate_exfiltration_ratio(full_url, network_reqs)
        features["cross_origin_form_actions"] = 1.0 if forms.get("stats", {}).get("crossDomainActions", 0) > 0 else 0.0
        
        return features

    @staticmethod
    def lexical_features(url: str, domain_sigs: Dict[str, Any]) -> Dict[str, float]:
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        
        # Homograph detection (Non-ASCII detection)
        has_homograph = 1.0 if re.search(r'[^\x00-\x7F]', hostname) and not hostname.startswith('xn--') else 0.0
        
        # Character distribution (Sign of random generation/DGA)
        letters = len(re.findall(r'[a-zA-Z]', hostname))
        digits = len(re.findall(r'[0-9]', hostname))
        digit_ratio = digits / (letters + digits) if (letters + digits) > 0 else 0
        
        return {
            "url_length": float(len(url)),
            "host_length": float(len(hostname)),
            "subdomain_depth": float(len(hostname.split(".")) - 2) if "." in hostname else 0.0,
            "shannon_entropy": FeatureEngineer.calculate_entropy(hostname),
            "path_entropy": FeatureEngineer.calculate_entropy(path),
            "has_homograph": has_homograph,
            "digit_ratio": digit_ratio,
            "is_ip": 1.0 if domain_sigs.get("isIPBased") else 0.0,
            "is_https": 1.0 if domain_sigs.get("isHTTPS") else 0.0
        }

    @staticmethod
    def calculate_brand_and_sector(hostname: str) -> (float, str):
        """Detects if a domain is 'shadowing' a major brand and identifies the target sector."""
        if not hostname: return 0.0, None
        base_host = hostname.split('.')[-2] if len(hostname.split('.')) >= 2 else hostname
        base_host = base_host.lower()
        
        scores = []
        found_sector = None
        
        for sector, brands in FeatureEngineer.SENSITIVE_SECTORS.items():
            for brand in brands:
                dist = Levenshtein.distance(base_host, brand)
                if dist == 0: continue # Whitelisted usually
                
                if dist <= 2:
                    score = 1.0 - (dist / len(brand))
                    scores.append(score)
                    if score > 0.6: found_sector = sector
        
        return (max(scores) if scores else 0.0), found_sector

    @staticmethod
    def calculate_exfiltration_ratio(base_url: str, requests: List[Dict]) -> float:
        if not requests: return 0.0
        landing_host = urlparse(base_url).netloc
        external = [r for r in requests if urlparse(r.get("url", "")).netloc != landing_host]
        return len(external) / len(requests)

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text: return 0.0
        probs = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs)
