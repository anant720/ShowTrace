import logging
import statistics
import os
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, List

class EnsembleScorer:
    """
    ShadowTrace Enterprise Engine v5.0 — Multi-Layer Defensive Ensemble.
    Hardened orchestration with Gradient Boosting & Isolation Forest.
    """

    def __init__(self):
        self.logger = logging.getLogger("shadowtrace.ml.ensemble")
        # Robust path detection relative to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_dir = os.path.join(base_dir, "models")
        
        # Load trained models
        try:
            l1_path = os.path.join(self.model_dir, "l1_xgb.joblib")
            l4_path = os.path.join(self.model_dir, "l4_iso.joblib")
            
            self.l1_model = joblib.load(l1_path)
            self.l4_model = joblib.load(l4_path)
            self.logger.info(f"ShadowTrace Enterprise Models Loaded Successfully from {self.model_dir}")
        except Exception as e:
            self.logger.error(f"Failed to load enterprise models from {self.model_dir}: {e}. Using heuristic fallback.")
            self.l1_model = None
            self.l4_model = None

        # Tuned weights for Enterprise Defensive posture
        self.weights = {
            "L1": 0.40,  # XGBoost Lexical (Trained)
            "L2": 0.25,  # Behavioral
            "L3": 0.20,  # Semantic
            "L4": 0.15   # Isolation Forest (Trained)
        }

    async def calculate_ensemble_score(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Enterprise-grade risk calculation with tiered ensemble inference.
        """
        # 1. Adaptive Weighting based on Target Sector
        active_weights = self.weights.copy()
        
        # If site is a high-value sector target (Bank/Work), increase Semantic & Behavioral weight
        criticality = features.get("target_sector_criticality", 0.0)
        if criticality > 0.8:
            active_weights["L3"] += 0.15 # Semantic (Brand Deception)
            active_weights["L2"] += 0.05 # Behavioral
            active_weights["L1"] -= 0.20 # Phishers hide lexical signals well
        elif criticality > 0.4:
            active_weights["L3"] += 0.05
            active_weights["L1"] -= 0.05

        # --- Layer Predictions (0-1.0 Scale) ---
        l1_raw = self._predict_l1(features)
        l2_raw = self._predict_l2(features)
        l3_raw = self._predict_l3(features)
        l4_raw = self._predict_l4(features)
        
        scores = {"L1": l1_raw * 100, "L2": l2_raw * 100, "L3": l3_raw * 100, "L4": l4_raw * 100}
        
        # Weighted Stacking
        weighted_avg = sum((scores[layer] / 100) * active_weights[layer] for layer in scores)
        
        # 2. Advanced Threat Multipliers (Exponential)
        threat_count = 0
        if features.get("has_keylogger"): threat_count += 2 
        if features.get("brand_similarity", 0) > 0.7: threat_count += 1
        if features.get("obfuscation_score", 0) > 50: threat_count += 1
        if features.get("has_homograph"): threat_count += 1
        if features.get("cross_origin_form_actions"): threat_count += 1
        
        # Sector Multiplier: Targeted attacks on sensitive sectors are higher risk
        sector_multiplier = 1.0 + (criticality * 0.4)
        behavior_multiplier = 1.0 + (threat_count * 0.3)
        
        # Complexity Multiplier (Phishing kits are often very heavy/complex)
        complexity_multiplier = 1.1 if features.get("dom_node_count", 0) > 3000 else 1.0
        
        total_multiplier = sector_multiplier * behavior_multiplier * complexity_multiplier
        
        # Final Score Calculation
        base_risk = 0.0
        if not features.get("is_https"): base_risk += 10.0
        if features.get("is_ip"): base_risk += 15.0
        
        final_score = min(100.0, (weighted_avg * 100 * total_multiplier) + base_risk)
        
        # Agreement-based Confidence
        core_vals = [l1_raw, l2_raw, l3_raw]
        std_dev = statistics.stdev(core_vals) if len(core_vals) > 1 else 0
        confidence = max(0.40, 1.0 - (std_dev * 2.0))
        
        return {
            "risk_score": round(final_score, 1),
            "risk_level": self._map_risk_level(final_score),
            "confidence": round(confidence, 2),
            "layer_scores": {k: round(v, 1) for k, v in scores.items()},
            "reasons": self._generate_ml_reasoning(scores, features),
            "explainability": {
                "top_indicators": sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)[:4],
                "threat_density": threat_count,
                "criticality_index": criticality
            }
        }

    def _predict_l1(self, f: Dict[str, float]) -> float:
        """Trained XGBoost inference for Lexical signals."""
        if not self.l1_model:
            score = 0
            if f.get("shannon_entropy", 0) > 4.8: score += 45
            if f.get("digit_ratio", 0) > 0.4: score += 35
            if f.get("has_homograph"): score += 95
            if f.get("subdomain_depth", 0) > 3: score += 25
            return min(score / 100, 1.0)
        
        try:
            ordered_feats = [f.get(k, 0) for k in sorted(f.keys()) if k != 'label']
            X = np.array([ordered_feats])
            return float(self.l1_model.predict_proba(X)[0][1])
        except:
            return 0.5

    def _predict_l2(self, f: Dict[str, float]) -> float:
        """Behavioral Density signal."""
        score = 0
        obf = f.get("obfuscation_score", 0)
        if obf > 60: score += 90
        elif obf > 25: score += 45
        
        density = f.get("event_listener_density", 0)
        if density > 10: score += 65
        if f.get("has_hidden_inputs"): score += 30
        return min(score / 100, 1.0)

    def _predict_l3(self, f: Dict[str, float]) -> float:
        """Semantic/Intent signal."""
        score = 0
        similarity = f.get("brand_similarity", 0)
        criticality = f.get("target_sector_criticality", 0)
        
        if similarity > 0.8:
            score += 95 if criticality > 0.6 else 75
        elif similarity > 0.4:
            score += 55
            
        if f.get("has_login") and similarity > 0.2: score += 45
        if f.get("cross_origin_form_actions"): score += 65
        if f.get("has_keylogger"): score += 95
        return min(score / 100, 1.0)

    def _predict_l4(self, f: Dict[str, float]) -> float:
        """Isolation Forest Anomaly score."""
        if not self.l4_model:
            ratio = f.get("external_exfiltration_ratio", 0)
            return min(ratio * 2.2, 1.0)
        
        try:
            ordered_feats = [f.get(k, 0) for k in sorted(f.keys()) if k != 'label']
            X = np.array([ordered_feats])
            decision = self.l4_model.decision_function(X)[0]
            return float(1.0 - (decision + 1.0) / 2.0)
        except:
            return 0.2

    def _map_risk_level(self, score: float) -> str:
        if score >= 65: return "Dangerous"
        if score >= 30: return "Suspicious"
        return "Safe"

    def _generate_ml_reasoning(self, scores: Dict[str, float], features: Dict[str, float]) -> List[str]:
        reasons = []
        similarity = features.get("brand_similarity", 0)
        criticality = features.get("target_sector_criticality", 0)
        
        if similarity > 0.7:
            vuln_type = "Targeted Phishing" if criticality > 0.8 else "Brand Impersonation"
            reasons.append(f"{vuln_type}: Site precisely mirrors protected work/finance assets ({round(similarity*100)}% match).")
        
        if features.get("has_keylogger"):
            reasons.append("Credential Interception: Active DOM hooks monitoring sensitive input streams for exfiltration.")
        
        if features.get("cross_origin_form_actions"):
            reasons.append("Data Diversion: Form submissions routed to unauthorized external infrastructure.")
            
        if features.get("shannon_entropy", 0) > 4.7:
            reasons.append("Structural Anomaly: Cryptographic host-string signature detected (high tunnel/DGA risk).")
            
        if scores["L2"] > 80:
            reasons.append("Anti-Analysis: Sophisticated JS obfuscation layer active to prevent forensic inspection.")
        
        if not reasons:
            reasons.append("Heuristic Baseline: Page behavior is consistent with standard enterprise operational standards.")
        return reasons
