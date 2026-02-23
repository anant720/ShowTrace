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
        self.model_dir = "backend/app/ml/models"
        
        # Load trained models
        try:
            self.l1_model = joblib.load(os.path.join(self.model_dir, "l1_xgb.joblib"))
            self.l4_model = joblib.load(os.path.join(self.model_dir, "l4_iso.joblib"))
            self.logger.info("ShadowTrace Enterprise Models Loaded Successfully.")
        except Exception as e:
            self.logger.error(f"Failed to load enterprise models: {e}. Using heuristic fallback.")
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
        # --- Layer Predictions (0-1.0 Scale) ---
        l1_raw = self._predict_l1(features)
        l2_raw = self._predict_l2(features)
        l3_raw = self._predict_l3(features)
        l4_raw = self._predict_l4(features)
        
        scores = {"L1": l1_raw * 100, "L2": l2_raw * 100, "L3": l3_raw * 100, "L4": l4_raw * 100}
        
        # Weighted Stacking
        weighted_avg = sum((scores[layer] / 100) * self.weights[layer] for layer in scores)
        
        # Agreement-based Confidence
        core_vals = [l1_raw, l2_raw, l3_raw]
        std_dev = statistics.stdev(core_vals) if len(core_vals) > 1 else 0
        confidence = max(0.5, 1.0 - (std_dev * 1.5))
        
        # Behavioral Risk Multipliers
        multiplier = 1.0
        if features.get("has_keylogger"): multiplier *= 1.4
        if features.get("brand_similarity", 0) > 0.8: multiplier *= 1.3
        if features.get("obfuscation_score", 0) > 30: multiplier *= 1.2
        
        final_score = min(100.0, (weighted_avg * multiplier) * 100)
        
        return {
            "risk_score": round(final_score, 1),
            "risk_level": self._map_risk_level(final_score),
            "confidence": round(confidence, 2),
            "layer_scores": {k: round(v, 1) for k, v in scores.items()},
            "reasons": self._generate_ml_reasoning(scores, features),
            "explainability": {
                "top_indicators": sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)[:3],
                "behavioral_boost": round((multiplier - 1.0) * 100, 1)
            }
        }

    def _predict_l1(self, f: Dict[str, float]) -> float:
        """Trained XGBoost inference for Lexical signals."""
        if not self.l1_model:
            # Heuristic fallback (simplified)
            score = 0
            if f.get("shannon_entropy", 0) > 4.2: score += 40
            if f.get("has_homograph"): score += 80
            return min(score / 100, 1.0)
        
        # Predict probability
        try:
            # Prepare feature vector in correct order (matching training)
            # For simplicity, we assume order matches. In production, we use a fixed schema.
            ordered_feats = [f.get(k, 0) for k in sorted(f.keys()) if k != 'label']
            X = np.array([ordered_feats])
            return float(self.l1_model.predict_proba(X)[0][1])
        except:
            return 0.5

    def _predict_l2(self, f: Dict[str, float]) -> float:
        """Behavioral Density signal."""
        score = 0
        if f.get("obfuscation_score", 0) > 20: score += 60
        if f.get("event_listener_density", 0) > 5: score += 40
        return min(score / 100, 1.0)

    def _predict_l3(self, f: Dict[str, float]) -> float:
        """Semantic/Intent signal."""
        score = 0
        if f.get("has_login"): score += 40
        if f.get("has_keylogger"): score += 70
        return min(score / 100, 1.0)

    def _predict_l4(self, f: Dict[str, float]) -> float:
        """Isolation Forest Anomaly score."""
        if not self.l4_model:
            return f.get("external_exfiltration_ratio", 0)
        
        try:
            ordered_feats = [f.get(k, 0) for k in sorted(f.keys()) if k != 'label']
            X = np.array([ordered_feats])
            # Isolation Forest returns -1 for anomaly, 1 for normal
            # Scale to 0 (normal) to 1 (highly anomalous)
            decision = self.l4_model.decision_function(X)[0]
            return float(1.0 - (decision + 1.0) / 2.0)
        except:
            return 0.2

    def _map_risk_level(self, score: float) -> str:
        if score > 75: return "Dangerous"
        if score > 40: return "Suspicious"
        return "Safe"

    def _generate_ml_reasoning(self, scores: Dict[str, float], features: Dict[str, float]) -> List[str]:
        reasons = []
        if features.get("brand_similarity", 0) > 0.8:
            reasons.append("Brand Deception: High similarity to a known sensitive brand detected.")
        if features.get("has_homograph"):
            reasons.append("Adversarial: Unicode homograph (look-alike) domain discovered.")
        if features.get("has_keylogger"):
            reasons.append("Infiltration: Active credential field monitoring (Keylogger) signaled.")
        if scores["L1"] > 70:
            reasons.append("ML Engine: Trained lexical model flagged adversarial URL construction.")
        if scores["L4"] > 70:
            reasons.append("Anomaly Engine: Observed behavior deviates significantly from safe baseline.")
        
        if not reasons:
            reasons.append("Heuristic Audit: Standard operational patterns detected.")
        return reasons
