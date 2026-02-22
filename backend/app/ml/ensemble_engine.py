import logging
import statistics
from typing import Dict, Any, List

class EnsembleScorer:
    """
    ShadowTrace Phase 4 — Hybrid Ensemble Engine.
    Orchestrates 4 ML layers to produce a high-confidence risk score.
    """

    def __init__(self):
        self.logger = logging.getLogger("shadowtrace.ml.ensemble")
        # Weights as defined in Phase 4 Design Doc
        self.weights = {
            "L1": 0.20,  # Lexical
            "L2": 0.30,  # Behavioral
            "L3": 0.40,  # Semantic
            "L4": 0.10   # Anomaly
        }

    async def calculate_ensemble_score(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Calculates a stacked risk score and confidence metric.
        """
        # --- Layer 1: Lexical ML (Simulator) ---
        l1_score = self._predict_l1(features)
        
        # --- Layer 2: Behavioral ML (Simulator) ---
        l2_score = self._predict_l2(features)
        
        # --- Layer 3: Semantic ML (Simulator) ---
        l3_score = self._predict_l3(features)
        
        # --- Layer 4: Anomaly ML (Simulator) ---
        l4_score = self._predict_l4(features)
        
        scores = {"L1": l1_score, "L2": l2_score, "L3": l3_score, "L4": l4_score}
        
        # Weighted Stacking
        final_score = sum(scores[layer] * self.weights[layer] for layer in scores)
        
        # Confidence Calculation (Standard Deviation across model layers)
        # Low variance = High agreement = High confidence
        std_dev = statistics.stdev([l1_score, l2_score, l3_score]) if len(scores) > 1 else 0
        confidence = max(0.0, 1.0 - (std_dev / 50.0))
        
        # ML-based Reasoning Generation
        reasons = self._generate_ml_reasoning(scores, features)
        
        return {
            "final_score": round(final_score, 1),
            "confidence": round(confidence, 2),
            "layer_scores": scores,
            "reasons": reasons,
            "explainability": {
                "top_features": sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
            }
        }

    def _predict_l1(self, f: Dict[str, float]) -> float:
        """Lightweight Lexical Prediction logic."""
        score = 0
        if f.get("entropy", 0) > 3.8: score += 40
        if f.get("dot_count", 0) > 3: score += 20
        if f.get("special_char_count", 0) > 5: score += 20
        if f.get("is_ip"): score += 50
        return min(score, 100)

    def _predict_l2(self, f: Dict[str, float]) -> float:
        """Lightweight Behavioral Prediction logic."""
        score = 0
        if f.get("eval_count", 0) > 0: score += 30
        if f.get("large_hex_count", 0) > 0: score += 40
        if f.get("form_traps", 0) > 0: score += 50
        if f.get("suspicious_handlers", 0) > 2: score += 40
        return min(score, 100)

    def _predict_l3(self, f: Dict[str, float]) -> float:
        """Lightweight Semantic Prediction (Mock DistilBERT)."""
        # In production, this would be a DistilBERT inference call
        score = 0
        # If L2 is high, L3 usually follows in phishing
        if f.get("form_traps", 0) > 0: score += 60
        return min(score, 100)

    def _predict_l4(self, f: Dict[str, float]) -> float:
        """Lightweight Anomaly Prediction logic."""
        return 10.0 # Baseline

    def _generate_ml_reasoning(self, scores: Dict[str, float], features: Dict[str, float]) -> List[str]:
        reasons = []
        if scores["L1"] > 50:
            reasons.append(f"L1 Lexical Engine detected structural anomalies (Entropy: {features.get('entropy'):.2f})")
        if scores["L2"] > 50:
            reasons.append("L2 Behavioral Engine identified high-risk scripting patterns (Eval/Trap hooks detected)")
        if scores["L3"] > 50:
            reasons.append("L3 Semantic Engine flagged phishing-intent content structure")
        
        if not reasons:
            reasons.append("No critical ML triggers identified")
        return reasons
