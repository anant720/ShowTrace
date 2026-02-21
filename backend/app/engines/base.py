"""
ShadowTrace Backend — Engine Base

Uniform interface for all detection engines.
Each engine produces an EngineResult with a normalized score.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class EngineResult:
    """Standard output from any detection engine."""
    engine_name: str
    score: float          # Raw score from this engine
    max_score: float      # Maximum possible score for this engine
    reasons: List[str] = field(default_factory=list)

    @property
    def normalized(self) -> float:
        """Score as 0.0–1.0 fraction of max."""
        if self.max_score <= 0:
            return 0.0
        return min(self.score / self.max_score, 1.0)
