from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any, Callable

from .memory import ExperienceMemory


@dataclass(frozen=True)
class AgentReview:
    score: int
    passed: bool
    evidence: list[str]
    risks: list[str]


class SolverAgent:
    def review(self, plan: dict[str, Any], allowed: set[tuple[str, str]]) -> AgentReview:
        risks: list[str] = []
        evidence: list[str] = []
        key = (str(plan.get("category", "")), str(plan.get("challenge_type", "")))
        if key in allowed:
            evidence.append("reviewed build primitive is available")
        else:
            risks.append("no reviewed build primitive")
        hints = plan.get("hints")
        if isinstance(hints, list) and 1 <= len(hints) <= 3:
            evidence.append("progressive hint path is present")
        else:
            risks.append("missing progressive hints")
        if str(plan.get("story", "")).strip():
            evidence.append("player objective has narrative context")
        else:
            risks.append("empty player objective")
        score = max(0, 100 - len(risks) * 35)
        return AgentReview(score, not risks, evidence, risks)


class BreakerAgent:
    DANGEROUS = re.compile(
        r"flag\{[^}]+\}|https?://(?!localhost|127\.0\.0\.1)|BEGIN .*PRIVATE KEY|"
        r"sk-[A-Za-z0-9_-]{16,}", re.IGNORECASE
    )

    def review(self, plan: dict[str, Any]) -> AgentReview:
        risks: list[str] = []
        evidence: list[str] = []
        public = " ".join([
            str(plan.get("title", "")),
            str(plan.get("story", "")),
            " ".join(map(str, plan.get("hints", []))) if isinstance(plan.get("hints"), list) else "",
        ])
        if self.DANGEROUS.search(public):
            risks.append("public design contains a flag, credential, or external target")
        else:
            evidence.append("no public secret or external target pattern")
        if len(str(plan.get("story", ""))) > 600:
            risks.append("story exceeds the public design boundary")
        if len(str(plan.get("title", ""))) < 4:
            risks.append("title is too weak to identify the challenge")
        hints = [str(x).lower() for x in plan.get("hints", [])] if isinstance(plan.get("hints"), list) else []
        if any("flag{" in hint or "solution:" in hint for hint in hints):
            risks.append("a hint appears to reveal the answer")
        if not risks:
            evidence.append("public design passed adversarial disclosure checks")
        score = max(0, 100 - len(risks) * 45)
        return AgentReview(score, not risks, evidence, risks)


class JudgeAgent:
    def review(self, plan: dict[str, Any], solver: AgentReview, breaker: AgentReview,
               novelty: int) -> dict[str, Any]:
        clarity = min(100, 35 + len(str(plan.get("story", ""))) // 5)
        score = round(solver.score * 0.35 + breaker.score * 0.30 +
                      novelty * 0.20 + clarity * 0.15)
        passed = solver.passed and breaker.passed and score >= 70
        return {
            "score": score,
            "passed": passed,
            "dimensions": {
                "solvability": solver.score,
                "safety": breaker.score,
                "novelty": novelty,
                "clarity": clarity,
            },
            "evidence": solver.evidence + breaker.evidence,
            "risks": solver.risks + breaker.risks,
        }


class EvolutionEngine:
    """Bounded adversarial selection. It cannot modify code or release gates."""

    def __init__(self, memory: ExperienceMemory) -> None:
        self.memory = memory
        self.solver = SolverAgent()
        self.breaker = BreakerAgent()
        self.judge = JudgeAgent()

    def evolve(self, candidate_factory: Callable[[int, list[str]], dict[str, Any]],
               *, allowed: set[tuple[str, str]], count: int = 3,
               experience_lessons: list[str] | None = None) -> dict[str, Any]:
        count = max(2, min(int(count), 5))
        candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for index in range(count):
            plan = candidate_factory(index, list(experience_lessons or []))
            solver = self.solver.review(plan, allowed)
            breaker = self.breaker.review(plan)
            review = self.judge.review(plan, solver, breaker, self.memory.novelty_score(plan))
            candidates.append((plan, review))
        viable = [item for item in candidates if item[1]["passed"]]
        if not viable:
            risks = [risk for _, review in candidates for risk in review["risks"]]
            raise ValueError("all adversarial candidates were rejected: " + "; ".join(risks[:6]))
        winner, winning_review = max(viable, key=lambda item: item[1]["score"])
        winner["evolution"] = {
            "run_id": secrets.token_hex(6),
            "agents": ["Generator", "Solver", "Breaker", "Judge"],
            "candidate_count": len(candidates),
            "winner_score": winning_review["score"],
            "winner_review": winning_review,
            "candidates": [
                {"index": index + 1, "score": review["score"], "passed": review["passed"],
                 "dimensions": review["dimensions"], "risks": review["risks"]}
                for index, (_, review) in enumerate(candidates)
            ],
            "memory": self.memory.stats(),
            "bounded": True,
            "self_modification": False,
        }
        return winner
