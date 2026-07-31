from __future__ import annotations

import re
import secrets
from copy import deepcopy
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
               novelty: int, execution: dict[str, Any] | None = None,
               parent_score: int | None = None) -> dict[str, Any]:
        clarity = min(100, 35 + len(str(plan.get("story", ""))) // 5)
        execution = execution or {
            "score": 0,
            "passed": False,
            "dimensions": {
                "execution": 0, "adversarial_resistance": 0,
                "determinism": 0, "runtime_integrity": 0,
            },
            "evidence": [],
            "risks": ["executable evaluation was not supplied"],
            "metrics": {},
        }
        dimensions = execution.get("dimensions", {})
        mutation_gain = 50 if parent_score is None else max(
            0, min(100, 50 + int(execution.get("score", 0)) - parent_score)
        )
        score = round(
            int(dimensions.get("execution", 0)) * 0.30
            + int(dimensions.get("adversarial_resistance", 0)) * 0.25
            + int(dimensions.get("determinism", 0)) * 0.10
            + int(dimensions.get("runtime_integrity", 0)) * 0.10
            + novelty * 0.15
            + clarity * 0.05
            + mutation_gain * 0.05
        )
        passed = (
            solver.passed and breaker.passed
            and bool(execution.get("passed")) and score >= 70
        )
        return {
            "score": score,
            "passed": passed,
            "dimensions": {
                "execution": int(dimensions.get("execution", 0)),
                "adversarial_resistance": int(
                    dimensions.get("adversarial_resistance", 0)
                ),
                "determinism": int(dimensions.get("determinism", 0)),
                "runtime_integrity": int(dimensions.get("runtime_integrity", 0)),
                "novelty": novelty,
                "clarity": clarity,
                "mutation_gain": mutation_gain,
            },
            "evidence": solver.evidence + breaker.evidence + list(execution.get("evidence", [])),
            "risks": solver.risks + breaker.risks + list(execution.get("risks", [])),
            "metrics": dict(execution.get("metrics", {})),
        }


class EvolutionEngine:
    """Bounded adversarial selection. It cannot modify code or release gates."""

    def __init__(self, memory: ExperienceMemory) -> None:
        self.memory = memory
        self.solver = SolverAgent()
        self.breaker = BreakerAgent()
        self.judge = JudgeAgent()

    @staticmethod
    def _mutate(
        parent: dict[str, Any],
        *,
        index: int,
        generation: int,
        parent_review: dict[str, Any],
        historical: list[dict[str, Any]],
    ) -> dict[str, Any]:
        plan = deepcopy(parent)
        mechanics = dict(plan.get("mechanics", {}))
        risks = " ".join(map(str, parent_review.get("risks", []))).lower()
        difficulty = str(plan.get("difficulty", "medium"))
        actions: list[str] = []
        if difficulty != "easy" and (
            "shortcut" in risks or index % 2 == 0
        ):
            mechanics["encoding_delta"] = 1
            actions.append("increased transform depth after shortcut probing")
        else:
            mechanics["encoding_delta"] = int(mechanics.get("encoding_delta", 0))
        historical_decoys = [
            int(item.get("mechanics", {}).get("decoy_density", 0))
            for item in historical
            if isinstance(item.get("mechanics"), dict)
        ]
        baseline_decoys = max(historical_decoys, default=-1) + 1
        mechanics["decoy_density"] = max(
            0, min(3, max(int(mechanics.get("decoy_density", 0)) + 1, baseline_decoys))
        )
        mechanics["reasoning_depth"] = max(
            2, min(5, int(mechanics.get("reasoning_depth", 1)) + generation)
        )
        mechanics["mutation_tag"] = f"g{generation}-m{index + 1}"
        actions.append("increased decoy density using retrieved historical mechanics")
        actions.append("added a reasoning stage before the final recovery step")
        perspectives = (
            "Correlate two independent observations before trusting the apparent solution.",
            "Distinguish a plausible decoy path from the state transition that actually matters.",
            "Validate the recovered intermediate value against a second piece of evidence.",
        )
        story = str(plan.get("story", "")).rstrip()
        plan["story"] = (story + " " + perspectives[index % len(perspectives)])[:600]
        plan["mechanics"] = mechanics
        plan["mutation"] = {
            "generation": generation,
            "parent_signature": ExperienceMemory.signature(parent),
            "actions": actions,
            "feedback_risks": list(parent_review.get("risks", []))[:8],
        }
        plan["designer_notes"] = (
            str(plan.get("designer_notes", "")) + " Mutation: " + "; ".join(actions)
        )[:500]
        return plan

    def evolve(self, candidate_factory: Callable[[int, list[str]], dict[str, Any]],
               *, allowed: set[tuple[str, str]], count: int = 3,
               experience_lessons: list[str] | None = None,
               executable_evaluator: Callable[[dict[str, Any], int, int], dict[str, Any]] | None = None,
               generations: int = 2) -> dict[str, Any]:
        count = max(2, min(int(count), 5))
        generations = max(2, min(int(generations), 3))
        run_id = secrets.token_hex(6)
        category = ""
        challenge_type = ""
        difficulty = ""
        candidates: list[tuple[dict[str, Any], dict[str, Any], int, str]] = []
        for index in range(count):
            plan = candidate_factory(index, list(experience_lessons or []))
            category = str(plan.get("category", ""))
            challenge_type = str(plan.get("challenge_type", ""))
            difficulty = str(plan.get("difficulty", ""))
            solver = self.solver.review(plan, allowed)
            breaker = self.breaker.review(plan)
            execution = (
                executable_evaluator(plan, index, 0)
                if executable_evaluator else None
            )
            review = self.judge.review(
                plan, solver, breaker, self.memory.novelty_score(plan), execution
            )
            candidates.append((plan, review, 0, ""))
        historical = self.memory.retrieve(category, challenge_type, difficulty, limit=8)
        for generation in range(1, generations):
            parents = sorted(candidates, key=lambda item: item[1]["score"], reverse=True)[:2]
            offspring: list[tuple[dict[str, Any], dict[str, Any], int, str]] = []
            for index in range(count):
                parent, parent_review, _, _ = parents[index % len(parents)]
                plan = self._mutate(
                    parent,
                    index=index,
                    generation=generation,
                    parent_review=parent_review,
                    historical=historical,
                )
                solver = self.solver.review(plan, allowed)
                breaker = self.breaker.review(plan)
                execution = (
                    executable_evaluator(plan, index, generation)
                    if executable_evaluator else None
                )
                review = self.judge.review(
                    plan, solver, breaker, self.memory.novelty_score(plan),
                    execution, parent_score=int(parent_review.get("score", 0)),
                )
                offspring.append((
                    plan, review, generation, ExperienceMemory.signature(parent)
                ))
            candidates.extend(offspring)
        viable = [item for item in candidates if item[1]["passed"]]
        if not viable:
            risks = [risk for _, review, _, _ in candidates for risk in review["risks"]]
            raise ValueError("all adversarial candidates were rejected: " + "; ".join(risks[:6]))
        winner, winning_review, winner_generation, winner_parent = max(
            viable,
            key=lambda item: (
                item[1]["score"],
                item[2],
                int(item[1]["dimensions"].get("novelty", 0)),
            ),
        )
        for plan, review, generation, parent_signature in candidates:
            self.memory.remember_episode(
                plan,
                score=int(review["score"]),
                passed=bool(review["passed"]),
                lessons=list(review["risks"]) + list(plan.get("mutation", {}).get("actions", [])),
                metrics=dict(review.get("metrics", {})),
                generation=generation,
                run_id=run_id,
                parent_signature=parent_signature,
            )
        initial_best = max(
            review["score"] for _, review, generation, _ in candidates if generation == 0
        )
        winner["evolution"] = {
            "run_id": run_id,
            "agents": ["Generator", "Solver", "Breaker", "Judge"],
            "candidate_count": len(candidates),
            "generations": generations,
            "executed_candidates": len(candidates),
            "winner_score": winning_review["score"],
            "winner_generation": winner_generation,
            "winner_parent_signature": winner_parent,
            "improvement_over_initial": winning_review["score"] - initial_best,
            "winner_review": winning_review,
            "candidates": [
                {
                    "index": index + 1,
                    "generation": generation,
                    "parent_signature": parent_signature,
                    "score": review["score"],
                    "passed": review["passed"],
                    "dimensions": review["dimensions"],
                    "metrics": review.get("metrics", {}),
                    "mechanics": plan.get("mechanics", {}),
                    "mutation_actions": plan.get("mutation", {}).get("actions", []),
                    "evidence": review["evidence"],
                    "risks": review["risks"],
                }
                for index, (plan, review, generation, parent_signature) in enumerate(candidates)
            ],
            "memory": self.memory.stats(),
            "historical_retrieval": {
                "episodes": len(historical),
                "lessons": list(experience_lessons or [])[:8],
            },
            "score_basis": "built bundles, repeated solver execution, export leak probes, runtime probes, mutation gain, and retrieved novelty",
            "bounded": True,
            "self_modification": False,
        }
        return winner
