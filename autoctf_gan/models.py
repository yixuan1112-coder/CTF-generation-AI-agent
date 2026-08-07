"""AutoCTF-GAN data model — Step 1.

Extends the `ctf_factory.models.ChallengeSpec` shape (same field names where they
overlap: slug/title/category/challenge_type/difficulty/story/flag/seed/mechanics)
with the four things the co-evolution loop needs and the base repo lacks:

  * lineage          — archetype id, generation index (Gen-N), parent, mutation ops
  * vuln_chain        — the ordered exploit chain; its *length* is the difficulty
  * artifacts         — the concrete files handed to players (path -> content)
  * official_solver   — the MANDATORY paired PoC (principle P1)
  * verification      — filled by verify_spec(); a spec is only deployable when valid

Kept as stdlib dataclasses (no pydantic dependency) to match the base repo and to
stay runnable anywhere. `to_ctf_factory_dict()` maps back onto the base
`ChallengeSpec` fields for drop-in reuse.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

DIFFICULTIES = ("easy", "medium", "hard")
CATEGORIES = ("web", "pwn", "reverse", "crypto", "forensics", "misc")


@dataclass
class Lineage:
    archetype_id: str
    generation: int = 0                       # Gen-N index
    parent_spec_id: str | None = None
    mutation_ops: list[str] = field(default_factory=list)
    seed: int = 0                             # P4: full reproducibility


@dataclass
class ChainStep:
    step: int
    primitive: str                            # e.g. "positional_shift", "xor", "b64"
    params: dict[str, Any] = field(default_factory=dict)
    guard: str | None = None                  # what blocks the trivial one-step path


@dataclass
class OfficialSolver:
    """The paired PoC. Without a passing one, the spec is invalid (P1)."""
    entry: str = "solver.py"
    files: dict[str, str] = field(default_factory=dict)   # path -> source
    expected_flag_sha256: str = ""            # verify without storing the flag (P5)
    max_runtime_s: int = 120
    deterministic: bool = True


@dataclass
class Verification:
    """Filled by verify_spec(). status stays 'pending' until the gate runs."""
    status: str = "pending"                   # pending | valid | rejected
    poc_passed: bool | None = None
    leak_gates_passed: bool | None = None
    determinism_runs: int = 0
    trivial_shortcut: bool | None = None
    measured_solve_time_s: float | None = None
    rejection_reason: str | None = None


@dataclass
class ChallengeSpec:
    # ---- fields shared with ctf_factory.models.ChallengeSpec ----------------
    slug: str
    title: str
    category: str
    challenge_type: str
    difficulty: str
    story: str
    vulnerability: str                        # one-line human summary
    intended_solution: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    delivery: str = "attachment"
    seed: int = 0
    mechanics: dict[str, Any] = field(default_factory=dict)
    flag: str = "flag{local_training_only}"   # organizer-only

    # ---- AutoCTF-GAN extensions --------------------------------------------
    spec_id: str = ""
    lineage: Lineage = field(default_factory=lambda: Lineage(archetype_id="unset"))
    vuln_chain: list[ChainStep] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)      # player files
    official_solver: OfficialSolver = field(default_factory=OfficialSolver)
    verification: Verification = field(default_factory=Verification)
    target_solve_rate: float = 0.05           # elite band centre

    # ---- (de)serialization --------------------------------------------------
    @property
    def intended_depth(self) -> int:
        return len(self.vuln_chain)

    def to_dict(self, *, include_flag: bool = True) -> dict[str, Any]:
        data = asdict(self)
        if not include_flag:
            data.pop("flag", None)
            # solver files + mechanics can contain the answer path — organizer only
            data.get("official_solver", {}).pop("files", None)
            data.pop("mechanics", None)
        return data

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ChallengeSpec":
        v = dict(value)
        if isinstance(v.get("lineage"), dict):
            v["lineage"] = Lineage(**v["lineage"])
        if isinstance(v.get("official_solver"), dict):
            v["official_solver"] = OfficialSolver(**v["official_solver"])
        if isinstance(v.get("verification"), dict):
            v["verification"] = Verification(**v["verification"])
        if isinstance(v.get("vuln_chain"), list):
            v["vuln_chain"] = [
                ChainStep(**s) if isinstance(s, dict) else s for s in v["vuln_chain"]
            ]
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: val for k, val in v.items() if k in allowed})

    def to_ctf_factory_dict(self) -> dict[str, Any]:
        """Project onto the base ctf_factory.ChallengeSpec field set."""
        return {
            "slug": self.slug,
            "title": self.title,
            "category": self.category,
            "challenge_type": self.challenge_type,
            "difficulty": self.difficulty,
            "story": self.story,
            "vulnerability": self.vulnerability,
            "intended_solution": self.intended_solution,
            "hints": self.hints,
            "delivery": self.delivery,
            "variant": self.lineage.mutation_ops[-1] if self.lineage.mutation_ops else "default",
            "seed": str(self.seed),
            "mechanics": self.mechanics,
            "flag": self.flag,
        }


@dataclass
class Verdict:
    """Result of the verify_spec gate (mirrors ctf_factory.GateReport intent)."""
    valid: bool
    reason: str
    poc_time_s: float | None = None
    checks: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
