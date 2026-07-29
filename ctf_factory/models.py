from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


DIFFICULTIES = ("easy", "medium", "hard")


@dataclass
class ChallengeSpec:
    slug: str
    title: str
    category: str
    challenge_type: str
    difficulty: str
    story: str
    vulnerability: str
    intended_solution: list[str]
    hints: list[str] = field(default_factory=list)
    delivery: str = "static"
    port: int | None = None
    variant: str = "default"
    seed: str | None = None
    flag: str = "flag{local_training_only}"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ChallengeSpec":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in value.items() if k in allowed})

    def to_dict(self, *, include_flag: bool = True) -> dict[str, Any]:
        result = asdict(self)
        if not include_flag:
            result.pop("flag", None)
        return result


@dataclass
class GateReport:
    passed: bool
    checks: list[str]
    failures: list[str]

