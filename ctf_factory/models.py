from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ChallengeSpec:
    slug: str
    title: str
    category: str
    difficulty: str
    story: str
    vulnerability: str
    intended_solution: list[str]
    hints: list[str] = field(default_factory=list)
    port: int = 8000
    flag: str = "flag{local_training_only}"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ChallengeSpec":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in value.items() if k in allowed})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GateReport:
    passed: bool
    checks: list[str]
    failures: list[str]

