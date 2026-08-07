"""ChallengeSpec JSON Schema + validator — Step 1.

Uses `jsonschema` (available in the environment). Swap for pydantic's
`model_json_schema()` if you standardise on pydantic later; the shape matches
`models.ChallengeSpec`.
"""
from __future__ import annotations

from typing import Any

import jsonschema

from .models import CATEGORIES, DIFFICULTIES

CHALLENGE_SPEC_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "ChallengeSpec",
    "type": "object",
    "required": [
        "slug", "title", "category", "challenge_type", "difficulty",
        "story", "vulnerability", "vuln_chain", "artifacts",
        "official_solver", "flag", "lineage",
    ],
    "properties": {
        "slug": {"type": "string", "pattern": "^[a-z0-9-]{3,80}$"},
        "title": {"type": "string", "minLength": 4},
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "challenge_type": {"type": "string", "minLength": 2},
        "difficulty": {"type": "string", "enum": list(DIFFICULTIES)},
        "story": {"type": "string", "maxLength": 600},
        "vulnerability": {"type": "string", "minLength": 3},
        "intended_solution": {"type": "array", "items": {"type": "string"}},
        "hints": {"type": "array", "maxItems": 3, "items": {"type": "string"}},
        "delivery": {"type": "string"},
        "flag": {"type": "string", "pattern": r"^flag\{.+\}$"},
        "target_solve_rate": {"type": "number", "minimum": 0, "maximum": 1},
        "lineage": {
            "type": "object",
            "required": ["archetype_id", "generation"],
            "properties": {
                "archetype_id": {"type": "string"},
                "generation": {"type": "integer", "minimum": 0},
                "parent_spec_id": {"type": ["string", "null"]},
                "mutation_ops": {"type": "array", "items": {"type": "string"}},
                "seed": {"type": "integer"},
            },
        },
        "vuln_chain": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["step", "primitive"],
                "properties": {
                    "step": {"type": "integer"},
                    "primitive": {"type": "string"},
                    "params": {"type": "object"},
                    "guard": {"type": ["string", "null"]},
                },
            },
        },
        "artifacts": {"type": "object"},
        "official_solver": {
            "type": "object",
            "required": ["entry", "files", "expected_flag_sha256"],
            "properties": {
                "entry": {"type": "string"},
                "files": {"type": "object", "minProperties": 1},
                "expected_flag_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "max_runtime_s": {"type": "integer", "minimum": 1},
                "deterministic": {"type": "boolean"},
            },
        },
        "verification": {"type": "object"},
        "mechanics": {"type": "object"},
    },
}

_validator = jsonschema.Draft7Validator(CHALLENGE_SPEC_SCHEMA)


def validate_spec_dict(data: dict[str, Any]) -> list[str]:
    """Return a list of human-readable schema errors ([] means valid)."""
    errors = []
    for err in sorted(_validator.iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(map(str, err.path)) or "<root>"
        errors.append(f"{loc}: {err.message}")
    return errors
