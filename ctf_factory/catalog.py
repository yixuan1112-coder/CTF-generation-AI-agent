from __future__ import annotations

from dataclasses import dataclass

from .models import DIFFICULTIES, ChallengeSpec


@dataclass(frozen=True)
class TemplateInfo:
    category: str
    challenge_type: str
    title: str
    vulnerability: str
    delivery: str
    base_steps: tuple[str, ...]
    hints: tuple[str, ...]


TEMPLATES = {
    ("web", "path-normalization"): TemplateInfo("web", "path-normalization", "The Archivist's Second Look", "double URL decoding after validation", "web", ("Map the file route.", "Compare validation and use-time decoding.", "Use encoded traversal to read the flag."), ("Count the decoding passes.", "A percent sign can also be encoded.", "The secret is adjacent to the public directory.")),
    ("web", "weak-session"): TemplateInfo("web", "weak-session", "Unsigned Authority", "client-controlled unsigned role token", "web", ("Inspect the role cookie.", "Decode and modify its JSON value.", "Request the admin route with the forged role."), ("The cookie is data, not a signature.", "Base64 is not encryption.", "The admin role can be represented in JSON.")),
    ("web", "query-injection"): TemplateInfo("web", "query-injection", "Inventory After Hours", "SQL query construction from user input", "web", ("Observe the item lookup behavior.", "Trigger a boolean condition in the query.", "Select the hidden flag record."), ("Quotes change query structure.", "Try making the predicate always true.", "The hidden row has a special kind.")),
    ("crypto", "repeating-xor"): TemplateInfo("crypto", "repeating-xor", "Repeating Signal", "reused short XOR key", "static", ("Use the known flag prefix.", "Recover the repeating key alignment.", "XOR the ciphertext with the recovered key."), ("XOR is its own inverse.", "The key repeats.", "You know how flags begin.")),
    ("crypto", "weak-rsa"): TemplateInfo("crypto", "weak-rsa", "Close Orbit RSA", "RSA primes too close together", "static", ("Notice that the RSA factors are close.", "Apply Fermat factorization.", "Derive the private exponent and decrypt."), ("Compare the factors around sqrt(n).", "A difference of squares factors n.", "Use integer square roots.")),
    ("crypto", "lcg-stream"): TemplateInfo("crypto", "lcg-stream", "Predictable Telemetry", "small-state LCG keystream", "static", ("Use the known plaintext prefix to recover output bytes.", "Brute-force the small initial state.", "Regenerate the stream and decrypt."), ("The generator state is intentionally small.", "Known plaintext filters candidates.", "The recurrence is public.")),
    ("forensics", "log-fragments"): TemplateInfo("forensics", "log-fragments", "Shuffled Incident", "flag fragments dispersed through logs", "static", ("Filter the suspicious event marker.", "Sort fragments by sequence number.", "Decode and join the fragments."), ("Most log lines are noise.", "Sequence numbers matter.", "Fragments are encoded.")),
    ("forensics", "zip-recovery"): TemplateInfo("forensics", "zip-recovery", "Broken Evidence Bag", "recoverable ZIP with damaged signature", "static", ("Identify the intended archive format.", "Repair the damaged magic bytes.", "Extract and decode the evidence."), ("The extension is truthful.", "Compare the header with ZIP magic.", "The note may have another encoding layer.")),
    ("forensics", "packet-timing"): TemplateInfo("forensics", "packet-timing", "Silent Intervals", "binary data encoded in packet timing", "static", ("Compute consecutive timestamp differences.", "Cluster short and long delays into bits.", "Decode bytes and unwrap the payload."), ("Payload contents are a distraction.", "There are two interval clusters.", "Read bits most-significant first.")),
}


def list_templates() -> list[TemplateInfo]:
    return list(TEMPLATES.values())


def make_spec(category: str, challenge_type: str, difficulty: str, theme: str) -> ChallengeSpec:
    if difficulty not in DIFFICULTIES:
        raise ValueError(f"difficulty must be one of: {', '.join(DIFFICULTIES)}")
    try:
        template = TEMPLATES[(category, challenge_type)]
    except KeyError as exc:
        raise ValueError(f"unknown template: {category}/{challenge_type}") from exc
    level = DIFFICULTIES.index(difficulty) + 1
    slug = f"{category}-{challenge_type}-{difficulty}"
    story = f"{theme.strip() or 'Local cyber range'}: {template.title}."
    steps = list(template.base_steps)
    if level >= 2:
        steps.insert(-1, "Remove one additional encoding or decoy layer.")
    if level >= 3:
        steps.insert(-1, "Infer the missing parameter from the supplied evidence.")
    return ChallengeSpec(
        slug=slug,
        title=f"{template.title} [{difficulty.title()}]",
        category=category,
        challenge_type=challenge_type,
        difficulty=difficulty,
        story=story,
        vulnerability=template.vulnerability,
        intended_solution=steps,
        hints=list(template.hints[: 4 - level]),
        delivery=template.delivery,
        port=8000 if template.delivery == "web" else None,
    )

