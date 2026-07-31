from __future__ import annotations

from dataclasses import dataclass

from .models import DIFFICULTIES, ChallengeSpec

CATEGORY_INFO = {
    "web": {"name": "Web 安全", "english": "Web Exploitation", "icon": "WEB"},
    "reverse": {"name": "逆向工程", "english": "Reverse Engineering", "icon": "RE"},
    "pwn": {"name": "二进制漏洞利用", "english": "Binary Exploitation", "icon": "PWN"},
    "crypto": {"name": "密码学", "english": "Cryptography", "icon": "CRY"},
    "forensics": {"name": "电子取证", "english": "Forensics", "icon": "FOR"},
    "misc": {"name": "隐写术与杂项", "english": "Misc / Steganography", "icon": "MSC"},
    "blockchain": {"name": "区块链安全", "english": "Blockchain / Web3", "icon": "WEB3"},
    "ai-ml": {"name": "人工智能安全", "english": "AI / LLM Security", "icon": "AI"},
    "iot": {"name": "物联网与硬件安全", "english": "IoT / Hardware", "icon": "IOT"},
    "mobile": {"name": "移动安全", "english": "Mobile / Android Security", "icon": "APK"},
}


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
    ("ai-ml", "prompt-injection"): TemplateInfo("ai-ml", "prompt-injection", "Untrusted Instructions", "instructions mixed with untrusted user context", "static", ("Separate policy from untrusted context.", "Identify the injected instruction marker.", "Recover the protected value from the simulated response trace."), ("Documents are data, not instructions.", "Inspect role boundaries.", "The trace records which instruction won.")),
    ("ai-ml", "rag-poisoning"): TemplateInfo("ai-ml", "rag-poisoning", "Poisoned Knowledge Base", "retrieval corpus contains an adversarial document", "static", ("Rank the retrieved documents.", "Find the document that imitates system policy.", "Follow provenance to recover the hidden value."), ("Trust and relevance are different scores.", "One document has suspicious provenance.", "Compare metadata with content.")),
    ("ai-ml", "model-extraction"): TemplateInfo("ai-ml", "model-extraction", "Tiny Oracle", "query access reveals a small linear model", "static", ("Query basis inputs conceptually.", "Recover the linear coefficients from observations.", "Interpret coefficients as encoded bytes."), ("The model is linear.", "Each feature can be isolated.", "Coefficients are byte values.")),
    ("reverse", "xor-strings"): TemplateInfo("reverse", "xor-strings", "Static Noise", "constant-key string obfuscation", "static", ("Inspect the supplied binary blob.", "Recover the single-byte XOR key from the known prefix.", "Decode the protected string."), ("The flag prefix is known.", "One byte is reused.", "XOR reverses itself.")),
    ("reverse", "bytecode-vm"): TemplateInfo("reverse", "bytecode-vm", "Pocket VM", "custom bytecode transformation", "static", ("Read the VM instruction listing.", "Model the accumulator operations.", "Invert the byte transformation."), ("The VM is linear.", "Operations apply to every byte.", "Run the instructions backwards.")),
    ("reverse", "license-check"): TemplateInfo("reverse", "license-check", "Serial Constellation", "shuffled license validation table", "static", ("Map each validation index.", "Restore character order.", "Reconstruct the accepted serial."), ("Indexes are more useful than row order.", "Sort before joining.", "The serial is the flag.")),
    ("pwn", "stack-overflow-sim"): TemplateInfo("pwn", "stack-overflow-sim", "Training Stack", "simulated saved-return-address overwrite", "static", ("Inspect the synthetic stack layout.", "Calculate the offset to the control field.", "Decode the bytes reached by the intended payload."), ("This is an offline memory model.", "Count padding bytes.", "The control marker selects the secret frame.")),
    ("pwn", "format-string-sim"): TemplateInfo("pwn", "format-string-sim", "Printf Observatory", "simulated uncontrolled format string reads", "static", ("Inspect the positional stack dump.", "Identify flag-shaped words.", "Order and decode the selected words."), ("Use positional indexes.", "Little-endian words look reversed.", "Join adjacent stack values.")),
    ("pwn", "integer-overflow-sim"): TemplateInfo("pwn", "integer-overflow-sim", "Cargo Counter", "simulated fixed-width integer wraparound", "static", ("Determine the counter width.", "Find the transaction that wraps the total.", "Use the wrapped index to select the protected record."), ("Arithmetic is modulo a power of two.", "Watch the boundary.", "Zero is a useful destination.")),
    ("misc", "ppm-lsb"): TemplateInfo("misc", "ppm-lsb", "Quiet Pixels", "least-significant-bit image steganography", "static", ("Parse the portable pixmap.", "Read the low bit of each color byte.", "Group bits into bytes and decode."), ("The image format is intentionally simple.", "Color values differ by one.", "Read bits most-significant first.")),
    ("misc", "whitespace-code"): TemplateInfo("misc", "whitespace-code", "Margins Matter", "binary data hidden in spaces and tabs", "static", ("Ignore visible cover text.", "Map spaces and tabs to bits.", "Decode each eight-bit group."), ("Whitespace is evidence.", "There are two indentation characters.", "Preserve line endings.")),
    ("misc", "encoding-matryoshka"): TemplateInfo("misc", "encoding-matryoshka", "Nested Signal", "layered standard encodings", "static", ("Identify the outer representation.", "Peel encoding layers in order.", "Validate the recovered flag format."), ("Hex has a limited alphabet.", "Base64 often ends with padding.", "Do not guess—inspect each layer.")),
    ("blockchain", "storage-slots"): TemplateInfo("blockchain", "storage-slots", "Cold Storage", "secret split across contract storage slots", "static", ("Read the storage snapshot.", "Order slots by index.", "Convert words to bytes and trim padding."), ("Storage words are hexadecimal.", "Slot order matters.", "Null bytes are padding.")),
    ("blockchain", "event-log"): TemplateInfo("blockchain", "event-log", "Event Horizon", "sensitive data emitted across event logs", "static", ("Filter the target contract events.", "Sort by block and log index.", "Join and decode event data."), ("Not every log belongs to the contract.", "Chain ordering is deterministic.", "Data fields are hexadecimal.")),
    ("blockchain", "nonce-reuse"): TemplateInfo("blockchain", "nonce-reuse", "Repeated Nonce", "toy signature nonce reuse", "static", ("Compare the two signatures.", "Use the repeated nonce relation.", "Recover the toy private scalar and decrypt the payload."), ("Both signatures share r.", "Subtraction removes the nonce.", "All arithmetic is modulo q.")),
    ("iot", "firmware-strings"): TemplateInfo("iot", "firmware-strings", "Firmware Whisper", "recoverable diagnostic string in firmware", "static", ("Inspect the firmware image structure.", "Locate the diagnostic marker.", "Undo the byte mask after the marker."), ("Search for recognizable markers.", "The mask is one byte.", "Firmware often contains debug leftovers.")),
    ("iot", "uart-fragments"): TemplateInfo("iot", "uart-fragments", "Serial Boot", "secret fragments in noisy UART output", "static", ("Filter boot diagnostics.", "Extract numbered UART fragments.", "Sort, join, and decode them."), ("Boot logs contain noise.", "Sequence numbers wrap nothing.", "Fragments use a common encoding.")),
    ("iot", "mqtt-retain"): TemplateInfo("iot", "mqtt-retain", "Retained Command", "sensitive retained MQTT message", "static", ("Inspect the broker capture.", "Filter retained messages by topic.", "Decode the device command payload."), ("Only one message is retained.", "Topic hierarchy is meaningful.", "The payload is encoded.")),
    ("mobile", "android-manifest"): TemplateInfo("mobile", "android-manifest", "Exported Activity", "insecure exported Android component", "static", ("Unpack the APK archive.", "Inspect AndroidManifest.xml for exported components.", "Follow the activity asset reference and decode it."), ("An APK is a ZIP archive.", "Exported components expand the attack surface.", "The activity name points to an asset.")),
    ("mobile", "dex-obfuscation"): TemplateInfo("mobile", "dex-obfuscation", "Smali Lantern", "reversible string obfuscation in DEX-like bytecode", "static", ("Inspect the simplified smali listing.", "Recover the constant byte mask.", "Apply it to the encoded array."), ("Look for xor-int/lit8.", "The array stores decimal bytes.", "Decode the result after removing the mask.")),
    ("mobile", "native-library"): TemplateInfo("mobile", "native-library", "JNI Vault", "secret transformation in a native JNI routine", "static", ("Inspect the exported JNI symbol table.", "Read the native transformation recipe.", "Invert rotate and XOR operations."), ("JNI names reveal the Java entry point.", "Undo operations in reverse order.", "Rotation is over eight-bit values.")),
}


def list_templates() -> list[TemplateInfo]:
    return list(TEMPLATES.values())


def make_spec(category: str, challenge_type: str, difficulty: str, theme: str, variant: str = "default", seed: str | None = None) -> ChallengeSpec:
    if difficulty not in DIFFICULTIES:
        raise ValueError(f"difficulty must be one of: {', '.join(DIFFICULTIES)}")
    try:
        template = TEMPLATES[(category, challenge_type)]
    except KeyError as exc:
        raise ValueError(f"unknown template: {category}/{challenge_type}") from exc
    level = DIFFICULTIES.index(difficulty) + 1
    slug = f"{category}-{challenge_type}-{difficulty}" + (f"-{variant}" if variant != "default" else "")
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
        variant=variant,
        seed=seed,
    )

