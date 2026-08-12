"""Build-time smoke test for the challenge-maker image.

A missing runtime dependency makes a broken image, and the failure should land
here — while the image is being built — rather than on the first build request of
the first match. `jsonschema` was nearly shipped missing exactly that way: the
package's `__init__` imports `generator`, which imports `schema`, which imports it
at module level, so the image built cleanly and would have failed in production.

Runs as the image's unprivileged user, so it also proves the verification path
can write where it needs to.

    docker build -t autoctf-maker:latest -f Dockerfile.maker .
"""
from __future__ import annotations

import json
import sys

from autoctf_gan.service import handle


def main() -> int:
    caps = handle({"op": "capabilities"})
    if not caps.get("ok"):
        print(f"capabilities failed: {caps}", file=sys.stderr)
        return 1
    c = caps["capabilities"]
    print(f"  capabilities  gcc={c['gcc']} fpylll={c['fpylll']} python={c['python']}")
    if not c["gcc"]:
        # The image installs gcc on purpose — the reverse ladder needs it, and an
        # arena on a host without a compiler relies on this image having one.
        print("  FAIL: the maker image is supposed to ship a gcc toolchain",
              file=sys.stderr)
        return 1

    # Build past the ladder so the composed path — the one that only exists in
    # this change — is exercised, and verify it for real.
    generation = 32
    result = handle({"op": "build", "seed": 1, "generation": generation,
                     "flag_secret": "smoke-test",
                     "campaign": {"start": "crypto", "design": "catalog"},
                     "verify": True})
    if not result.get("ok"):
        print(f"build failed: {result.get('error')}", file=sys.stderr)
        return 1
    verdict = result.get("verdict") or {}
    if not verdict.get("valid"):
        print(f"the maker built an unsolvable challenge: {verdict}", file=sys.stderr)
        return 1

    spec = result["spec"]
    print(f"  built         {spec['mechanics']['attack_class']}")
    print(f"  verified      {verdict['reason']} in {verdict['poc_time_s']:.2f}s")
    print(f"  artifacts     {len(spec['artifacts'])} player files")
    if spec["flag"] in json.dumps(spec["artifacts"]):
        print("  FAIL: the flag leaked into a player artifact", file=sys.stderr)
        return 1
    print("  smoke test OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
