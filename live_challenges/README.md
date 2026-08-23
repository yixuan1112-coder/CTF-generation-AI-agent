# Live challenges (Docker, one instance per player)

Unlike the static `/practice` catalogue (download files, submit a flag), these are
running services a player must attack over the network — the interactive,
no-oracle kind a solver cannot brute or read off disk. Each ships a Dockerfile and
a service that takes the real flag as `-e FLAG=...` at launch, so the flag exists
only in the running container, never in any file a player can read.

Launch one hardened, on a fresh loopback port, with auto-expiry:

    deploy/launch_live.sh live_challenges/signalgate 19000 "flag{...}" 1800

The container runs non-root, read-only rootfs, all caps dropped, memory/PID/CPU
capped, and is killed after the TTL. Publish it to players via the reverse proxy
(a TCP/L4 route to 127.0.0.1:<port>) or an on-demand broker.

| challenge | what it is | why it resists an agent |
|---|---|---|
| `signalgate` | a bespoke binary protocol on TCP | blind-reverse the framing, handshake, a non-standard auth transform, and a state gate — no files, no oracle beyond probing |
| `gauntlet` | a timed 20-stage challenge-response | reverse the stage grammar and script a client that answers every stage type fast; manual play and partial coverage both fail |
| `jwtlab` | a JWT algorithm-confusion web service | the verifier trusts the token's own `alg` and accepts `alg:none`; forge an unsigned admin token — the HS256 secret is never recoverable |
| `racewallet` | a TOCTOU double-spend web service | a single-use coupon's check and its "used" write straddle a slow ledger update; only overlapping requests stack it, sequential play tops out short |
| `retwin` | a ret2win stack overflow on TCP | non-PIE, no canary: overflow a 64-byte buffer and overwrite the saved return address with the leaked `win()`; the overflow offset is the only unknown |

Both were validated end to end: launched with a random flag, the reference
`solve.py` recovered exactly that flag, then the instance was torn down.
