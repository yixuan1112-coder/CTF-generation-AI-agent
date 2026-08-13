# Example agents

## `docker_demo/` — package an agent as a Docker image

The workshop kit. Builds one image that is both an interactive demo (`docker run -it` →
a menu, and you choose to run the AI) and a valid submission you can upload unchanged.

It teaches the **circle-memory** pattern — `PERCEIVE → RECALL → DECIDE → ACT → RECORD`
over an explicit memory, with no language model, no prompts and no network anywhere in
it — and the image contract: `/opt/agent/agent.py` defining `solve`, and `python` on
`PATH`. See `docker_demo/README.md`.

```bash
docker build -t autoctf-demo-agent -f examples/docker_demo/Dockerfile .
docker run --rm -it autoctf-demo-agent
# or: ARENA=... TEAM="My Team" ./examples/docker_demo/submit.sh
```

## `champion_agent/` — clears the whole crypto ladder

The starter agent (`../team_agent.py`) has six classical RSA attacks and no lattice
attack, so the challenge-maker out-evolves it at Gen-6 (Boneh-Durfee). This one adds that
stage by shipping `lattice.py` alongside `agent.py`, and clears the ladder.

It exists to show the **shape** of a zip submission: uploaded agents get no network and
cannot import this repository, so every library an agent needs either comes from the host
(see `GET /api/config` → `libraries`) or travels inside the zip.

Package and submit it:

```bash
cd examples/champion_agent
zip -r ../champion.zip agent.py lattice.py
# then upload ../champion.zip on http://127.0.0.1:8090/submit
```

A real run against a live arena:

```
✔ Gen-0 smalle        0.003s
✔ Gen-1 hastad        0.004s
✔ Gen-2 commonmod     0.004s
✔ Gen-3 wiener        0.004s
✔ Gen-4 fermat        0.009s
✔ Gen-5 pollard       1.138s
✔ Gen-6 bonehdurfee  11.903s   ← the real lattice attack
🏆 Ladder cleared — the challenge-maker ran out of moves.
```

`champion.zip` itself is gitignored; build it with the command above.


## `reverse_agent/` — clears the reverse ladder

A single file, standard library only. It recovers the flag from `crackme.c`
without ever guessing the password.

The crackme XORs the flag against a keystream from a 32-bit xorshift, seeded by
`mix_state(password)`. The password is not shipped — but xorshift32 is **linear
over GF(2)**, so each keystream byte is eight linear equations in the 32 unknown
state bits. The flag's own `flag{` prefix supplies five known bytes, i.e. 40
equations for 32 unknowns, and Gaussian elimination pins the state exactly. No
search, microseconds per rung.

```bash
# it is one file, so upload it directly — no zip needed
curl -X POST "$ARENA/api/agents?kind=upload&name=xorshift&filename=agent.py" \
     -H "Authorization: Bearer $TOKEN" --data-binary @examples/reverse_agent/agent.py
```

Worth knowing what this demonstrates about the track: `ROUNDS` only affects how
the *password* reaches the state, and this attack never touches the password — so
every rung falls in the same 3 ms and the reverse ladder does not separate strong
agents from weak ones. Crypto is the track that discriminates.
