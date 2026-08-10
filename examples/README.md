# Example agents

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
