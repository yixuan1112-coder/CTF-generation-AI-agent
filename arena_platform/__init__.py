"""AutoCTF Arena — the competition platform layer.

`autoctf_gan` knows how to *build and evolve* challenges. This package turns that
engine into a contest real teams can enter:

  * teams register and get an API token
  * a team submits an agent — either an uploaded Python file/zip that the server
    runs in a sandbox, or a remote HTTP endpoint the server calls
  * the platform runs a MATCH: the team's agent climbs a ladder against its own
    private, evolving challenge-maker, one generation at a time
  * every match is persisted, replayable, and ranked on a public leaderboard

Nothing here is a simulation. A match only advances when the team's agent returns
the real flag for a freshly generated challenge instance.
"""

__all__ = ["store", "sandbox", "agents", "runner", "server", "tracks"]
__version__ = "1.0.0"
