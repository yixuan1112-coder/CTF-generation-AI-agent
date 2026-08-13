"""Track definitions — which route a match climbs.

A *track* used to wrap one `autoctf_gan` ladder and describe it for the
leaderboard: how many rungs exist and how deep the maker could escalate "before
it runs out of moves". It cannot run out any more. A track now names a starting
discipline, and the maker walks a CAMPAIGN from there:

    its own ladder  ->  a different discipline's ladder  ->  challenges it authors

`rungs` is the bounded prefix of that route — the part the UI can draw as a fixed
ladder. `endless` says whether an authoring tail follows it, in which case
reaching the last bounded rung is a milestone, not the end of the match.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from autoctf_gan.campaign import Campaign, default_campaign


# What the MAKER can build, which stops being a question about this host as soon
# as the maker runs in a container. `Arena` sets this from the maker's reported
# capabilities at startup; None means "probe the host", the pre-container default.
_MAKER_CAPABILITIES: dict | None = None


def set_maker_capabilities(capabilities: dict | None) -> None:
    """Plan routes against the toolchain that will actually build them."""
    global _MAKER_CAPABILITIES
    _MAKER_CAPABILITIES = dict(capabilities) if capabilities else None
    _campaign.cache_clear()


@lru_cache(maxsize=None)
def _campaign(category: str, cross_track: bool, authoring: bool) -> Campaign:
    """Cached: building one probes a toolchain, and Track reads it often."""
    return default_campaign(start=category, cross_track=cross_track,
                            authoring=authoring, capabilities=_MAKER_CAPABILITIES)


@dataclass(frozen=True)
class Track:
    key: str
    label: str
    category: str                 # the discipline the campaign STARTS on
    blurb: str
    per_gen_timeout_s: int = 120
    match_budget_s: int = 900
    # A track is playable only if its flag can be recovered from the files the
    # agent receives. Service-style challenges cannot be, until the arena grows
    # an instance broker — see `offered_reason`.
    offered: bool = True
    offered_reason: str = ""
    cross_track: bool = True
    authoring: bool = True
    # Service tracks (web) stand up a live target container per match, so they
    # are only playable where a Docker daemon exists — verification can fall back
    # to an in-process server, but a real match cannot.
    needs_docker: bool = False

    @property
    def available(self) -> bool:
        """Offered by design, buildable on this host, and — for service tracks —
        backed by a Docker daemon to run the live instance."""
        if not (self.offered and self.campaign.start_available):
            return False
        if self.needs_docker:
            from .sandbox import docker_available
            return docker_available()
        return True

    @property
    def unavailable_reason(self) -> str:
        if not self.offered:
            return self.offered_reason
        if not self.campaign.start_available:
            return (f"This host cannot build the starting ladder: "
                    + "; ".join(self.campaign.describe_skipped()))
        if self.needs_docker:
            from .sandbox import docker_available
            if not docker_available():
                return ("This is a service challenge: it needs a Docker daemon to "
                        "stand up the live target each match. This host has none.")
        return ""

    @property
    def campaign(self) -> Campaign:
        return _campaign(self.category, self.cross_track, self.authoring)

    @property
    def rungs(self) -> list[str]:
        """The bounded prefix: every rung that exists before authoring starts."""
        campaign = self.campaign
        return campaign.rung_names(campaign.bounded_rungs)

    @property
    def max_gen(self) -> int:
        """Index of the last bounded rung. NOT a ceiling when `endless` is true."""
        return max(0, self.campaign.bounded_rungs - 1)

    @property
    def endless(self) -> bool:
        return self.campaign.has_authoring_tail

    @property
    def route(self) -> list[dict]:
        """Segment-by-segment description, for the match view and the docs page."""
        return [{"key": s.key, "label": s.label, "category": s.category,
                 "blurb": s.blurb, "rungs": list(s.rungs), "authoring": s.unbounded}
                for s in self.campaign.segments]

    @property
    def skipped_segments(self) -> list[str]:
        return self.campaign.describe_skipped()

    def rung_name(self, gen: int) -> str:
        if gen < 0:
            return "nothing"
        return self.campaign.rung_name(gen)


def warmup() -> None:
    """Import the engine's heavy modules on the MAIN thread, before threads start.

    fpylll installs a signal handler when it is imported, and Python only permits
    that from the main thread. If a match worker or an HTTP handler triggers the
    first import instead, it raises, crypto_ladder quietly drops the Boneh-Durfee
    rung, and the arena would serve a shorter ladder than it advertises — the boss
    fight the whole contest is built around would simply vanish. Building the
    campaigns here puts fpylll in sys.modules so every later thread import is a
    no-op, and warms the lru_cache off the main thread's result.
    """
    for track in all_tracks().values():
        _ = track.rungs


def all_tracks() -> dict[str, Track]:
    return {
        "crypto": Track(
            key="crypto",
            label="Crypto — RSA attack ladder",
            category="crypto",
            blurb=("Starts by rotating to a harder attack CLASS each rung, not a bigger "
                   "modulus. Past the ladder the maker composes verified attacks into "
                   "challenges no rung covers, so there is no last challenge."),
            per_gen_timeout_s=120,
            match_budget_s=900,
        ),
        "reverse": Track(
            key="reverse",
            label="Reverse — compiled crackme",
            category="reverse",
            blurb=("A generated C crackme whose key schedule gains a round every "
                   "generation. Be aware this ladder discriminates weakly: rounds only "
                   "affect how the password reaches the keystream state, and an agent "
                   "that solves for the state directly never touches the password — so "
                   "every rung falls at the same speed. The crypto rungs that follow "
                   "are what separate strong agents."),
            per_gen_timeout_s=180,
            match_budget_s=1200,
        ),
        "web": Track(
            key="web",
            label="Web — template injection",
            category="web",
            blurb=("A Flask SSTI service behind a denylist. Every generation bans "
                   "the token the previous bypass used, so each rung forces a new "
                   "technique."),
            per_gen_timeout_s=120,
            match_budget_s=900,
            # Now offered: the arena stands up a live target per match (see
            # instance.WebInstance / runner.run_match), so the flag exists only
            # in the running container and the agent wins by attacking it over
            # the network. `available` still gates on the host being able to
            # build the ladder, so a Docker-less host will not advertise it.
            offered=True,
            needs_docker=True,
            cross_track=False,
            authoring=False,
            offered_reason=(
                "This is a service challenge: the flag is injected into the running "
                "container as $FLAG at deploy time, so it exists nowhere in the files "
                "an agent receives. It needs a Docker daemon to stand up the live "
                "target; this host has none, so the track is not offered here."),
        ),
    }


def playable_tracks() -> dict[str, Track]:
    """Only tracks an agent can actually win from the files it is handed."""
    return {k: t for k, t in all_tracks().items() if t.available}


def get_track(key: str) -> Track:
    tracks = all_tracks()
    if key not in tracks:
        raise KeyError(f"unknown track {key!r}; choose one of {sorted(tracks)}")
    return tracks[key]
