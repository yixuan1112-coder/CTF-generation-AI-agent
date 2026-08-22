# Signal Gate (live TCP)

An undocumented device speaks a binary protocol on `nc HOST PORT`. Nothing is
given but the endpoint. Reverse the framing, find the handshake, work out how the
device expects you to answer its challenge, and walk the state machine to the flag.
