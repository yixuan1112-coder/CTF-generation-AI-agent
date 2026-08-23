# Pickle Trap (live HTTP)

`http://HOST:PORT/`. The service hands you a `session` cookie — base64 of a
Python `pickle`d session object — and `GET /whoami` reads it back by
**unpickling** it. `pickle` executes code during load, and the cookie is
unsigned, so you can swap in a pickle whose `__reduce__` runs a command on the
server. Read the flag out of the process environment and echo it back through
`/whoami`.

    GET /            -> sets your guest session cookie
    GET /whoami      -> unpickles your cookie and describes it
