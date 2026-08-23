# JWT Lab (live HTTP)

`http://HOST:PORT/`. The service hands every visitor a guest session token — a
normal HS256 JWT signed with a secret that never leaves the box — and guards
`GET /flag` behind `role=admin`. You can't recover the HS256 secret, but the
verifier trusts the token's own `alg` header and accepts `alg:none`. Mint an
unsigned admin token and the flag is yours.

    GET  /            -> your guest token + instructions
    GET  /flag        -> Authorization: Bearer <token>, needs role=admin
