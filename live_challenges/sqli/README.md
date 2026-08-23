# Blind SQLi (live HTTP)

`http://HOST:PORT/`. `GET /user?name=<name>` tells you only whether an account
exists — one bit. The lookup is built by string concatenation, so it is
injectable, but a filter blocks `UNION`, comment markers and all whitespace: no
echo, no UNION shortcut. The flag lives in a separate `secret(flag)` table.
Turn that one bit into a boolean oracle and extract the flag character by
character. Scripting the oracle is the challenge.

    GET /user?name=alice        -> {"exists": true}
    GET /user?name=nobody       -> {"exists": false}
