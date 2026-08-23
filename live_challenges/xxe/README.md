# XXE (live HTTP)

`http://HOST:PORT/`. `POST /profile` takes an XML user profile and greets the
name: `<user><name>Alice</name></user>` -> `Hello, Alice`. The parser resolves
external entities and DTDs, so declare an external entity pointing at a local
file and reference it inside `<name>` to exfiltrate it. The flag is
`/tmp/flag.txt`.

    <!DOCTYPE user [ <!ENTITY xxe SYSTEM "file:///tmp/flag.txt"> ]>
    <user><name>&xxe;</name></user>
