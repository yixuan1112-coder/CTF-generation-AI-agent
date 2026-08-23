# NoSQL Injection (live HTTP)

`http://HOST:PORT/`. `POST /login` with `{"user":"...","pass":"..."}` looks you
up in a Mongo-like store by passing your JSON straight into the query, so it
honours operator objects (`$ne`, `$gt`, `$regex`, ...). The admin password is
random, so guessing is out — inject an operator that always matches and log in as
`admin` to get the flag.

    {"user": "admin", "pass": {"$ne": ""}}
