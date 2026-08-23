# Golden Ticket (live HTTP)

`http://HOST:PORT/`. The domain controller trusts any Kerberos ticket that
decrypts under the **krbtgt** account's key — so whoever holds that key can forge
a ticket for anyone. From an earlier compromise you dumped it
(`GET /loot/krbtgt_hash`). No real user is a Domain Admin (`/tgt` will issue jdoe
a valid but unprivileged ticket), so forge your own: seal a ticket naming a
Domain Admin under the krbtgt key and present it to `/resource` for the flag.
That is a Golden Ticket — full domain compromise from the krbtgt hash.

    ticket = XOR( json{"magic","user","groups"}, sha256-keystream(krbtgt_key) )
