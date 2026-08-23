# Network Pivot (live HTTP, multi-host)

`http://HOST:PORT/` is `web01`, the only host exposed to you. Behind it, on a
private network you cannot reach directly, sit two more hosts: an internal
`metadata` service and a `vault` that holds the flag. `web01` has an SSRF: `GET
/fetch?url=http://<internal-host>:9000/...` makes the request *from web01*, so it
is your pivot. Enumerate the internal hosts, pull the internal token from the
metadata service, and present it to the vault to read the flag.

    GET /fetch?url=http://metadata:9000/latest/meta-data/internal-token
    GET /fetch?url=http://vault:9000/flag?token=<TOKEN>

Real multi-container pivoting: metadata and vault have no host port — the only
path to them is through web01.
