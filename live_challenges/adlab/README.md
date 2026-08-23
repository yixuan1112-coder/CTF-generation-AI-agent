# AD Lab — Internal Network (live HTTP)

`http://HOST:PORT/`. You have a foothold on `web01` (10.0.0.5) in the `CORP`
domain. Only web01's pivot is exposed; `fileserver` (10.0.0.10) and the domain
controller `dc01` (10.0.0.100) are reachable **only** through it:
`GET /fetch?url=http://10.0.0.X/path`.

The kill chain:

1. **Loot web01** — its config backup leaks user `CORP\jdoe`'s NT hash.
2. **Pass-the-Hash** — authenticate to `fileserver` with that hash (no password).
3. A share note names service account `svc_sql` (SPN `MSSQLSvc/dc01`).
4. **Kerberoast** — ask `dc01` for that SPN's service ticket; it is encrypted
   under the service account's password key. Crack it offline (`/wordlist.txt`).
5. `svc_sql` is a (misconfigured) Domain Admin — authenticate to `dc01` with its
   hash and read the flag.

Real primitives: NT hash = MD4(password as UTF-16LE); only the correct password
decrypts the roastable ticket. The flag lives on dc01, behind Domain Admin.
