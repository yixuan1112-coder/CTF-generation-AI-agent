# Race Wallet (live HTTP)

`http://HOST:PORT/`. You have 10 credits; the flag costs 100. A one-time welcome
coupon adds 40 — redeemed once you reach 50, and the coupon is then marked used.
But the "already used?" check and the "mark used" write straddle a slow ledger
update: fire several `POST /redeem` requests at the same time and each clears the
check before any marks the coupon spent, stacking +40 several times. Climb past
100, then `POST /buy` the flag. One request at a time can never win.

    GET  /            -> balance + instructions
    POST /redeem      -> +40, "one-time" (race it)
    POST /buy         -> flag if balance >= 100
