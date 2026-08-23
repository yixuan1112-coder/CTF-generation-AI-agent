# ECB Oracle (live HTTP)

`http://HOST:PORT/`. `GET /encrypt?data=<hex>` returns
`AES-ECB(key, prefix || data || FLAG)` under a fixed key. ECB maps equal
plaintext blocks to equal ciphertext blocks, and you control `data`, so you can
align the hidden `FLAG` to a block boundary and peel it off one byte at a time.
The twist: a fixed random `prefix` of unknown length sits in front of your input,
so recover the prefix length first. Classic byte-at-a-time ECB decryption, hard
mode.
