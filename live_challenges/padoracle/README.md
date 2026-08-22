# Padding Oracle (live TCP)

`nc HOST PORT`. The service hands you a ciphertext and then, for any ciphertext you
send it, tells you only whether its PKCS#7 padding decrypts cleanly. That one bit is
the whole attack surface: recover the target's plaintext byte by byte. The plaintext
is the flag.
