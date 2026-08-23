# Return to Win (live TCP)

`nc HOST PORT`. A classic stack buffer overflow. The program reads 512 bytes into
a 64-byte stack buffer with no canary, and it is non-PIE — so `win()` sits at a
fixed address, which it even prints on connect. Overflow the buffer, overwrite the
saved return address with `win()`, and it prints the flag from its environment.
No binary or libc needed; only the overflow offset is yours to find.
