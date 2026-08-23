# Format String (live TCP)

`nc HOST PORT`. The program does `printf(buf)` on your input — a format-string
bug: the conversions walk the stack, and `%n` *writes*. The buffer is on the
stack, so an address you place in it becomes a `%n` target. The global `authed`
is checked after each line and its fixed (non-PIE) address is printed on connect;
overwrite it with any non-zero value and the flag prints. No leak of the flag
anywhere — turning the read primitive into an arbitrary write is the challenge.
