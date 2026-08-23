# Heap: tcache poisoning (live TCP)

`nc HOST PORT`. A job manager with a heap freelist that works exactly like a
tcache bin — a freed chunk stores the freelist's next-pointer in its own body,
and `free` has no double-free guard. Double-free a chunk so `alloc` returns it
twice, poison the freelist to point at the global `pending.run` function pointer,
and make the next allocation land there so your write sets it to `win()`. Then
`dispatch`. Non-PIE: `win()` and `&pending.run` are printed on connect, so no
leak is needed — the tcache poisoning is the whole challenge.

    1 alloc <idx> + 32 bytes   2 free <idx>   3 dispatch   4 quit
