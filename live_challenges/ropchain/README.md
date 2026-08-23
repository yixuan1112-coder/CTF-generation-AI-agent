# ROP Chain (live TCP)

`nc HOST PORT`. A stack overflow with no argument-free win: the flag printer
`print_flag(key)` only fires when `key == 0xC0FFEE`, so overwriting the return
address with its entry is not enough — you must stage the argument first. The
binary is non-PIE, and it prints the fixed addresses of a `pop rdi ; ret` gadget
and `print_flag` on connect. Assemble the chain
`[pop rdi ; ret][0xC0FFEE][print_flag]` over the saved return address. No binary
or libc needed — the ROP mechanics are the whole challenge.
