# Heap Pwn (live TCP)

`nc HOST PORT`. A note manager with a use-after-free. Notes carry a function
pointer; deleting one leaves the slot dangling, and a raw stash allocation lands on
the freed chunk so you can plant the pointer. The binary is non-PIE and leaks the
address of its `win()` gadget on connect — no binary or libc needed; the heap
grooming is the whole challenge. Groom the tcache, overwrite the action pointer with
`win`, and call it.
