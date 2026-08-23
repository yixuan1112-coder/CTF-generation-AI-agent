/* heaptcache — double-free -> tcache poisoning -> hijack a function pointer.
 *
 * Harder than a plain UAF: this leaks nothing about the heap and requires you to
 * poison the tcache freelist so malloc hands back an attacker-chosen address.
 *
 * Layout: an array of "job" objects, each { void (*run)(void); char name[24]; }
 * (32 bytes -> one tcache bin). There is a global `struct job pending` whose
 * `run` pointer is called by `dispatch`. The bug in `del` is a classic
 * double-free (the tcache pointer is not cleared and there is no double-free
 * guard defeat needed for the first two frees of the same chunk on old-ish libc;
 * to keep it deterministic across libc versions the program also never sets the
 * tcache key, by allocating through a tiny custom bin of its own).
 *
 * To stay libc-independent and reliable in a CTF box, the "heap" here is a small
 * fixed arena with a LIFO freelist that behaves exactly like the tcache: free
 * pushes a chunk (writing the next pointer into the chunk's first 8 bytes),
 * malloc pops it. A double-free creates a cycle; then two allocations plus a
 * write let you set the freelist head to `&pending.run`, so the next allocation
 * returns that address and your write lands on the function pointer. Point it at
 * win().  Non-PIE: win()'s address is printed on connect.
 *
 * This models tcache poisoning faithfully (the freelist-in-freed-chunk mechanic
 * and the double-free primitive) without depending on a specific glibc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define CHUNK 32
#define NCHUNK 16

static unsigned char arena[CHUNK * NCHUNK];
static void *freelist = 0;                  /* LIFO head, like a tcache bin */

/* free: push chunk onto the freelist, storing the old head in the chunk. No
 * check that the chunk is already free -> double-free is possible. */
static void bin_free(void *p) {
    *(void **)p = freelist;
    freelist = p;
}
/* malloc: pop the head; the new head is read from the popped chunk. */
static void *bin_alloc(void) {
    if (!freelist) return 0;
    void *p = freelist;
    freelist = *(void **)p;
    return p;
}

struct job { void (*run)(void); char name[24]; };
static struct job pending;                  /* its run pointer is the target */

static void banner(void) { write(1, "job queued\n", 11); }
void win(void) {
    char *f = getenv("FLAG");
    write(1, "WIN ", 4);
    write(1, f ? f : "no flag", f ? strlen(f) : 7);
    write(1, "\n", 1);
    _exit(0);
}

static int rdline(char *b, int n) {
    int i = 0; char c;
    while (i < n - 1 && read(0, &c, 1) == 1 && c != '\n') b[i++] = c;
    b[i] = 0; return i;
}
static int rdint(void) { char b[16]; if (rdline(b, sizeof b) <= 0) _exit(0); return atoi(b); }
static int rdbytes(char *dst, int n) { int g = 0, r; while (g < n && (r = read(0, dst + g, n - g)) > 0) g += r; return g; }

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    /* seed the arena into the freelist as NCHUNK fixed chunks, ready to alloc */
    for (int i = NCHUNK - 1; i >= 0; i--) bin_free(&arena[i * CHUNK]);

    pending.run = 0;
    printf("win() is at %p\n", (void *)win);
    printf("pending.run is at %p\n", (void *)&pending.run);
    printf("commands: 1 alloc <hex bytes>  2 free <idx>  3 dispatch  4 quit\n");

    void *slots[NCHUNK] = {0};
    for (;;) {
        printf("> ");
        int c = rdint();
        if (c == 1) {
            int idx = rdint() % NCHUNK;
            void *p = bin_alloc();
            slots[idx] = p;
            if (p) {
                char buf[64];
                int n = rdbytes(buf, CHUNK);     /* up to a full chunk of control */
                memcpy(p, buf, n < CHUNK ? n : CHUNK);
            }
        } else if (c == 2) {
            int idx = rdint() % NCHUNK;
            if (slots[idx]) bin_free(slots[idx]);   /* no clear -> double-free */
        } else if (c == 3) {
            if (pending.run) pending.run();
        } else break;
    }
    return 0;
}
