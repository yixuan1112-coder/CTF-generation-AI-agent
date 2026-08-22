/* Note manager with a use-after-free / tcache type-confusion.
 * Non-PIE, no stack protector: win()'s address is fixed and leaked at start, so
 * no binary or libc is needed — the difficulty is the heap manipulation itself.
 *
 * struct note { void (*action)(void); char data[24]; }  (32 bytes, one tcache bin)
 * bug: `delete` frees a note but leaves its slot pointer (UAF); `stash` mallocs a
 * 32-byte buffer you fully control and can land it on a freed note's chunk, so you
 * can write the action pointer of a still-referenced (freed) note and call it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct note { void (*action)(void); char data[24]; };
static struct note *slots[8];

void win(void) {
    char *f = getenv("FLAG");
    write(1, f ? f : "no flag", f ? strlen(f) : 7);
    write(1, "\n", 1);
    _exit(0);
}
static void banner(void) { write(1, "a plain note.\n", 14); }

static int rdline(char *b, int n) {
    int i = 0; char c;
    while (i < n - 1 && read(0, &c, 1) == 1 && c != '\n') b[i++] = c;
    b[i] = 0;
    return i;
}
static int rdint(void) { char b[16]; if (rdline(b, sizeof b) == 0) _exit(0); return atoi(b); }
static int rdbytes(char *dst, int n) { int g = 0, r; while (g < n && (r = read(0, dst + g, n - g)) > 0) g += r; return g; }

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    printf("[dbg] win() is at %p\n", (void *)win);
    printf("note manager. 1 create  2 delete  3 stash  4 show  5 exit\n");
    for (;;) {
        write(1, "> ", 2);
        int c = rdint();
        if (c == 1) { int i = rdint() % 8; slots[i] = malloc(sizeof(struct note)); slots[i]->action = banner; rdbytes(slots[i]->data, 24); }
        else if (c == 2) { int i = rdint() % 8; free(slots[i]); }                 /* UAF: slot not cleared */
        else if (c == 3) { int i = rdint() % 8; slots[i] = malloc(32); rdbytes((char *)slots[i], 32); }
        else if (c == 4) { int i = rdint() % 8; if (slots[i] && slots[i]->action) slots[i]->action(); }
        else break;
    }
    return 0;
}
