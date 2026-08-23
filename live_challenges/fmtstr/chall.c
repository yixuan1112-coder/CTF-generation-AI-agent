/* fmtstr — a format-string bug giving an arbitrary write.
 *
 * printf(buf) with attacker-controlled buf is a format-string vulnerability: the
 * conversions read (and, with %n, WRITE) using the stack as their argument list.
 * The buffer is on the stack, so any address you place in it becomes a %n target.
 * Overwrite the global `authed` (whose fixed, non-PIE address is printed on
 * connect) to any non-zero value and the flag prints. The loop lets you send one
 * format string, then it checks. No leak of the flag anywhere — the write is the
 * whole challenge.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int authed = 0;

void print_flag(void) {
    char *f = getenv("FLAG");
    write(1, "AUTHED ", 7);
    write(1, f ? f : "no flag", f ? strlen(f) : 7);
    write(1, "\n", 1);
    _exit(0);
}

int main(void) {
    char buf[128];
    setvbuf(stdout, 0, _IONBF, 0);
    printf("authed is at %p\n", (void *)&authed);
    for (;;) {
        printf("fmt> ");
        fflush(stdout);
        int n = read(0, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;
        printf(buf);          /* the vulnerability */
        if (authed) print_flag();
    }
    return 0;
}
