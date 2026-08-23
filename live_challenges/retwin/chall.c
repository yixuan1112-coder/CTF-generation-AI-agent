/* ret2win — a textbook stack buffer overflow.
 *
 * Non-PIE, no stack protector: win()'s address is fixed and printed on connect,
 * and there is no canary between the buffer and the saved return address. vuln()
 * reads far more bytes than its 64-byte buffer holds, so the return address is
 * yours to overwrite. Point it at win() and it prints the flag from the
 * environment. win() uses only write()/_exit(), so there is no stack-alignment
 * subtlety to trip over — the overflow itself is the whole challenge.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    char *f = getenv("FLAG");
    write(1, "WIN\n", 4);
    write(1, f ? f : "no flag", f ? strlen(f) : 7);
    write(1, "\n", 1);
    _exit(0);
}

void vuln(void) {
    char buf[64];
    read(0, buf, 512);          /* deliberate overflow: 512 into 64 */
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    printf("win() is at %p\n", (void *)win);
    printf("name? ");
    fflush(stdout);
    vuln();
    printf("bye\n");
    return 0;
}
