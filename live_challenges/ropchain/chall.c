/* ropchain — a stack overflow that needs a real ROP chain, not just ret2win.
 *
 * There is no argument-free win(). The flag printer, print_flag(key), only
 * cooperates when called with key == 0xC0FFEE, so overwriting the return address
 * with its entry is not enough: you have to stage the argument first. The binary
 * is non-PIE, so the gadget you need — `pop rdi ; ret` — and print_flag sit at
 * fixed addresses; both are printed on connect, so no binary or libc is needed.
 * The challenge is assembling the chain: [pop rdi ; ret][0xC0FFEE][print_flag].
 *
 * print_flag uses only write()/_exit(), so there is no movaps alignment trap to
 * worry about — the ROP mechanics are the whole difficulty.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* An explicit `pop rdi ; ret` gadget, in its own function so its address is easy
 * to expose. The trailing ret is provided by the function epilogue. */
__asm__(
    ".global pop_rdi_gadget\n"
    "pop_rdi_gadget:\n"
    "    pop %rdi\n"
    "    ret\n");
extern void pop_rdi_gadget(void);

void print_flag(unsigned long key) {
    if (key != 0xC0FFEEUL) {
        write(1, "wrong key\n", 10);
        return;
    }
    char *f = getenv("FLAG");
    write(1, "FLAG ", 5);
    write(1, f ? f : "no flag", f ? strlen(f) : 7);
    write(1, "\n", 1);
    _exit(0);
}

void vuln(void) {
    char buf[64];
    read(0, buf, 512);          /* overflow */
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    printf("pop_rdi gadget: %p\n", (void *)pop_rdi_gadget);
    printf("print_flag:     %p\n", (void *)print_flag);
    printf("need: print_flag(0xC0FFEE). name? ");
    fflush(stdout);
    vuln();
    printf("bye\n");
    return 0;
}
