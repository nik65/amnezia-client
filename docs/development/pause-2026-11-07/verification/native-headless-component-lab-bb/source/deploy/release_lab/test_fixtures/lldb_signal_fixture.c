#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t handled;
static void on_sigsegv(int signo) { handled = signo == SIGSEGV; }

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (strcmp(argv[1], "handled") == 0) {
        if (signal(SIGSEGV, on_sigsegv) == SIG_ERR) return 65;
        sleep(1);
        raise(SIGSEGV);
        return handled ? 0 : 66;
    }
    if (strcmp(argv[1], "fatal") == 0) {
        sleep(1);
        raise(SIGSEGV);
        return 67;
    }
    return 68;
}
