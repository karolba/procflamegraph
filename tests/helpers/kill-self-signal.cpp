#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include "common.hpp"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <signal-number>\n", argv[0]);
        return 1;
    }

    int signal = atoi(argv[1]);
    printf("doing raise(%d)\n", signal);

    MUST_LIBC(raise(signal));

    // wait to be killed
    while (true)
        pause();

    return 0;
}
