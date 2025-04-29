#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>

#include "common.hpp"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        MUST_LIBC(execl(argv[0], argv[0], "--factorial", "9", NULL));
    }

    MUST(strcmp(argv[1], "--factorial") == 0);

    if (strcmp(argv[2], "0") == 0 || strcmp(argv[2], "1") == 0) {
        puts(argv[2]);
        exit(0);
    }

    int number = atoi(argv[2]);

    pid_t p1, p2;

    int pipe1[2], pipe2[2];
    MUST_LIBC(pipe(pipe1));
    MUST_LIBC(pipe(pipe2));

    if ((p1 = MUST_LIBC(fork())) == 0) {
        MUST_LIBC(dup2(pipe1[1], 1));
        char numarg[16];
        snprintf(numarg, 16, "%d", number - 1);
        MUST_LIBC(execl(argv[0], argv[0], "--factorial", numarg, NULL));
    }

    if ((p2 = MUST_LIBC(fork())) == 0) {
        MUST_LIBC(dup2(pipe2[1], 1));
        char numarg[16];
        snprintf(numarg, 16, "%d", number - 2);
        MUST_LIBC(execl(argv[0], argv[0], "--factorial", numarg, NULL));
    }

    FILE *child_1_out = MUST_LIBC_NOT_NULL(fdopen(pipe1[0], "r"));
    FILE *child_2_out = MUST_LIBC_NOT_NULL(fdopen(pipe2[0], "r"));

    int child_1_out_nr, child_2_out_nr;
    MUST_LIBC(fscanf(child_1_out, "%d", &child_1_out_nr));
    MUST_LIBC(fscanf(child_2_out, "%d", &child_2_out_nr));

    printf("%d\n", child_1_out_nr + child_2_out_nr);

    int child_return;
    MUST_LIBC(waitpid(p1, &child_return, 0));
    MUST(WEXITSTATUS(child_return) == 0);

    MUST_LIBC(waitpid(p2, &child_return, 0));
    MUST(WEXITSTATUS(child_return) == 0);

    return 0;
}
