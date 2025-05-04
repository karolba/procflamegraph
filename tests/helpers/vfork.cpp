#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

#include "common.hpp"

int first_child(char *progname) {
    MUST_LIBC(execl(progname, progname, "--wahooo", NULL));
    return 1;
}

int second_child() {
    return 0;
}

int third_child() {
    return 50;
}

int fourth_child(char *progname) {
    MUST_LIBC(execl(progname, progname, "--self-exec", NULL));
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--wahooo") == 0) {
        printf("Wahoo\n");
        return 123;
    }

    if (argc == 2 && strcmp(argv[1], "--self-exec") == 0) {
        return 42;
    }

    pid_t p1, p2, p3, p4;

    if ((p1 = MUST_LIBC(vfork())) == 0) {
        _exit(first_child(argv[0]));
    }

    if ((p2 = MUST_LIBC(vfork())) == 0) {
        _exit(second_child());
    }

    if ((p3 = MUST_LIBC(vfork())) == 0) {
        _exit(third_child());
    }

    if ((p4 = MUST_LIBC(vfork())) == 0) {
        _exit(fourth_child(argv[0]));
    }

    int child_return;
    MUST_LIBC(waitpid(p1, &child_return, 0));
    MUST(WEXITSTATUS(child_return) == 123);

    MUST_LIBC(waitpid(p2, &child_return, 0));
    MUST(WEXITSTATUS(child_return) == 0);

    MUST_LIBC(waitpid(p3, &child_return, 0));
    MUST(WEXITSTATUS(child_return) == 50);

    MUST_LIBC(waitpid(p4, &child_return, 0));
    MUST(WEXITSTATUS(child_return) == 42);

    return 0;
}
