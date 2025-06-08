#include <stdio.h>
#include <unistd.h>
#include <thread>

static void in_thread() {
    exit(101);
}

int main() {
    std::thread thr(in_thread);
    thr.join();

    puts("this should never happen");
}
