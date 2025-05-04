#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include "common.hpp"

#define X_SIGNALS \
    X(SIGHUP)     \
    X(SIGINT)     \
    X(SIGQUIT)    \
    X(SIGILL)     \
    X(SIGTRAP)    \
    X(SIGABRT)    \
    X(SIGBUS)     \
    X(SIGFPE)     \
    X(SIGUSR1)    \
    X(SIGSEGV)    \
    X(SIGUSR2)    \
    X(SIGPIPE)    \
    X(SIGALRM)    \
    X(SIGTERM)    \
    X(SIGCHLD)    \
    X(SIGCONT)    \
    X(SIGTSTP)    \
    X(SIGTTIN)    \
    X(SIGTTOU)    \
    X(SIGURG)     \
    X(SIGXCPU)    \
    X(SIGXFSZ)    \
    X(SIGVTALRM)  \
    X(SIGPROF)    \
    X(SIGWINCH)   \
    X(SIGIO)      \
    X(SIGSYS)     \
    X(SIGQUIT)

static const int number_of_handled_signal_types =
    0
    #define X(_signal) + 1
    X_SIGNALS
    #undef X
    ;

static const char *signal_message(int sig) {
    #define X(signal) if (sig == signal) return "Caught a signal: " #signal "\n";
    X_SIGNALS
    #undef X
    return "Caught an unknown signal\n";
};

static volatile int caught_signals = 0;

static void sig_handler(int sig) {
    const char *message = signal_message(sig);
    write(STDOUT_FILENO, message, strlen(message));

    caught_signals += 1;
}

int main() {
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    #define X(signal) sigaction(signal, &sa, NULL);
    X_SIGNALS
    #undef X

    #define X(signal) raise(signal);
    X_SIGNALS
    #undef X

    // make sure everything is done
    while (caught_signals < number_of_handled_signal_types) {
        pause();
    }

    return 0;
}
