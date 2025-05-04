#include <sys/syscall.h>

/*
 * This little program exists to test whether injecting our own syscalls just before the first syscall
 * executes in the target program doesn't mess with the first syscall of the target.
 *
 * The libc does a couple of syscalls before main() starts, so this file skips the libc
 * The linker also does syscalls of its own, so this file needs to be compiled with -static
 */

#ifdef __x86_64__
    #define SYSCALL(sysno, arg1, arg2, arg3, arg4, arg5, arg6) __asm__ volatile ( \
        "syscall" \
        : \
        : "a" (sysno), "D" (arg1), "S" (arg2), "d" (arg3), "r" (arg4), "r" (arg5), "r" (arg6) \
        : "rcx", "r11", "memory" \
    )
#elif __aarch64__
    #define SYSCALL(sysno, arg1, arg2, arg3, arg4, arg5, arg6) do { \
        register long x8 __asm__("x8") = (sysno); \
        register long x0 __asm__("x0") = (arg1); \
        register long x1 __asm__("x1") = (arg2); \
        register long x2 __asm__("x2") = (arg3); \
        register long x3 __asm__("x3") = (arg4); \
        register long x4 __asm__("x4") = (arg5); \
        register long x5 __asm__("x5") = (arg6); \
        __asm__ volatile ( \
            "svc #0" \
            : "+r"(x0) \
            : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) \
            : "memory" \
        ); \
    } while(0)
#else
    #error unsupported architecture, sorry
#endif

static const char msg1[] = "Hello ";
static const char msg2[] = "world\n";

extern "C" void _start() {
    SYSCALL(SYS_write, 1, (long int)msg1, sizeof(msg1) - 1, 0, 0, 0);
    SYSCALL(SYS_write, 1, (long int)msg2, sizeof(msg2) - 1, 0, 0, 0);
    SYSCALL(SYS_exit, 0, 0, 0, 0, 0, 0);
}
