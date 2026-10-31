#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Test-only redirection: exercise the kernel flag without changing the host. */
int open(const char *path, int flags, ...)
{
    int (*real_open)(const char *, int, ...);
    void *symbol = dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    const char *fixture;

    if (symbol == NULL)
        _exit(127);
    _Static_assert(sizeof(real_open) == sizeof(symbol), "dlsym pointer size");
    memcpy(&real_open, &symbol, sizeof(real_open));
    if (flags & O_CREAT) {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    fixture = getenv("TEST_FIPS_FLAG_FILE");
    if (fixture != NULL && strcmp(path, "/proc/sys/crypto/fips_enabled") == 0)
        path = fixture;
    return real_open(path, flags, mode);
}
