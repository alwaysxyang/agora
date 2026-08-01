#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>

extern int agora_sandbox_open_with_mode(const char *path, int flags, mode_t mode);
extern int agora_sandbox_openat_with_mode(int directory, const char *path, int flags, mode_t mode);

typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);

int agora_sandbox_call_open(const void *function, const char *path, int flags, mode_t mode) {
    open_fn original = (open_fn)function;
    return (flags & O_CREAT) != 0 ? original(path, flags, (int)mode) : original(path, flags);
}

int agora_sandbox_call_openat(
    const void *function,
    int directory,
    const char *path,
    int flags,
    mode_t mode
) {
    openat_fn original = (openat_fn)function;
    return (flags & O_CREAT) != 0 ? original(directory, path, flags, (int)mode)
                                  : original(directory, path, flags);
}

int agora_sandbox_open_shim(const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    return agora_sandbox_open_with_mode(path, flags, mode);
}

int agora_sandbox_openat_shim(int directory, const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    return agora_sandbox_openat_with_mode(directory, path, flags, mode);
}
