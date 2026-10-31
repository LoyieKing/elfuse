#define _GNU_SOURCE 1
#include <unistd.h>
#include <sys/syscall.h>
#ifndef SYS_gettid
#error no SYS_gettid
#endif
static inline pid_t __elfuse_gettid(void)
{
    return (pid_t) syscall(SYS_gettid);
}
#define gettid __elfuse_gettid
