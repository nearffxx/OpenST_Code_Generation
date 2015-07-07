typedef int clockid_t;

long sys_clock_gettime(clockid_t which_clock,
        struct timespec  *tp) {}
