typedef int		__kernel_pid_t;
typedef __kernel_pid_t	pid_t;
struct st
{
	int a;
	int b;
};
struct pollfd {
	int fd;
	short events;
	unsigned short revents;
	pid_t *pid;
	struct st *pid2;
};
struct st2
{
	int a;
};
typedef struct {
	int a;
}time_t;

typedef struct {
	int b;
}size_t;

typedef struct {
	int *c;
}uid_t;
typedef struct {
	pid_t d;
}gid_t;

char* sys_1(struct st *st1, const struct st2* st2, unsigned a, time_t *tloc, long c, unsigned long d) {}
char* sys_2(void) {}
char* sys_3(unsigned int asd) {}
char* sys_3_5(unsigned long sdfsdf) {}
char* sys_4(struct pollfd *ufds) {}
char* sys_5(pid_t *pid) {}
char* sys_6(unsigned int *asd) {}