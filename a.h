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
	struct st *two_digs;
	pid_t *pid;
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

