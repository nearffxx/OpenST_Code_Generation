#include <stdio.h>
#include <stdlib.h>

char* copy_params(char **dumped_params, int nr_params, int len);
int dump_pollfd(int depth, char **dump_data);
int dump_int(char **dump_data);
int dump_short(char **dump_data);
int dump_uint(char **dump_data);
int dump_long(char **dump_data);

void free_dumped_params(char **dumped_params, int nr_params)
{
	int i;
	for (i=0; i<nr_params; i++)
		free(dumped_params[i]);

	free(dumped_params);
}

char* copy_params(char **dumped_params, int nr_params, int len)
{
	int i, j, aux_len;
	char *merged_params;

	// len, plus \0, plus commas, plus parenthesis
	merged_params = malloc(len+1+nr_params+2);

	merged_params[0] = '{';
	for (aux_len=1, i=0; i<nr_params; i++)
	{
		for (j=0; dumped_params[i][j] != '\0'; j++)
			merged_params[aux_len + j] = dumped_params[i][j];
		merged_params[aux_len + j] = ',';
		aux_len += j+1;
	}
	merged_params[aux_len-1] = '}';
	merged_params[aux_len] = '\0';

	return merged_params;
}

// long sys_poll(struct pollfd *ufds, unsigned int nfds, long timeout);
char* dump_sys_poll(int depth)
{
	char **dumped_params, *param_str;
	int len;

	dumped_params = malloc(3*sizeof(char*));

	len = dump_pollfd(depth, &dumped_params[0]);
	len += dump_uint(&dumped_params[1]);
	len += dump_long(&dumped_params[2]);

	param_str = copy_params(dumped_params, 3, len);

	free_dumped_params(dumped_params, 3);

	return param_str;
}

// int fd, short events, short revents
int dump_pollfd(int depth, char **dumped_params) {
	char **dumped_pollfd_params;
	int len;

	if(depth < 0)
	{
		len = 0;
		*dumped_params = malloc(0);
	} else if (depth == 0) {
		// address 8bytes + 0x + \0
		*dumped_params = malloc(11);
		snprintf(*dumped_params, 11, "0x%u", 0x61FD462F);
	} else {
		dumped_pollfd_params = malloc(3*sizeof(char*));

		len = dump_int(&dumped_pollfd_params[0]);
		len += dump_short(&dumped_pollfd_params[1]);
		len += dump_short(&dumped_pollfd_params[2]);

		*dumped_params = copy_params(dumped_pollfd_params, 3, len);

		free_dumped_params(dumped_pollfd_params, 3);
	}

	return len;
}

int dump_int(char **dumped_params) {
	*dumped_params = malloc(22);
	int n_read;

	n_read = snprintf(*dumped_params, 22, "%d", 100);

	return n_read;
}

int dump_short(char **dumped_params) {
	*dumped_params = malloc(22);
	int n_read;

	n_read = snprintf(*dumped_params, 22, "%d", 10);

	return n_read;
}

int dump_uint(char **dumped_params) {
	*dumped_params = malloc(22);
	int n_read;

	n_read = snprintf(*dumped_params, 22, "%d", 1000);

	return n_read;
}

int dump_long(char **dumped_params) {
	*dumped_params = malloc(22);
	int n_read;

	n_read = snprintf(*dumped_params, 22, "%d", 10000);

	return n_read;
}

char* dump_sys2(int depth)
{
	return "hello_sys2";
}

char* (*sys_ptr[2])(int depth);

int main()
{
	char *param_str;
	sys_ptr[0] = &dump_sys_poll;
	sys_ptr[1] = &dump_sys2;

	param_str = sys_ptr[0](0);

	//printf("%s\n", param_str);

	free(param_str);

	return 0;
}
