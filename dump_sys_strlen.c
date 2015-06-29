#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* copy_params(char **dumped_params, int nr_params, int len);
char* dump_pollfd(int depth);
char* dump_int();
char* dump_short();
char* dump_uint();
char* dump_long();

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

	//snprintf(merged_params, 21, "TODO: copy");

	return merged_params;
}

// long sys_poll(struct pollfd *ufds, unsigned int nfds, long timeout);
char* dump_sys_poll(int depth)
{
	char **dumped_params, *res;

	dumped_params = malloc(3*sizeof(char*));

	dumped_params[0] = dump_pollfd(depth);
	dumped_params[1] = dump_uint();
	dumped_params[2] = dump_long();

	int len = strlen(dumped_params[0]) + strlen(dumped_params[1]) + strlen(dumped_params[2]);

	res = copy_params(dumped_params, 3, len);

	free_dumped_params(dumped_params, 3);

	return res;
}

// int fd, short events, short revents
char* dump_pollfd(int depth) {
	char **dumped_params, *res;

	if(depth < 0)
	{
		res = malloc(0);
	} else if (depth == 0) {
		// address 8bytes + 0x + \0
		res = malloc(11);
		snprintf(res, 11, "0x%u", 0x61FD462F);
	} else {
		dumped_params = malloc(3*sizeof(char*));

		dumped_params[0] = dump_int();
		dumped_params[1] = dump_short();
		dumped_params[2] = dump_short();

		int len = strlen(dumped_params[0]) + strlen(dumped_params[1]) + strlen(dumped_params[2]);

		res = copy_params(dumped_params, 3, len);

		free_dumped_params(dumped_params, 3);
	}

	return res;
}

char* dump_int() {
	char *buffer;

	buffer = malloc(21);

	snprintf(buffer, 21, "%d", 100);

	return buffer;
}

char* dump_short() {
	char *buffer;

	buffer = malloc(21);

	snprintf(buffer, 21, "%d", 10);

	return buffer;
}

char* dump_uint() {
	char *buffer;

	buffer = malloc(21);

	snprintf(buffer, 21, "%d", 1000);

	return buffer;
}

char* dump_long() {
	char *buffer;

	buffer = malloc(21);

	snprintf(buffer, 21, "%d", 10000);

	return buffer;
}

char* dump_sys2(int depth)
{
	return "hello_sys2";
}

char* (*sys_ptr[2])(int depth);

int main()
{
	char *dumped_params;
	sys_ptr[0] = &dump_sys_poll;
	sys_ptr[1] = &dump_sys2;

	dumped_params = sys_ptr[0](0);

	//printf("%s\n", dumped_params);

	free(dumped_params);

	return 0;
}

