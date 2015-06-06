#include<stdio.h>
#include"a.h"

void sys_1(struct st st1)
{
	printf("%d, %d\n", st1.a, st1.b);
}

int main ()
{
	struct st st1 = 
	{
		.a = 2,
		.b = 3
	};
	sys_1(st1);
}
