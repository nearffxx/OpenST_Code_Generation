#include<stdio.h>
#include <stdint.h>
#include <string.h>
#include"a.h"

// emulation
int32_t reg( char *r )
{
	if ( !strcmp(r, "r0") )
	{
		return 0x00000000;
	} else if ( !strcmp(r, "r1") )
	{
		return 0x00000000;
	}
	return 0;
}

int8_t mdb(int32_t addr)
{
	int8_t a[] = { 1, 0, 0, 0, 2, 0, 0, 0 };
	return a[addr];
}
// end emulation

// util
void cpy( void *dst, int32_t addr, int32_t len )
{
	int32_t i;
	for(i = 0; i < len; i++)
	{
		( (int8_t *) dst)[i] = mdb( addr + i );
	}
}

int32_t offset_base(void *arg, void *base)
{
	return (int8_t *)arg - (int8_t *)base;
}
// end util

// structs dump
void p_st( struct st *st1, int32_t addr )
{
	cpy( &st1->a, addr + offset_base( &st1->a, st1 ), sizeof(st1->a) ); // CHECK SIZEOF
	cpy( &st1->b, addr + offset_base( &st1->b, st1 ), sizeof(st1->b) ); // CHECK SIZEOF
}
// end structs dump

// syscalls dump
void sys_1()
{
	int32_t base_addr = reg( "r0" );
	struct st *st1 = malloc( sizeof( st1 ) );
	p_st( st1, base_addr );
	
	printf( "0x%08x, 0x%08x\n", &st1->a, &st1->b );
	printf( "0x%08x, 0x%08x\n", st1->a, st1->b );
}
// end syscalls dumps

int main ()
{
	sys_1();
}
