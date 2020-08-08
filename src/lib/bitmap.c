/**
* Simple bitmap implementation.
*/
#include "lib.h"

static inline bool bit_set(char c, int num)	{ return ((c & (1<<num)) != 0); }
static inline void set_bit(char* c, int num) { *c |= (1<<num); }
static inline void clear_bit(char* c, int num) { *c &= ~(1<<num); }

struct bm* bm_create(unsigned long bytes)	{
	struct bm* bm = (struct bm*)xalloc( sizeof(struct bm) );
	void* b = (void*)xalloc(bytes);
	memset(b, 0x00, bytes);

	bm->bm = b;
	bm->bytes = bytes;

	return bm;
}

int bm_create_fixed(struct bm* bm, ptr_t addr, unsigned long bytes)	{
	bm->bytes = bytes;
	bm->bm = (void*)addr;

	memset(bm->bm, 0x00, bm->bytes);
	return 0;
}

signed long bm_get_first(struct bm* bm)	{
	uint8_t* b = (uint8_t*)bm->bm;
	long i, j;
	for(i = 0; i < bm->bytes; i++)	{
		if(b[i] == 0xff)	continue;

		for(j = 0; j < 8; j++)	{
			if(!(bit_set(b[i], j)))	{
				set_bit(&(b[i]), j);
				return (i * 8) + j;
			}
		}
	}
	return -1;
}

signed long bm_get_first_num(struct bm* bm, int num)	{
	uint8_t* b = (uint8_t*)bm->bm;
	int count = 0, i, j;
	for(i = 0; i < bm->bytes * 8; i++)	{
		if(!(bit_set(b[i/8], i % 8)))	{
			count++;
			if(count == num)	{
				// If found, mark as taken and return
				for(j = (i - count + 1); j <= i; j++)	{
					set_bit( &(b[j/8]), j % 8);
				}
				return (i - count + 1);
			}
		}
		else	{
			count = 0;
		}
	}

}

void bm_clear(struct bm* bm, long idx)	{
	uint8_t* b = (uint8_t*)bm->bm;
	clear_bit(&(b[idx / 8]), idx % 8);
}

void bm_set(struct bm* bm, int from, int to)	{
	int i;
	uint8_t* b = (uint8_t*)(bm->bm);
	for(i = from; i < to; i++)	{
		set_bit(&(b[i/8]), i % 8);
	}
}
