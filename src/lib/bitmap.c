/**
* Simple bitmap implementation.
*/
#include "lib.h"

static inline bool bit_set(char c, int num)	{ return ((c & (1<<num)) != 0); }
static inline void set_bit(char* c, int num) { *c |= (1<<num); }
static inline void clear_bit(char* c, int num) { *c &= ~(1<<num); }

struct bm* bm_create(unsigned long bytes)	{
	TMALLOC(bm, struct bm);
	if(PTR_IS_ERR(bm))	return bm;
	void* b = (void*)kmalloc(bytes);
	if(PTR_IS_ERR(b))	{
		kfree(bm);
		return b;
	}

	bm_create_fixed(bm, (ptr_t)b, bytes);
	return bm;
}
void bm_delete(struct bm* bm)	{
	mutex_acquire(&bm->lock);
	kfree(bm->bm);
	kfree(bm);
}
int bm_create_fixed(struct bm* bm, ptr_t addr, unsigned long bytes)	{
	bm->bytes = bytes;
	bm->bm = (void*)addr;
	mutex_clear(&bm->lock);

	memset(bm->bm, 0x00, bm->bytes);
	return 0;
}

signed long bm_get_first(struct bm* bm)	{
	uint8_t* b = (uint8_t*)bm->bm;
	long i, j, res = -1;

	mutex_acquire(&bm->lock);
	for(i = 0; i < bm->bytes; i++)	{
		if(b[i] == 0xff)	continue;

		for(j = 0; j < 8; j++)	{
			if(!(bit_set(b[i], j)))	{
				set_bit(&(b[i]), j);
				res = (i * 8) + j;
				goto done;
			}
		}
	}
done:
	mutex_release(&bm->lock);
	return res;
}

bool bm_index_free(struct bm* bm, int idx)	{
	uint8_t* b = (uint8_t*)bm->bm;
	return !(bit_set(b[idx/8], idx % 8));
}

bool bm_index_taken(struct bm* bm, int idx)	{
	return !(bm_index_free(bm, idx));
}

signed long bm_get_first_num(struct bm* bm, int num)	{
	uint8_t* b = (uint8_t*)bm->bm;
	int count = 0, i, j;
	long res = -1;

	mutex_acquire(&bm->lock);
	for(i = 0; i < bm->bytes * 8; i++)	{
		if(!(bit_set(b[i/8], i % 8)))	{
			count++;
			if(count == num)	{
				// If found, mark as taken and return
				for(j = (i - count + 1); j <= i; j++)	{
					set_bit( &(b[j/8]), j % 8);
				}
				res = (i - count + 1);
				goto done;
			}
		}
		else	{
			count = 0;
		}
	}
done:
	mutex_release(&bm->lock);
	return res;
}

void bm_clear(struct bm* bm, long idx)	{
	uint8_t* b = (uint8_t*)bm->bm;
	mutex_acquire(&bm->lock);
	clear_bit(&(b[idx / 8]), idx % 8);
	mutex_release(&bm->lock);
}
void bm_clear_nums(struct bm* bm, long idx, int count)	{
	int i;
	for(i = 0; i < count; i++)	{
		bm_clear(bm, idx + i);
	}
}

void bm_set(struct bm* bm, int from, int to)	{
	int i;
	uint8_t* b = (uint8_t*)(bm->bm);
	mutex_acquire(&bm->lock);
	for(i = from; i < to; i++)	{
		set_bit(&(b[i/8]), i % 8);
	}
	mutex_release(&bm->lock);
}
