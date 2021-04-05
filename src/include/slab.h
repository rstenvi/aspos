#ifndef __SLAB_H
#define __SLAB_H
/**
* A simple form of slab allocator. The main reason for creating this is to
* support the creation of dynamic memory objects in kernel mode which are
* accessible in user mode. 
*
* In general, the slab can be used to allocate objects where the size is known
* at compile-time. No timing experiments have been done, so I don't know the
* speed of this compared to kmalloc.
*/

#include "kernel.h"
#include <assert.h>

#define SLAB_CHK_SIZE(type,sz) static_assert(sizeof(type) == sz, "slab size mismatch, slab allocator must be updated")
/*
* Default size we allocate in each entry, this size holds several slabs and
* should therefore be a multiple of all the sizes.
*/
#define SLAB_ALLOC_ENTRY (PAGE_SIZE)


struct slab_entry {
    void* start;
    size_t num_slabs;
    struct bm* free;

    // We can expand this if necessary
    struct slab_entry* next;
};
struct slab {
    size_t slab_size;
    enum MEMPROT prot;
    struct slab_entry* entry;
    bool user;
};

extern struct slab kernslabs[];
extern struct slab userslabs[];

#define get_slab(user, n1, n2) (user) ? &(userslabs[n1]) : &(kernslabs[n2])

void slab_free(struct slab* slab, void* addr);
void* slab_alloc(struct slab* slab);

static inline void* slab_alloc_n(struct slab* s, int n)	{
	ASSERT_TRUE(s->slab_size == n, "Slab size is wrong");
	return slab_alloc(s);

}
static inline void* slab_alloc_16(bool user)	{
	struct slab* s = get_slab(user, 0, 0);
	return slab_alloc_n(s, 16);
}
static inline void* slab_alloc_32(bool user)	{
	struct slab* s = get_slab(user, 1, 1);
	return slab_alloc_n(s, 32);
}
static inline void* slab_alloc_64(bool user)	{
	struct slab* s = get_slab(user, 2, 2);
	return slab_alloc_n(s, 64);
}

static inline void slab_free_16(void* addr, bool user)	{
	struct slab* s = get_slab(user, 0, 0);
	slab_free(s, addr);
}
static inline void slab_free_32(void* addr, bool user)	{
	struct slab* s = get_slab(user, 1, 1);
	slab_free(s, addr);
}
static inline void slab_free_64(void* addr, bool user)	{
	struct slab* s = get_slab(user, 2, 2);
	slab_free(s, addr);
}
#endif
