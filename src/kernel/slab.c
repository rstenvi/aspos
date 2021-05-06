#include "kernel.h"
#include "slab.h"

struct slab kernslabs[] = {
	{16, PROT_RW, NULL, false},
	{32, PROT_RW, NULL, false},
	{64, PROT_RW, NULL, false},
};
struct slab userslabs[] = {
	{16, PROT_RW, NULL, true},
	{32, PROT_RW, NULL, true},
	{64, PROT_RW, NULL, true},
};

struct slab_entry* alloc_slab_entry(size_t num_slabs, void* addr)	{
	TZALLOC(se, struct slab_entry);
	if(PTR_IS_ERR(se))	return se;

	se->start = addr;
	se->num_slabs = num_slabs;
	se->free = bm_create(num_slabs / 8);
	se->next = NULL;
	return se;
}

static ptr_t _slab_find_free(ptr_t vmmstart, ptr_t vmmend, int pages)	{
	ptr_t i;
	int found;
	for(i = vmmstart; i < vmmend; i += PAGE_SIZE)	{
		if(mmu_addr_mapped(i, (pages * PAGE_SIZE), MMU_ALL_UNMAPPED))	{
			return i;
		}
	}
	return 0;
}

ptr_t slab_find_free_addr(struct slab* slab, int pages)	{
	return (slab->user) ?
		_slab_find_free(ARM64_VA_USER_SLAB_START, ARM64_VA_USER_SLAB_STOP, pages) :
		_slab_find_free(ARM64_VA_KERNEL_SLAB_START, ARM64_VA_KERNEL_SLAB_STOP, pages);
}
int slab_map_addr(struct slab* slab, struct slab_entry* entry)	{
	int pages = (slab->slab_size * entry->num_slabs) / PAGE_SIZE;
	if(entry->start != NULL)	{
		if(mmu_map_pages((ptr_t)entry->start, pages, slab->prot))	{
			PANIC("Unable to map pages");
		}
	}
	else	{
		ptr_t addr = slab_find_free_addr(slab, pages);
		if(addr == 0)	PANIC("Unable to find any free addr for slab");
		mmu_map_pages(addr, pages, slab->prot);
		entry->start = (void*)addr;
	}
	return OK;
}

struct slab_entry* _find_slab_entry(struct slab* slab, ptr_t addr)	{
	struct slab_entry* e = slab->entry;
	ptr_t max;
	while(e != NULL)	{
		max = (ptr_t)e->start + (slab->slab_size * e->num_slabs);

		if(addr >= (ptr_t)e->start && addr < max)	return e;
		e = e->next;
	}
	return ERR_ADDR_PTR(-GENERAL_FAULT);
}
void slab_free(struct slab* slab, void* addr)	{
	int idx;
	if(addr == NULL)	return;

	struct slab_entry* e;
	e = _find_slab_entry(slab, (ptr_t)addr);
	if(PTR_IS_ERR(e))	{
		logw("Unable to find addr %x\n", addr);
		return;
	}
	idx = ((ptr_t)addr - (ptr_t)e->start) / slab->slab_size;
	bm_clear(e->free, idx);
}


void* slab_alloc(struct slab* slab)	{
	if(slab->entry == NULL)	{
		slab->entry = alloc_slab_entry(SLAB_ALLOC_ENTRY / slab->slab_size, NULL);
		ASSERT_FALSE(PTR_IS_ERR(slab->entry), "Unable to allocate slab entry");
		slab_map_addr(slab, slab->entry);
	}
	long n;
	struct slab_entry* entry = slab->entry;
	while(entry != NULL)	{
		ASSERT_TRUE(entry->start, "addr is NULL");
		n = bm_get_first(entry->free);
		if(n >= 0)	break;
		else		entry = entry->next;
	}
	if(entry == NULL)	{
		logi("Exhausted slab of size %i, creating another\n", slab->slab_size);
		struct slab_entry* e = alloc_slab_entry(SLAB_ALLOC_ENTRY / slab->slab_size, NULL);
		ASSERT_FALSE(PTR_IS_ERR(slab->entry), "Unable to allocate slab entry");
		slab_map_addr(slab, e);

		// Add this at the beginning to future allocations faster
		e->next = slab->entry;
		slab->entry = e;
		return slab_alloc(slab);
	}
	return entry->start + (slab->slab_size * n);
}
