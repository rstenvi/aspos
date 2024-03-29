#include "kernel.h"

#define PAGE_SIZE ARM64_PAGE_SIZE


static int _pmm_add_ref(size_t block)	{
	struct pmm* pmm = cpu_get_pmm();
	if(pmm->bitmap[block] != 0xff)	{
		pmm->bitmap[block]++;
		return pmm->bitmap[block];
	}
	return -1;
}
static int _pmm_dec_ref(size_t block)	{
	struct pmm* pmm = cpu_get_pmm();
	if(pmm->bitmap[block] > 0)	{
		pmm->bitmap[block]--;
		return pmm->bitmap[block];
	}
	return -1;
}

int pmm_init()	{
	size_t i;
	struct pmm* pmm = cpu_get_pmm();
	ptr_t offset = cpu_linear_offset();

	mutex_clear(&pmm->lock);

	// Calculate number of blocks we have
	size_t blocks = (pmm->end - pmm->start) / PAGE_SIZE;

	// Calculate blocks we must reserve for bitmap
	size_t bm_blocks = blocks / PAGE_SIZE;
	if((blocks % PAGE_SIZE) != 0)	bm_blocks++;

	// Place bitmap at the end
	pmm->bitmap = (uint8_t*)(pmm->end - (bm_blocks * PAGE_SIZE));
	pmm->bitmap = (uint8_t*)((ptr_t)pmm->bitmap + offset);
	memset(pmm->bitmap, 0x00, bm_blocks * PAGE_SIZE);
	
	for(i = (blocks - bm_blocks); i < blocks; i++)	{
		_pmm_add_ref(i);
	}
	pmm->pages = blocks;

	stat_set_phys_pages(pmm->pages);
	stat_add_taken_pages(bm_blocks);
	return 0;	
}
int pmm_ref(ptr_t page)	{
	int res = -1;
	struct pmm* pmm = cpu_get_pmm();
	ptr_t idx = (page - pmm->start) / PAGE_SIZE;
	res = pmm->bitmap[idx];
	return res;

}
int pmm_add_ref(ptr_t page)	{
	int res = -1;
	struct pmm* pmm = cpu_get_pmm();
	ptr_t idx = (page - pmm->start) / PAGE_SIZE;

	mutex_acquire(&pmm->lock);
	res = _pmm_add_ref(idx);
	mutex_release(&pmm->lock);
	return res;
}
int pmm_free(ptr_t page)	{
	int res = -1;
	struct pmm* pmm = cpu_get_pmm();
	ptr_t idx = (page - pmm->start) / PAGE_SIZE;

	mutex_acquire(&pmm->lock);
	res = _pmm_dec_ref(idx);
	mutex_release(&pmm->lock);
	return res;
}

ptr_t pmm_alloc(int pages)	{
	size_t i, j;
	int count = 0;
	ptr_t ret = 0;
	struct pmm* pmm = cpu_get_pmm();
	mutex_acquire(&pmm->lock);
	for(i = 0; i < pmm->pages; i++)	{
		if(pmm->bitmap[i] == 0)	count++;
		else					count = 0;

		if(count == pages)	{
			for(j = (1+i-pages); j < (i+pages); j++)	{
				_pmm_add_ref(j);
			}
			stat_add_taken_pages(pages);
			ret = (pmm->start + ((1+i-pages) * PAGE_SIZE));
			goto done;
		}
	}
	PANIC("Unable to find physical page, must do paging");
done:
	mutex_release(&pmm->lock);
	//logd("PMM: %lx - %i\n", ret, pages);
	return ret;
}
ptr_t pmm_allocz(int pages)	{
	ptr_t page = pmm_alloc(pages);
	ASSERT_TRUE(page != 0, "Unable to allocate page table");
	ptr_t vpage = page + cpu_linear_offset();
	memset((void*)vpage, 0x00, pages * PAGE_SIZE);
	return page;
}

int pmm_mark_mem(ptr_t start, ptr_t end)	{
	struct pmm* pmm = cpu_get_pmm();
	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	ALIGN_UP_POW2(end, PAGE_SIZE);

	ASSERT_TRUE(start < end, "End is lower than start");

	mutex_acquire(&pmm->lock);
	ptr_t rstart = start - pmm->start;
	ptr_t rend = end - pmm->start;
	ptr_t i;

	stat_add_taken_pages( (rend - rstart) / PAGE_SIZE );

	for(i = (rstart / PAGE_SIZE); i < (rend / PAGE_SIZE); i++)	{
		_pmm_add_ref(i);
	}
	mutex_release(&pmm->lock);
	return 0;
}

// int pmm_highmem_init(ptr_t linstart)	{
// 	struct pmm* pmm = cpu_get_pmm();
// 	mutex_acquire(&pmm->lock);
// 	pmm->bitmap = (uint8_t*)( (ptr_t)(pmm->bitmap) + linstart );
// 	mutex_release(&pmm->lock);
// 	return 0;
// }
// highmem_init(pmm_highmem_init);
