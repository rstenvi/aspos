#include "kernel.h"

#define PAGE_SIZE ARM64_PAGE_SIZE

void pmm_add_ref(size_t block)	{
	struct pmm* pmm = cpu_get_pmm();
	pmm->bitmap[block]++;
}

int pmm_init()	{
	int i;
	struct pmm* pmm = cpu_get_pmm();

	mutex_clear(&pmm->lock);

	// Calculate number of blocks we have
	size_t blocks = (pmm->end - pmm->start) / PAGE_SIZE;

	// Calculate blocks we must reserve for bitmap
	size_t bm_blocks = blocks / PAGE_SIZE;
	if((blocks % PAGE_SIZE) != 0)	bm_blocks++;

	// Place bitmap at the end
	pmm->bitmap = (uint8_t*)(pmm->end - (bm_blocks * PAGE_SIZE));
	memset(pmm->bitmap, 0x00, bm_blocks * PAGE_SIZE);
	
	for(i = (blocks - bm_blocks); i < blocks; i++)	{
		pmm_add_ref(i);
	}
	pmm->pages = blocks;

	stat_set_phys_pages(pmm->pages);
	stat_add_taken_pages(bm_blocks);
	logd("Stored bitmap @ %p\n", pmm->bitmap);
	return 0;	
}

void pmm_free(ptr_t page)	{
	logd("Freeing page 0x%lx\n", page);
	struct pmm* pmm = cpu_get_pmm();
	ptr_t idx = (page - pmm->start) / PAGE_SIZE;

	mutex_acquire(&pmm->lock);
	pmm->bitmap[idx] = 0;
	mutex_release(&pmm->lock);
}

ptr_t pmm_alloc(int pages)	{
	int i, count = 0, j;
	ptr_t ret = 0;
	struct pmm* pmm = cpu_get_pmm();
	mutex_acquire(&pmm->lock);
	for(i = 0; i < pmm->pages; i++)	{
		if(pmm->bitmap[i] == 0)	count++;
		else					count = 0;

		if(count == pages)	{
			
			for(j = (1+i-pages); j < (i+pages); j++)	{
				pmm->bitmap[j] = 1;
			}
			stat_add_taken_pages(pages);
			ret = (pmm->start + ((1+i-pages) * PAGE_SIZE));
			goto done;
		}
	}
done:
	mutex_release(&pmm->lock);
	return ret;
}

int pmm_mark_mem(ptr_t start, ptr_t end)	{
	struct pmm* pmm = cpu_get_pmm();
	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	ALIGN_UP_POW2(end, PAGE_SIZE);
	logd("Marking memory 0x%lx -> 0x%lx\n", start, end);

	ASSERT_TRUE(start < end, "End is lower than start");

	mutex_acquire(&pmm->lock);
	ptr_t rstart = start - pmm->start;
	ptr_t rend = end - pmm->start;
	ptr_t i;

	stat_add_taken_pages( (rend - rstart) / PAGE_SIZE );

	for(i = (rstart / PAGE_SIZE); i < (rend / PAGE_SIZE); i++)	{
		pmm_add_ref(i);
	}
	mutex_release(&pmm->lock);
	return 0;
}

int pmm_highmem_init(ptr_t linstart)	{
	struct pmm* pmm = cpu_get_pmm();
	mutex_acquire(&pmm->lock);
	pmm->bitmap = (uint8_t*)( (ptr_t)(pmm->bitmap) + linstart );
	mutex_release(&pmm->lock);
	return 0;
}

highmem_init(pmm_highmem_init);