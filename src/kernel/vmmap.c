#include "kernel.h"



int init_vmmap(void)	{
	struct vmmap* vmmap = cpu_get_vmmap();

	// Number of blocks we control
	ptr_t blocks = (VMMAP_STOP - VMMAP_START) / PAGE_SIZE;

	// Number of blocks we must reserve for vmmap bitmap
	ptr_t bmreserve = (blocks / PAGE_SIZE / 8);
	

	vmmap->vaddrstart = VMMAP_START;
	vmmap->blocks = blocks;

	// Map a single kernel page to store bitmap
	mmu_map_page(VMMAP_START, PROT_RW);

	// Say to bitmap lib where it should be located and 
	// how many bytes we have
	// We can add to this later as long as we reserve the necessary
	// virtual pages in this bitmap.
	bm_create_fixed( &(vmmap->bm), VMMAP_START, PAGE_SIZE );
	
	// Reserve blocks in the beginning so that we can expand the bitmap to cover
	// the whole VMMAP region.
	bm_set(&(vmmap->bm), 0, bmreserve);

	return 0;
}

static ptr_t find_phys_contiguous(struct vmmap* v, int pages)	{
	signed long free = bm_get_first_num(&(v->bm), pages);
	if(free < 0)	{
		PANIC("VMMAP");
	}
	return (v->vaddrstart + (PAGE_SIZE * free));
}


static ptr_t allocate_virt_contiguous(struct vmmap* v, int pages)	{
	signed long free = bm_get_first_num(&(v->bm), pages);
	if(free < 0)	{
		PANIC("VMMAP");
	}
	return (v->vaddrstart + (PAGE_SIZE * free));
}

ptr_t vmmap_alloc_pages(int pages, enum MEMPROT prot, ptr_t flags)	{
	int i;
	struct vmmap* v = cpu_get_vmmap();

	// Several flags are incompatible with lazy alloc
	if(FLAG_SET(flags, VMMAP_FLAG_LAZY_ALLOC))	{
		if(FLAG_SET(flags, VMMAP_FLAG_PHYS_CONTIG) || FLAG_SET(flags, VMMAP_FLAG_ZERO))	{
			// This is a kernel error
			PANIC("You cannot lazy alloc physically contigous pages\n");
		}
	}

	// Address is always virtually contigous
	// This function will simply reserve the VA in bitmap
	ptr_t vaddr = allocate_virt_contiguous(v, pages);

#if defined(CONFIG_KASAN)
	if(!(FLAG_SET(flags, VMMAP_FLAG_KASAN_NOMARK)))	{
		kasan_mark_valid(vaddr, pages * PAGE_SIZE);
	}
#endif

	// If lazy alloc is used, we simply reserve and return addr
	if(FLAG_SET(flags, VMMAP_FLAG_LAZY_ALLOC))	{
		return vaddr;
	}
	
	if(FLAG_SET(flags, VMMAP_FLAG_PHYS_CONTIG) || pages == 1)	{
		if(mmu_map_pages(vaddr, pages, prot) != OK)	{
			// TODO:
			// - To fix this we could move pages around so that larger blocks
			// would become available
			PANIC("Unable to allocate physically contigous pages");
		}
	}
	else	{
#if CONFIG_ATTEMPT_PLUG_MEMORY_HOLES == 1
		/*
		* If the pages doesn't need to be physically contiguous, we allocate all
		* the pages individually. This way, we increase the chance that we
		* reserve physically contguous blocks for when they are needed.
		*/
		for(i = 0; i < pages; i++)	{
			mmu_map_page(vaddr + (i * PAGE_SIZE), prot);
		}
#else
		if(mmu_map_pages(vaddr, pages, prot) != OK)	{
			PANIC("");
		}
#endif
	}

	if(FLAG_SET(flags, VMMAP_FLAG_ZERO))	{
		if(!prot_writable(prot))	{
			// Need to temporary change permissions
			PANIC("Not made yet");
		}
		memset((void*)vaddr, 0x00, (PAGE_SIZE * pages));
	}

	return vaddr;
}

ptr_t vmmap_alloc_page(enum MEMPROT prot, ptr_t flags)	{
	return vmmap_alloc_pages(1, prot, flags);
}

int vmmap_map_page(ptr_t vaddr)	{
	// TODO: Must take a protection argument as well
	mmu_map_page(vaddr, PROT_RW);
	return 0;
}
int vmmap_map_pages(ptr_t vaddr, int pages)	{
	int i;
	for(i = 0; i < pages; i++)	{
		vmmap_map_page(vaddr + (i * PAGE_SIZE) );
	}
	return 0;
}

void vmmap_unmap(ptr_t vaddr)	{
	struct vmmap* v = cpu_get_vmmap();

	mmu_unmap_page(vaddr);
	bm_clear( &(v->bm), (vaddr - v->vaddrstart) / PAGE_SIZE );
}

void vmmap_unmap_pages(ptr_t vaddr, int pages)	{
	int i;
	for(i = 0; i < pages; i++)	{
		vmmap_unmap(vaddr + (i * PAGE_SIZE));
	}
}
