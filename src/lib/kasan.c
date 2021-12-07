
#ifndef UMODE
#include "kernel.h"
#else
#include "lib.h"
#include "fcntl.h"
#endif

#include "memory.h"
#include "kasan.h"
#include "arch.h"

#ifndef UMODE
#define KASAN_START_ADDR (ARM64_VA_SHADOW_START)
#define ADDR_EL_WRONG ADDR_USER
#define KASAN_FIRST_ADDR (ARM64_VA_KERNEL_FIRST_ADDR)
#define kasan_exit(n) kern_poweroff(1)
#else
// Generated dynamically based on mmap()
ptr_t KASAN_START_ADDR = 0;
#define ADDR_EL_WRONG ADDR_KERNEL
#define KASAN_FIRST_ADDR (0)
//#define kasan_exit(n) exit(n)
#define kasan_exit(n) poweroff()
#endif

#define _KASAN_ROUND_DOWN(val) (GET_ALIGNED_DOWN_POW2(val, SHADOW_BYTES_PER))
#define _KASAN_ROUND_UP(val)   (GET_ALIGNED_UP_POW2(val, SHADOW_BYTES_PER))
#define ADDR_TO_SHADOW_FIRST(val) (((_KASAN_ROUND_DOWN(val) - KASAN_FIRST_ADDR) / SHADOW_BYTES_PER) + KASAN_START_ADDR)
#define ADDR_TO_SHADOW_LAST(val) (((_KASAN_ROUND_UP(val) - KASAN_FIRST_ADDR) / SHADOW_BYTES_PER) + KASAN_START_ADDR)

#define ADDR_OFFSET_IN_BYTE(addr) (addr % SHADOW_BYTES_PER)
//#define ADDR_OFFSET_VALUE(addr) (SHADOW_BYTES_PER - ADDR_OFFSET_IN_BYTE(addr))

#define KASAN_MAGIC_INVALID  (0xff)
#define KASAN_MAGIC_FREED    (0xfe)
#define KASAN_MAGIC_RZ_BEFOR (0xfd)
#define KASAN_MAGIC_RZ_AFTER (0xfc)

#ifndef UMODE
extern uint64_t KERNEL_TEXT_START;
extern uint64_t KERNEL_TEXT_STOP;
extern uint64_t KERNEL_DATA_START;
extern uint64_t KERNEL_DATA_STOP;
extern uint64_t KERNEL_BSS_START;
extern uint64_t KERNEL_BSS_STOP;
extern uint64_t KERNEL_RODATA_START;
extern uint64_t KERNEL_RODATA_STOP;
#else
extern uint64_t UMODE_IMAGE_START;
extern uint64_t UMODE_IMAGE_STOP;
#endif

#define KASAN_STORE_ALLOC_LOC 1

/**
* We allocate an array of these using a page, so the size should be divisible by
* PAGE_SIZE.
*/
struct k_alloced {
	ptr_t addr, size;
	uint16_t rz_before, rz_after;
#if defined(KASAN_STORE_ALLOC_LOC)
	ptr_t caller;
#endif
} __attribute__((aligned(32)));;

/**
* Array of allocated objects
*
* Would normally use a linked list here, but insertion in that list migth
* cause a malloc, which will cause an infinite loop. To avoid this mess, we
* use an array and allocate pages as needed.
*/
struct k_alloc {
	int curr, max, amax;
	struct k_alloced* arr;
};

struct kasan {
	mutex_t lock;
	bool initialized;

	/** Wether fault is a PANIC */
	bool panic_on_err;

#ifndef UMODE
	/*
	* We currently don't track memory in the linear region. As a result, we must
	* allow all access to the regions. Possible better solutions:
	* - Track all memory in linear regions
	* - Disable asan in functions which access linear region
	*/
	ptr_t linear_start, linear_length;
//#else
//	int memfd;
#endif

	/** All objects allocated, but not free'd */
	struct k_alloc alloced;
#if KASAN_FREE_QUARANTINE
	struct XIFO* quarantine;
#endif
};

static struct kasan kasan;

#define MSGID_PAGE_UNMAPPED (0)
#define MSGID_INV_ACCESS    (1)
#define MSGID_UAF           (2)
#define MSGID_RZ_BEFORE     (3)
#define MSGID_RZ_AFTER      (4)
#define MSGID_INV_FREE      (5)
#define MSGID_WRONG_EL_ADDR (6)
#define NUM_MSGIDS (7)
static const char* kasan_msgs[] = {
	"page not mapped in",
	"invalid access",
	"use-after-free",
	"redzone before buffer",
	"redzone after buffer",
	"free of invalid value",
#ifndef UMODE
	"user-mode addr",
#else
	"kernel-mode addr",
#endif
};

static int kasan_report(int msgid, ptr_t addr, int size, bool write, ptr_t ip)	{
	kasan.initialized = false;
	char* msg = "undefined";
	char* access = (write) ? "Write" : "Read";

	if(msgid < NUM_MSGIDS)	msg = (char*)kasan_msgs[msgid];
	bugprintf("BUG: KASAN: %s IP %lx\n%s at addr %lx of %i bytes\n",
		msg, ip, access, addr, size);

	bugprintf("KASAN finished\n");

	//osdata.printk("KASAN: %s: Address: %lx IP: %lx\n", msg, addr, ip);
	if(kasan.panic_on_err)	{
		bugprintf("KASAN: panic_on_err is set, powering off\n");
		kasan_exit(1);
	}
	bugprintf("\n");
	kasan.initialized = true;
	return OK;
}

static int check_addr_shadow(ptr_t start, ptr_t end, bool write, ptr_t ip)	{
	/**
	* TODO: This is currently valid because arch-code is excluded, should
	* re-evaluate that.
	*/
	if(ADDR_EL_WRONG(start) || ADDR_EL_WRONG(end))	{
		/*
		* This is currently ignored
		* - Wrong access from kernel mode should be caught by PAN
		* - Wrong access from user mode should trigger a page fault
		*/
		//kasan_report(MSGID_WRONG_EL_ADDR, start, (end - start), write, ip);
		return OK;
	}

	char* s_start = (char*)ADDR_TO_SHADOW_FIRST(start),
		*s_end = (char*)ADDR_TO_SHADOW_LAST(end);
	char* shadow = s_start;
	int first_byte = (start % 8);
	int last_byte = (end % 8);
	unsigned char c;
/*
	int n = seek_read(kasan.memfd, NULL, (s_end - s_start), (ptr_t)shadow) < (s_end - s_start);
	if(n != (s_end - s_start)) {
		printf("seek read returned %i\n", n);
		kasan_report(MSGID_PAGE_UNMAPPED, start + (shadow - s_start), (end - start), write, ip);
	}*/
	ptr_t i = GET_ALIGNED_PAGE_DOWN((ptr_t)s_start),
		stop = GET_ALIGNED_PAGE_UP((ptr_t)s_end);
	for(; i < stop; i += PAGE_SIZE)	{
#ifndef UMODE
		if(!mmu_page_mapped(i))	{
#else
		if(!is_mapped(i))	{
#endif
			kasan_report(MSGID_PAGE_UNMAPPED, start + (shadow - s_start), (end - start), write, ip);
			return 1;
		}
	}
	
	while(shadow != s_end)	{
		c = *shadow;
		if(c != 0x00)	{
			if(c > SHADOW_BYTES_PER)	{
				kasan_report(0x100 - (int)c, start + (shadow - s_start), (end - start), write, ip);
				return c;
			}
			if(shadow == s_start && first_byte > c)	{
				kasan_report(MSGID_INV_ACCESS, start + (shadow - s_start), (end - start), write, ip);
				return 1;
			}
			if(shadow == s_end && last_byte > c)	{
				kasan_report(MSGID_INV_ACCESS, start + (shadow - s_start), (end - start), write, ip);
				return 1;
			}
		}
		shadow++;
	}
	return OK;
}
/*
static void _kasan_unpoison_block(ptr_t addr)	{
	char* sh = (char*)ADDR_TO_SHADOW_FIRST(addr);
	*sh = 0x00;
}*/
static void _kasan_ensure_mapped_in(ptr_t _s_start, ptr_t _s_end)	{
	ptr_t s_start = GET_ALIGNED_DOWN_POW2(_s_start, PAGE_SIZE),
		s_end = GET_ALIGNED_UP_POW2(_s_end, PAGE_SIZE),
		i;
	for(i = s_start; i < s_end; i += PAGE_SIZE)	{
#ifndef UMODE
		if(!mmu_page_mapped(i))	{
			mmu_map_page(i, PROT_RW);
#else
		//if((n = seek_read(kasan.memfd, NULL, PAGE_SIZE, i)) != PAGE_SIZE)	{
		if(is_mapped(i) == 0)	{
			// TODO:
			// - Page is not written correctly when page fault on memset
			uint64_t* a = (uint64_t*)i;
			WRITE_ONCE(a[0], 0xffffffffffffffff);
#endif
			memset((void*)i, 0xff, PAGE_SIZE);
		}
	}
}
static void _kasan_unpoison_buf(ptr_t start, ptr_t end)	{
	if(ADDR_EL_WRONG(start) || ADDR_EL_WRONG(end))	{
		bugprintf("KASAN: Tried to unpoison wrong mode addr\n");
		return;
	}
	// Get aligned down shadow addresses
	ptr_t s_start = ADDR_TO_SHADOW_FIRST(start);
	ptr_t s_end = ADDR_TO_SHADOW_FIRST(end);
	char* _s ;

	ptr_t mapend = s_end;
	mapend += ((end % SHADOW_BYTES_PER) != 0) ? 1 : 0;


	// Must ensure addresses are mapped in
	_kasan_ensure_mapped_in(s_start, mapend);

	// For the start address we always align that on a SHADOW_BYTES_PER
	// boundary, but the end address allows us to only allow the first n bites
	if((end % SHADOW_BYTES_PER) != 0)	{
		_s = (char*)(s_end);
		*_s = ADDR_OFFSET_IN_BYTE(end);
	}

	memset((void*)s_start, 0x00, (s_end - s_start));
}

static void _kasan_poison_buf(ptr_t start, ptr_t end, char c)	{
	if(ADDR_EL_WRONG(start) || ADDR_EL_WRONG(end))	{
		bugprintf("KASAN: Tried to poison wrong mode addr\n");
		return;
	}
	// Get aligned down shadow addresses
	ptr_t s_start = ADDR_TO_SHADOW_FIRST(start);
	ptr_t s_end = ADDR_TO_SHADOW_FIRST(end);
	char* _s ;
	int last_byte = (end % SHADOW_BYTES_PER);


	// TODO: Check if mapped in
#ifndef UMODE
	if(!mmu_page_mapped(s_start) || !mmu_page_mapped(s_end))	{
//#else
//	if((n = seek_read(kasan.memfd, NULL, s_end - s_start, s_start)) != (s_end - s_start))	{
//#endif
		if(kasan.initialized)	{
			bugprintf("KASAN: Tried to poison memory not mapped in\n");
		}
		return;
//#ifndef UMODE
	}
#endif

	// TODO: Double check this
	
	if((end % SHADOW_BYTES_PER) != 0)	{
		_s = (char*)(s_end + 1);
		if(*_s == last_byte)	{
			// If we are poisoning the first X bytes which were available
			// we can safely poison the whole kasan-byte
			*_s = c;
		}
		else	{
			// TODO: Not sure if this ever happens in practice, but
			// will in worst case scenario lead to false negatives
			*_s = 0x00;
		}
	}
	memset((void*)s_start, c, (s_end - s_start));
}

#ifndef UMODE
static bool _kasan_in_linear(ptr_t a_addr, int a_length)	{
	ptr_t addr = kasan.linear_start, length = kasan.linear_length;

	return (a_addr >= addr && a_addr < (addr + length) &&
		(a_addr + a_length) >= addr && (a_addr + a_length) < (addr + length));
	return false;
}
#endif

void kasan_mark_valid(ptr_t addr, ptr_t len)	{
	mutex_acquire(&kasan.lock);
	_kasan_unpoison_buf(addr, (addr + len));
	mutex_release(&kasan.lock);
}
void kasan_mark_freed(ptr_t addr, ptr_t len)	{
	//mutex_acquire(&kasan.lock);
	_kasan_poison_buf(addr, (addr + len), KASAN_MAGIC_FREED);
	//mutex_release(&kasan.lock);
}
void kasan_mark_poison(ptr_t addr, ptr_t len, char magic)	{
	_kasan_poison_buf(addr, (addr + len), magic);
}

void kasan_init(void)	{
	ptr_t start, stop;
	//mutex_clear(&kasan.lock);
	kasan.lock = 0;
#ifndef UMODE
	if(get_memory_dtb(&kasan.linear_start, &kasan.linear_length))	PANIC("Cannot get physical memory details from dtb\n");
	kasan.linear_start += cpu_linear_offset();

	start = (ptr_t)(&(KERNEL_TEXT_START));
	stop = (ptr_t)(&(KERNEL_TEXT_STOP));
	_kasan_unpoison_buf(start, stop);

	start = (ptr_t)(&(KERNEL_DATA_START));
	stop = (ptr_t)(&(KERNEL_DATA_STOP));
	_kasan_unpoison_buf(start, stop);

	start = (ptr_t)(&(KERNEL_BSS_START));
	stop = (ptr_t)(&(KERNEL_BSS_STOP));
	_kasan_unpoison_buf(start, stop);

	start = (ptr_t)(&(KERNEL_RODATA_START));
	stop = (ptr_t)(&(KERNEL_RODATA_STOP));
	_kasan_unpoison_buf(start, stop);
#else
	ptr_t size = (1UL << (CONFIG_AARCH64_VA_BITS)) / SHADOW_BYTES_PER;

	// We use _mmap here so that we don't include this in kasan mmap
	KASAN_START_ADDR = (ptr_t)_mmap(NULL, size, PROT_RW, MAP_LAZY_ALLOC, -1);
	if(PTR_IS_ERR(KASAN_START_ADDR))	{
		bugprintf("KASAN: Unable to mmap memory region for kasan\n");
		return;
	}

// 	kasan.memfd = open("/dev/umem", OPEN_FLAG_RW);
// 	if(kasan.memfd < 0)	{
// 		bugprintf("KASAN: Unable to open driver for controlling memory access\n");
// 		return;
// 	}

	start = (ptr_t)(&(UMODE_IMAGE_START));
	stop = (ptr_t)(&(UMODE_IMAGE_STOP));
	_kasan_unpoison_buf(start, stop);

#endif

#define AMAX_PAGES (32)
	kasan.alloced.curr = 0;
	kasan.alloced.amax = (AMAX_PAGES * PAGE_SIZE) / sizeof(struct k_alloced);
#ifndef UMODE
	kasan.alloced.max = 0;
	kasan.alloced.arr = (struct k_alloced*)
		vmmap_alloc_pages(AMAX_PAGES, PROT_RW, VMMAP_FLAG_LAZY_ALLOC);
#else
	kasan.alloced.max = kasan.alloced.amax;
	//kasan.alloced.arr = (struct k_alloced*)_mmap(NULL, AMAX_PAGES * PAGE_SIZE, PROT_RW, MAP_LAZY_ALLOC, -1);
	kasan.alloced.arr = (struct k_alloced*)_mmap(NULL, AMAX_PAGES * PAGE_SIZE, PROT_RW, MAP_LAZY_ALLOC, -1);
#endif
	ASSERT(PTR_IS_VALID(kasan.alloced.arr));

#if KASAN_FREE_QUARANTINE
	// Allocate twice the size of MAX to avoid having to adjust the buffer all the time
	kasan.quarantine = xifo_alloc(KASAN_QUARANTINE_MAX * 2, 0);
	ASSERT(PTR_IS_VALID(kasan.quarantine));
	_kasan_unpoison_buf((ptr_t)kasan.quarantine, (ptr_t)(kasan.quarantine) + sizeof(struct XIFO));
	_kasan_unpoison_buf((ptr_t)kasan.quarantine->items, (ptr_t)(kasan.quarantine->items) + sizeof(void*) * (KASAN_QUARANTINE_MAX * 2));
#endif

	kasan.initialized = true;
	kasan.panic_on_err = true;
}
void kasan_check_access(void* addr, int size, bool write, void* ip)	{
	if(!(kasan.initialized))	return;
#ifndef UMODE
	if(_kasan_in_linear((ptr_t)addr, size))	return;
#endif

	if(check_addr_shadow((ptr_t)addr, (ptr_t)(addr) + size, write, (ptr_t)ip))	{
		// int kasan_report(const char* msg, ptr_t addr, bool write, ptr_t ip)	{
		//kasan_report("kasan check", );
		//PANIC("KASAN invalid memory access\n");
	}
}
#define __alias(symbol)	__attribute__((alias(#symbol)))

#define ASAN_LOAD_STORE(size) \
void __asan_load##size(void* addr) {\
	kasan_check_access(addr, size, false, __builtin_return_address(0));\
}\
void __asan_load##size##_noabort(void*) __alias(__asan_load##size); \
void __asan_store##size(void* addr) {\
	kasan_check_access(addr, size, true, __builtin_return_address(0));\
}\
void __asan_store##size##_noabort(void*) __alias(__asan_store##size);


ASAN_LOAD_STORE(1)
ASAN_LOAD_STORE(2)
ASAN_LOAD_STORE(4)
ASAN_LOAD_STORE(8)
ASAN_LOAD_STORE(16)

void __asan_storeN(void* addr, long int size)	{
	kasan_check_access(addr, size, true, __builtin_return_address(0));
}
void __asan_storeN_noabort(void*,long int) __alias(__asan_storeN);

void __asan_loadN(void* addr, long int size)	{
	kasan_check_access(addr, size, false, __builtin_return_address(0));
}
void __asan_loadN_noabort(void*,long int) __alias(__asan_loadN);

void __asan_handle_no_return(void)	{
	// This is called before exit()
}
static void _kasan_map_next_alloc(void)	{
	ptr_t addr = (ptr_t)(kasan.alloced.arr);
	if(kasan.alloced.max == kasan.alloced.amax)	{
		bugprintf("KASAN: Reached max target array used to hold allocated objects");

		// If we've exhausted the array, we simply throw away the first page.
		// The result is that we will not be able to mark values as freed in
		// shadow memory. This could lead to false positives.
		// 
		memmove((void*)addr, (const void*)(addr + PAGE_SIZE), PAGE_SIZE);
		kasan.alloced.curr -= (PAGE_SIZE / sizeof(struct k_alloced));
	}
#ifndef UMODE
	/* We only need to maunally map in pages in kernel mode */
	addr += (kasan.alloced.curr * sizeof(struct k_alloced));
	ASSERT(addr == GET_ALIGNED_DOWN_POW2(addr, PAGE_SIZE));
	vmmap_map_page(addr);
	kasan.alloced.max += (PAGE_SIZE / sizeof(struct k_alloced));
#endif
}

/**
* This algorithm for searching might seem slow, but most free's will be on
* recently allocated objects. In addition, we have no penalty on allocations.
*
* Timing compared to binary search has not been tested.
*/
int _kasan_find_addr(struct k_alloced* arr, int last, void* addr)	{
	while(last >= 0)	{
		if(arr[last].addr == (ptr_t)addr)	return last;
		last--;
	}
	return -1;
}

void kasan_mmap(void* addr, size_t size)	{
	kasan_mark_valid((ptr_t)addr, size);
}
void kasan_munmap(void* addr)	{
	// TODO:
	// - Need to manually track size
	bugprintf("TODO: Unmapping of region not implemented, could lead to kasan false negaitive\n");
}

void kasan_malloc(void* addr, size_t size)	{
	int ins;
	struct k_alloced* arr;

	int rz_after = KASAN_REDZONE_AFTER + (SHADOW_BYTES_PER - (size % SHADOW_BYTES_PER));
	ptr_t rz1 = (ptr_t)(addr);
	ptr_t rz2 = (ptr_t)(addr + size + KASAN_REDZONE_BEFORE);
	ALIGN_UP_POW2(rz2, SHADOW_BYTES_PER);

	kasan_mark_poison(rz1, KASAN_REDZONE_BEFORE, KASAN_MAGIC_RZ_BEFOR);
	kasan_mark_valid((ptr_t)addr + KASAN_REDZONE_BEFORE, size);
	kasan_mark_poison(rz2, rz_after, KASAN_MAGIC_RZ_AFTER);

	mutex_acquire(&kasan.lock);
	if(!kasan.initialized)	goto err1;
	if(kasan.alloced.curr >= kasan.alloced.max)	{
		_kasan_map_next_alloc();
	}
	arr = kasan.alloced.arr;
	ins = kasan.alloced.curr;
	arr[ins].addr = (ptr_t)addr + KASAN_REDZONE_BEFORE;
	arr[ins].size = size;
	arr[ins].rz_before = KASAN_REDZONE_BEFORE;
	arr[ins].rz_after = rz_after;
#if defined(KASAN_STORE_ALLOC_LOC)
	arr[ins].caller = (ptr_t)__builtin_return_address(0);
#endif
	kasan.alloced.curr++;
err1:
	mutex_release(&kasan.lock);
}
void kasan_free(void* addr)	{
	ptr_t pc = (ptr_t)__builtin_return_address(0);
	void* ret;
	size_t sz;
	int idx;
	uint16_t rz_before;
	struct k_alloced* arr;
	arr = kasan.alloced.arr;
//	bool remove = false;

	mutex_acquire(&kasan.lock);
	idx = _kasan_find_addr(arr, kasan.alloced.curr - 1, addr);
	if(idx < 0 || ((ret = (void*)arr[idx].addr) != addr))	{
		kasan_report(MSGID_INV_FREE, (ptr_t)addr, 0, false, pc);
		goto err1;
	}

	sz = arr[idx].size;
	rz_before = arr[idx].rz_before;

	// We maintain the redzone around buffer, if we access a OOB index in free'd
	// area, it will only be reported as OOB, but not UAF
	kasan_mark_freed((ptr_t)addr, sz);

#if KASAN_FREE_QUARANTINE
	if(xifo_count(kasan.quarantine) == KASAN_QUARANTINE_MAX)	{
		// If fifo is full, we must:
		// - pop value in fifo
		// - free address
		void* f = xifo_pop_front(kasan.quarantine);
		free(f);
	}
	xifo_push_back(kasan.quarantine, addr - rz_before);
#else
	free(addr - rz_before);
#endif

	// We always remove from our own list, even if we haven't freed it yet
	kasan.alloced.curr--;
	if(idx < kasan.alloced.curr)	{
		int n_items = (kasan.alloced.curr - idx);
		memmove(&arr[idx], &arr[idx+1], n_items * sizeof(struct k_alloced));
	}
err1:
	mutex_release(&kasan.lock);
}

int kasan_alloc_size(void* addr)	{
	int idx;
	struct k_alloced* arr;
	int res = 0;

	mutex_acquire(&kasan.lock);
	arr = kasan.alloced.arr;
	idx = _kasan_find_addr(arr, kasan.alloced.curr - 1, addr);
	if(idx < 0)	{
		goto err1;
	}
	if(arr[idx].addr != (ptr_t)addr)	{
		// TODO: Should print an error here
		goto err1;
	}
	res = arr[idx].size;
err1:
	mutex_release(&kasan.lock);
	return res;
}

void kasan_never_freed(void* addr)	{
	int idx;
	struct k_alloced* arr;
	void* ret;
	if(addr == NULL)	return;

	mutex_acquire(&kasan.lock);
	arr = kasan.alloced.arr;
	idx = _kasan_find_addr(arr, kasan.alloced.curr - 1, addr);
	if(idx < 0)	{
		goto err1;
	}
	ret = (void*)arr[idx].addr;
	if(ret != addr)	{
		// TODO: Should print an error here
		bugprintf("KASAN: Asked to non-free on %p but value was not found\n", addr);
		goto err1;
	}

	kasan.alloced.curr--;
	if(idx < kasan.alloced.curr)	{
		int n_items = (kasan.alloced.curr - idx);
		memmove(&arr[idx], &arr[idx+1], n_items * sizeof(struct k_alloced));
	}
err1:
	mutex_release(&kasan.lock);
}

void kasan_print_allocated(void)	{
#if defined(KASAN_STORE_ALLOC_LOC)
	long total = 0;
	mutex_acquire(&kasan.lock);
	if(kasan.alloced.curr > 0)	{
		bugprintf("\nMEMLEAK: Memory locations not free'd\n");
		int i;
		struct k_alloced* k;
		for(i = 0; i < kasan.alloced.curr; i++)	{
			k = &kasan.alloced.arr[i];
			bugprintf("%i object @ %lx (0x%lx) PC: 0x%lx\n", i, k->addr, k->size, k->caller);
			total += k->size;
		}
	}
	mutex_release(&kasan.lock);
	bugprintf("Total: 0x%lx\n", total);
#endif
}

