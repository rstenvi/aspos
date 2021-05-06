#include "kernel.h"
#include "kasan.h"
#include "arch.h"

#define KASAN_START_ADDR (ARM64_VA_SHADOW_START)
//#define SHADOW_BYTES_PER (8)

#define _KASAN_ROUND_DOWN(val) (GET_ALIGNED_DOWN_POW2(val, SHADOW_BYTES_PER))
#define _KASAN_ROUND_UP(val)   (GET_ALIGNED_UP_POW2(val, SHADOW_BYTES_PER))
#define ADDR_TO_SHADOW_FIRST(val) (((_KASAN_ROUND_DOWN(val) - ARM64_VA_KERNEL_FIRST_ADDR) / SHADOW_BYTES_PER) + KASAN_START_ADDR)
#define ADDR_TO_SHADOW_LAST(val) (((_KASAN_ROUND_UP(val) - ARM64_VA_KERNEL_FIRST_ADDR) / SHADOW_BYTES_PER) + KASAN_START_ADDR)

#define ADDR_OFFSET_IN_BYTE(addr) (addr % SHADOW_BYTES_PER)
//#define ADDR_OFFSET_VALUE(addr) (SHADOW_BYTES_PER - ADDR_OFFSET_IN_BYTE(addr))

#define KASAN_MAGIC_INVALID  (0xff)
#define KASAN_MAGIC_FREED    (0xfe)
#define KASAN_MAGIC_RZ_BEFOR (0xfd)
#define KASAN_MAGIC_RZ_AFTER (0xfc)

extern uint64_t KERNEL_TEXT_START;
extern uint64_t KERNEL_TEXT_STOP;

extern uint64_t KERNEL_DATA_START;
extern uint64_t KERNEL_DATA_STOP;

extern uint64_t KERNEL_BSS_START;
extern uint64_t KERNEL_BSS_STOP;

extern uint64_t KERNEL_RODATA_START;
extern uint64_t KERNEL_RODATA_STOP;

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

struct k_alloc {
	int curr, max, amax;
	struct k_alloced* arr;
};

struct kasan {
	mutex_t lock;
	bool initialized;
	bool panic_on_err;
	ptr_t linear_start, linear_length;

	/**
	* Array of all allocated objects.
	*
	* Would normally use a linked list here, but insertion in that list migth
	* cause a malloc, which will cause an infinite loop. To avoid this mess, we
	* use an array and allocate pages as needed.
	*/
	struct k_alloc alloced;
#ifdef KASAN_FREE_QUARANTINE
	struct XIFO* quarantine;
#endif
};

static struct kasan kasan;

#define NUM_MSGIDS (7)
static const char* kasan_msgs[] = {
	"page not mapped in",
	"invalid access",
	"use-after-free",
	"redzone before buffer",
	"redzone after buffer",
	"free of invalid value",
	"user-mode addr",
};

static int kasan_report(int msgid, ptr_t addr, int size, bool write, ptr_t ip)	{
	kasan.initialized = false;
	char* msg = "undefined";
	char* access = (write) ? "write" : "read";

	if(msgid < NUM_MSGIDS)	msg = (char*)kasan_msgs[msgid];
	bugprintf("KASAN: %s\nAddress: %lx %s of %i bytes IP: %lx\n",
		msg, addr, access, size, ip);

	bugprintf("KASAN finished\n\n");

	//osdata.printk("KASAN: %s: Address: %lx IP: %lx\n", msg, addr, ip);
	if(kasan.panic_on_err)	{
		bugprintf("KASAN: panic_on_err is set, powering off\n");
		kern_poweroff(true);
	}
	kasan.initialized = true;
}

static int check_addr_shadow(ptr_t start, ptr_t end, bool write, ptr_t ip)	{
	if(ADDR_USER(start) || ADDR_USER(end))	{
		kasan_report(NUM_MSGIDS-1, start, (end - start), write, ip);
		return 1;
	}

	char* s_start = (char*)ADDR_TO_SHADOW_FIRST(start),
		*s_end = (char*)ADDR_TO_SHADOW_LAST(end);
	char* shadow = s_start;
	int first_byte = (start % 8);
	int last_byte = (end % 8);
	unsigned char c;
	
	while(shadow != s_end)	{
		if(!mmu_page_mapped((ptr_t)shadow))	{
			kasan_report(0, start + (shadow - s_start), (end - start), write, ip);
			return 1;
		}
		c = *shadow;
		if(c != 0x00)	{
			if(c > SHADOW_BYTES_PER)	{
				kasan_report(0x100 - (int)c, start + (shadow - s_start), (end - start), write, ip);
				return c;
			}
			if(shadow == s_start && first_byte > c)	{
				kasan_report(1, start + (shadow - s_start), (end - start), write, ip);
				return 1;
			}
			if(shadow == s_end && last_byte > c)	{
				kasan_report(1, start + (shadow - s_start), (end - start), write, ip);
				return 1;
			}
		}
		shadow++;
	}
	return OK;
}
/*
static bool _kasan_mapped(ptr_t addr)	{
}
static void _kasan_unpoison_byte(ptr_t addr)	{
	ptr_t start = ADDR_TO_SHADOW_FIRST(addr);
}
*/
static void _kasan_unpoison_block(ptr_t addr)	{
	char* sh = (char*)ADDR_TO_SHADOW_FIRST(addr);
	*sh = 0x00;
}
static void _kasan_ensure_mapped_in(ptr_t _s_start, ptr_t _s_end)	{
	ptr_t s_start = GET_ALIGNED_DOWN_POW2(_s_start, PAGE_SIZE),
		s_end = GET_ALIGNED_UP_POW2(_s_end, PAGE_SIZE),
		i;
	for(i = s_start; i < s_end; i += PAGE_SIZE)	{
		if(!mmu_page_mapped(i))	{
			mmu_map_page(i, PROT_RW);
			memset((void*)i, 0xff, PAGE_SIZE);
		}
	}
}
static void _kasan_unpoison_buf(ptr_t start, ptr_t end)	{
	if(ADDR_USER(start) || ADDR_USER(end))	{
		PANIC("Tried to unpoison user-mode addr\n");
	}
	ptr_t i,
		// Get aligned down shadow addresses
		s_start = ADDR_TO_SHADOW_FIRST(start),
		s_end = ADDR_TO_SHADOW_FIRST(end);
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
	if(ADDR_USER(start) || ADDR_USER(end))	{
		PANIC("Tried to poison user-mode addr\n");
		return;
	}
	ptr_t i,
		// Get aligned down shadow addresses
		s_start = ADDR_TO_SHADOW_FIRST(start),
		s_end = ADDR_TO_SHADOW_FIRST(end);
	char* _s ;
	int last_byte = (end % SHADOW_BYTES_PER);


	// TODO: Check if mapped in
	if(!mmu_page_mapped(s_start) || !mmu_page_mapped(s_end))	{
		// TODO: Print error
		return;
	}

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

static bool _kasan_in_linear(ptr_t a_addr, int a_length)	{
	ptr_t addr = kasan.linear_start, length = kasan.linear_length;
//	if(get_memory_dtb(&addr, &length))	PANIC("Cannot get physical memory details from dtb\n");

	return (a_addr >= addr && a_addr < (addr + length) &&
		(a_addr + a_length) >= addr && (a_addr + a_length) < (addr + length));
}
/*static void _kasan_unpoison_linear(void)	{
	ptr_t addr, length;
	if(get_memory_dtb(&addr, &length))	PANIC("Cannot get physical memory details from dtb\n");

	addr += ARM64_VA_LINEAR_START;
	_kasan_unpoison_buf(addr, addr + length);
}*/

void kasan_mark_valid(ptr_t addr, ptr_t len)	{
	//mutex_acquire(&kasan.lock);
	_kasan_unpoison_buf(addr, (addr + len));
	//mutex_release(&kasan.lock);
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
	//_kasan_unpoison_linear();
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

#define AMAX_PAGES (10)
	kasan.alloced.curr = 0;
	kasan.alloced.max = 0;
	kasan.alloced.amax = (AMAX_PAGES * PAGE_SIZE) / sizeof(struct k_alloced);
	kasan.alloced.arr = (struct k_alloced*)
		vmmap_alloc_pages(AMAX_PAGES, PROT_RW, VMMAP_FLAG_LAZY_ALLOC);

	ASSERT(PTR_IS_VALID(kasan.alloced.arr));
#ifdef KASAN_FREE_QUARANTINE
	// Allocate twice the size of MAX to avoid having to adjust the buffer all the time
	kasan.quarantine = xifo_alloc(KASAN_QUARANTINE_MAX * 2, 0);
	ASSERT(PTR_IS_VALID(kasan.quarantine));
#endif

	kasan.initialized = true;
	kasan.panic_on_err = true;
}
void kasan_check_access(void* addr, int size, bool write, void* ip)	{
	if(!(kasan.initialized))	return;
	if(_kasan_in_linear((ptr_t)addr, size))	return;

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

static void _kasan_map_next_alloc(void)	{
	ptr_t addr = (ptr_t)(kasan.alloced.arr);
	if(kasan.alloced.max == kasan.alloced.amax)	{
		logw("Reached max target array used to hold allocated objects");

		// If we've exhausted the array, we simply throw away the first page.
		// The result is that we will not be able to mark values as freed in
		// shadow memory. This could lead to false positives.
		// 
		memmove((void*)addr, (const void*)(addr + PAGE_SIZE), PAGE_SIZE);
		kasan.alloced.curr -= (PAGE_SIZE / sizeof(struct k_alloced));
	}
	addr += (kasan.alloced.curr * sizeof(struct k_alloced));
	ASSERT(addr == GET_ALIGNED_DOWN_POW2(addr, PAGE_SIZE));
	vmmap_map_page(addr);
	kasan.alloced.max += (PAGE_SIZE / sizeof(struct k_alloced));
}
/*
int _kasan_find_addr(struct k_alloced* arr, int last, void* addr)	{
	int first = 0;
	int mid = first + ((last - first) / 2);
	void* elem;
	while(first < last)	{
		mid = first + ((last - first) / 2);
		elem = arr[mid].addr;
		if(addr < elem)			first = mid+1;
		else if(addr > elem)	last = mid;
		else	break;
	}
	return mid;
}
*/

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
/*
#define Q_MAX_SIZE_BITS (63 - ARM64_VA_BITS)
#define Q_MAX_SIZE (1 << Q_MAX_SIZE_BITS)
#define Q_SIZE_MASK ((1 << Q_MAX_SIZE_BITS) << ARM64_VA_BITS)
#define Q_ADDR_MASK ((1 << ARM64_VA_BITS)-1)
#define Q_SIZE(size) ((size << ARM64_VA_BITS) & Q_SIZE_MASK)

static inline ptr_t _encode_free_addr(ptr_t addr, ptr_t size)	{
	if(size >= Q_MAX_SIZE)	return 0;
	ptr_t ret = (1 << 63) & addr;

	ret |= (addr & Q_ADDR_MASK);
	ret |= Q_SIZE(size);

	return ret;
}
*/
void kasan_free(void* addr)	{
	ptr_t pc = __builtin_return_address(0);
	void* ret;
	size_t sz;
	int idx;
	uint16_t rz_before;
	struct k_alloced* arr;
	arr = kasan.alloced.arr;
	bool remove = false;

	mutex_acquire(&kasan.lock);
	idx = _kasan_find_addr(arr, kasan.alloced.curr - 1, addr);
	if(idx < 0 || ((ret = (void*)arr[idx].addr) != addr))	{
		kasan_report(NUM_MSGIDS - 2, (ptr_t)addr, 0, false, pc);
		goto err1;
	}
	/*
	ret = (void*)arr[idx].addr;
	if(ret != addr)	{
		// TODO: Should print an error here
		goto err1;
	}*/

	sz = arr[idx].size;
	rz_before = arr[idx].rz_before;

	kasan_mark_freed((ptr_t)addr + rz_before, sz);

#ifdef KASAN_FREE_QUARANTINE
	if(xifo_count(kasan.quarantine) == KASAN_QUARANTINE_MAX)	{
		// If fifo is full, we must:
		// - pop value in fifo
		// - free address
		void* f = xifo_pop_front(kasan.quarantine);
//		idx = _kasan_find_addr(arr, kasan.alloced.max, f);
//		remove = (arr[idx] == f);
		free(f);
	}
	xifo_push_back(kasan.quarantine, addr - rz_before);
#else
//	remove = true;
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
	mutex_acquire(&kasan.lock);
	int i;
	struct k_alloced* k;
	for(i = 0; i < kasan.alloced.curr; i++)	{
		k = &kasan.alloced.arr[i];
		logi("%i object @ %lx (0x%x) PC: 0x%lx\n", i, k->addr, k->size, k->caller);
	}
	mutex_release(&kasan.lock);
#endif
}

/*
void kasan_hexdump(unsigned char* start, int bytes, unsigned char* marker)	{
	ALIGN_UP_POW2(bytes, 16);
	int i, j;
	char c = ' '
	unsigned char* curr;
	if(!mmu_page_mapped((ptr_t)start))	{
		bufprintf("Hexdump page not mapped in\n");
	}
	if((GET_ALIGNED_DOWN2(start+bytes, PAGE_SIZE) != start))	{
		if(!mmu_page_mapped(GET_ALIGNED_DOWN_POW2((ptr_t)start + bytes)))	{
			ptr_t end = GET_ALIGNED_UP_POW2(start, PAGE_SIZE);
			bytes = end - start;
			ALIGN_DOWN_POW2(bytes, 16);
		}
	}
			
	for(i = 0; i < bytes; i += 16)	{
		curr = &(start[i]);
		c = ' ';
		if(marker && marker == curr)	c = '>';

		bufprintf("%c %p: ", c, curr);
		for(j = i; j < i + 16; j += 4)	{
			bufprintf("%02x %02x %02x %02x ", start[j], start[j+1], start[j+2], start[j+3]);
		}
		bugprintf("\n");
		if(marker > curr && marker < curr + 16)	{
			for(j = 0; j <= (marker - curr); j++)	{
				bugprintf("   ");
			}
			bugprintf("^\n");
		}
	}
}
*/
