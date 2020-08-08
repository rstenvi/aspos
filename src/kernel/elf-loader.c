/**
* Load ELF executable file into memory.
*/

#include "kernel.h"


typedef uint32_t Elf32_Word;
typedef uint32_t Elf64_Word;
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Xword;
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

struct elf_hdr {
  uint8_t e_ident[16];         /* Magic number and other info */
  uint16_t e_type;              /* Object file type */
  uint16_t e_machine;           /* Architecture */
  uint32_t e_version;           /* Object file version */
  uint64_t e_entry;             /* Entry point virtual address */
  uint64_t e_phoff;             /* Program header table file offset */
  uint64_t e_shoff;             /* Section header table file offset */
  uint32_t e_flags;             /* Processor-specific flags */
  uint16_t e_ehsize;            /* ELF header size in bytes */
  uint16_t e_phentsize;         /* Program header table entry size */
  uint16_t e_phnum;             /* Program header table entry count */
  uint16_t e_shentsize;         /* Section header table entry size */
  uint16_t e_shnum;             /* Section header table entry count */
  uint16_t e_shstrndx;          /* Section header string table index */
};

struct elf_sh {
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
};


struct elf_ph	{
	uint32_t p_type;
	#if ( ARCH_CPUBITS == 64 )
		uint32_t p_flags;
	#endif
	uint64_t p_offset,
	p_vaddr,
	p_paddr,
	p_filsz,
	p_memsz;
	#if ( ARCH_CPUBITS == 32 )
		uint32_t p_flags;
	#endif
	uint64_t p_align;
};

// Flags: 1 = executable, 2 = writable, 4 = readable

#define P_FLAG_X 1
#define P_FLAG_W 2
#define P_FLAG_R 4

// p_type values
#define PT_NULL 0
#define PT_LOAD 1

#define ET_EXEC 2

enum MEMPROT _elf2memprot(int flag)	{
	flag &= (P_FLAG_X | P_FLAG_W | P_FLAG_R);

	if(flag == 7)		return PROT_RWX;
	else if(flag == 6)	return PROT_RW;
	else if(flag == 5)	return PROT_RX;
	else if(flag == 4)	return PROT_RO;
	else if(flag == 0)	return PROT_NONE;
	else	{
		logw("Unsupported prot value %i\n", flag);
		return PROT_NONE;
	}
}

bool is_elf(void* addr)	{
	struct elf_hdr* hdr = (struct elf_hdr*)addr;
	return hdr->e_ident[0] == 0x7f && 
		strncmp(&(hdr->e_ident[1]), "ELF", 3) == 0;
}

// On Qemu, ramdisk is loaded at 0x44000000
// which is 2MB below DTB
// Should look in DTB and /chosen" -> "linux,initrd-start
ptr_t elf_load(void* addr)	{
	int i;
	struct elf_sh* shdr;
	struct elf_ph* phdr;
	struct elf_hdr* hdr = (struct elf_hdr*)addr;
	ptr_t curr;

	if(! is_elf(addr))	return -1;

	if(hdr->e_type != ET_EXEC)	{
		logw("Not an executable file\n");
		return -1;
	}

	logi("ELF version %i | entry: 0x%x\n", hdr->e_version, hdr->e_entry);

//	shdr = (addr + hdr->e_shoff);
	phdr = (addr + hdr->e_phoff);
	for(i = 0; i < hdr->e_phnum; i++)	{
		logi("\tPH 0x%x 0x%x 0x%x\n",
			phdr->p_offset, phdr->p_vaddr, phdr->p_paddr);

		ptr_t rvaddr = phdr->p_vaddr;
		ALIGN_DOWN_POW2(rvaddr, PAGE_SIZE);

		ptr_t msize = phdr->p_memsz;
		msize += (phdr->p_vaddr - rvaddr);
		ALIGN_UP_POW2(msize, PAGE_SIZE);

		ptr_t fsize = phdr->p_filsz;
		fsize += (phdr->p_vaddr - rvaddr);
		ALIGN_UP_POW2(fsize, PAGE_SIZE);

		logi("\tmapping 0x%lx -> 0x%lx\n", rvaddr, rvaddr + msize);
		mmu_map_pages(rvaddr, msize / PAGE_SIZE, PROT_RWX);

		// Start with everything as 0
		memset((void*)rvaddr, 0x00, msize);
		copy_to_user((void*)(phdr->p_vaddr), (addr + phdr->p_offset), phdr->p_filsz);

		// TODO:
		// - change protection on pages

		phdr = (struct elf_ph*)( (ptr_t)phdr + hdr->e_phentsize);
	}
	return hdr->e_entry;
}
