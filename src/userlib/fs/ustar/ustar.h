#ifndef __USTAR_H
#define __USTAR_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <tar.h>

#include "lib.h"


#define TYPE_REG  0
#define TYPE_LNK  1
#define TYPE_SYM  2
#define TYPE_CHR  3
#define TYPE_BLK  4
#define TYPE_DIR  5
#define TYPE_FIFO 6
#define TYPE_CONT 7

struct tar_entry {
	char* name;
	uint32_t mode, uid, gid;
	uint64_t size, mtime;
	uint8_t type;
	uint32_t start_meta;
	struct XIFO* childs;
//	struct tar_entry* next;
};

struct tar_meta {
	mutex_t lock;
	char* mntpoint;
	int blockfd, cusefd;
	size_t size;
	uint32_t blksize;
	struct tar_entry* root;
	struct tar_meta* next;
};

struct tar_file_open {
	struct tar_entry* entry;
	struct tar_meta* meta;
};

/**
* Simple header
*/
struct raw_tar_entry	{
	char filename[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];	// in bytes
	char mtime[12];
	char chksum[8];
	char typeflag[1];
//	char linkname[100];
};

struct raw_tar_entry2	{
	char null;
	char magic[TMAGLEN];
	char version[TVERSLEN];
	char owner[32];
	char group[32];
	char major[8];
	char minor[8];
//	char fname_prefix[155];
};

static inline void normalize_path(char* path)	{
	int n;
	n = strlen(path);
	if(path[n-1] == '/')	path[n-1] = 0x00;
}


#define TAR_ENTRY_SIZE (512)


#endif
