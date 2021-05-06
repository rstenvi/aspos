#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
//#include <dirent.h>
#include "ustar.h"
#include "vfs.h"

#define OCTAL_END_CHAR NULL

static struct tar_meta* ustar_meta = NULL;

/*
* TODO: Clean up function, we do normalize path now, so should be a bit simpler
*  - Also, code is written twice
*/
struct tar_entry* _search_entry(struct tar_entry* entry, char** _name, bool exact)	{
	struct tar_entry* n = entry, *n2;
	int len, count, i;
	char* fname = (char*)*_name, *div;
	bool found;
	while((div = strstr(fname, "/")) != NULL)	{
		len = div - fname;
		if(strlen(div) == 1 && !exact)	goto end;
		if(len > 1)	{
			count = xifo_count(n->childs);
			found = false;
			for(i = 0; i < count; i++)	{
				n2 = (struct tar_entry*)xifo_item(n->childs, i);
				if(strlen(n2->name) == len && strncmp(fname, n2->name, len) == 0)	{
					found = true;
					break;
				}
			}
			if(!found)	{
				printf("Unable to find entry for '%s' (%i)\n", fname, len);
				return NULL;
			}
			n = n2;
		}
		fname = div + 1;
	}
	if(exact)	{
		len = strlen(fname);
		count = xifo_count(n->childs);
		found = false;
		for(i = 0; i < count; i++)	{
			n2 = (struct tar_entry*)xifo_item(n->childs, i);
			if(strlen(n2->name) == len && strncmp(fname, n2->name, len) == 0)	{
				found = true;
				break;
			}
		}
		if(!found)	{
			printf("Unable to find entry for '%s' (%i)\n", fname, len);
			return NULL;
		}
		n = n2;
		/*
		if(len > 0)	{
			n2 = n->next;
			while(n2 != NULL)	{
				if(strlen(n2->name) == len && strncmp(fname, n2->name, len) == 0)	break;
				n2 = n2->next;
			}
			if(n2 == NULL)	{
				printf("Unable to find entry for '%s' (%i)\n", fname, len);
				return NULL;
			}
			n = n2;
		}
		*/
	}
end:
	*_name = fname;
	return n;

}

struct tar_entry* walk_path(struct tar_entry* entry, const char* _name)	{
	char** n = (char**)&_name;
	return _search_entry(entry, n, true);
}

static int convert_tar_entry(struct raw_tar_entry* rawentry, struct tar_entry* entry)	{
	int nlen;
	nlen = strlen(rawentry->filename);
	entry->name = (char*)kmalloc( nlen + 1 );
	strcpy(entry->name, rawentry->filename);

	entry->mode = strtol(rawentry->mode, OCTAL_END_CHAR, 8);
	entry->uid = strtol(rawentry->uid, OCTAL_END_CHAR, 8);
	entry->gid = strtol(rawentry->gid, OCTAL_END_CHAR, 8);

	entry->size = strtoll(rawentry->size, OCTAL_END_CHAR, 8);
	entry->mtime = strtoll(rawentry->mtime, OCTAL_END_CHAR, 8);
	entry->type = (rawentry->typeflag[0] - '0');
	return 0;
}
static struct tar_entry* alloc_tar_entry(struct raw_tar_entry* entry)	{
	TZALLOC(ret, struct tar_entry);
	if(PTR_IS_ERR(ret))	return ret;

	ret->childs = xifo_alloc(5, 2);
	convert_tar_entry(entry, ret);
	return ret;
}
static int add_tar_entry(struct tar_meta* meta, struct raw_tar_entry* entry, size_t seek)	{
	char* div, *fname = entry->filename;
	char** _fname = &fname;
	struct tar_entry* n = meta->root, * n2;
	int len, i;

	// This can happen if we read past normal buffer into padding
	if(strlen(fname) == 0)	return -1;

	normalize_path(fname);
	if(meta->root == NULL)	{
		n = alloc_tar_entry(entry);
		n->start_meta = seek;
		meta->root = n;
		return 0;
	}
	n2 = _search_entry(n, _fname, false);
	fname = *_fname;

	// Copy relative path over to entry
	// we can't use memcpy/strcpy here because the addresses overlap
	for(i = 0; i < strlen(fname)+1; i++)	{
		entry->filename[i] = fname[i];
	}
	n = alloc_tar_entry(entry);
	n->start_meta = seek;

	xifo_push_back(n2->childs, (void*)n);
//	n->next = n2->next;
//	n2->next = n;

	return 0;
}

static int parse_all(struct tar_meta* m)	{
	int fd = m->blockfd, res;

	uint64_t seek = 0, esz;
	struct raw_tar_entry raw;

	while((seek + sizeof(raw)) < m->size || m->size == 0)	{
		lseek(fd, seek, SEEK_SET);
		res = read(fd, &raw, sizeof(raw));
		if(res != sizeof(raw))	{
			perror("read");
			return -1;
		}
		res = add_tar_entry(m, &raw, seek);

		// There is usually padding at the end, if we read an empty entry
		// we should just stop
		if(res != 0)	break;

		esz = strtoll(raw.size, OCTAL_END_CHAR, 8);
		if(esz != 0)	{
			ALIGN_UP_POW2(esz, TAR_ENTRY_SIZE);
		}
		esz += TAR_ENTRY_SIZE;
		if((esz % m->blksize) != 0)	{
			printf("Unexpected read not at the start");
			exit(1);
		}
		seek += (esz / m->blksize);
	}
	return 0;
}

struct tar_meta* find_meta(char** _name)	{
	struct tar_meta* n = ustar_meta, *bmatch;
	char* name = *_name;
	int len = strlen(name), minsz, bmatchlen = -1;
	while(n != NULL)	{
		minsz = MIN(strlen(n->mntpoint), len);
		if(minsz > bmatchlen && strncmp(n->mntpoint, name, minsz) == 0)	{
			bmatch = n;
			bmatchlen = minsz;
		}
		n = n->next;
	}
	if(bmatch)	{
		*_name += strlen(bmatch->mntpoint);
	}
	return bmatch;
}

static int ustar_open(struct vfsopen* o, const char* n, int flags, int mode)	{
	struct tar_file_open* f;
	struct tar_entry* e;
	struct tar_meta* meta;
	int res = OK, len = strlen(n);
	char** _n, *relname;
	char* path = kmalloc(len + 1), *_path;
	_path = path;
	strcpy(path, n);
	normalize_path(path);
	_n = &path;
	meta = find_meta(_n);
	if(!meta)	{
		res = -USER_FAULT;
		goto err1;
	}
	
	relname = *_n;
	e = _search_entry(meta->root, _n, true);
	if(PTR_IS_ERR(e))	{
		res = -USER_FAULT;
		goto err1;
	}
#if defined(linux)
	printf("open: '%s' -> '%s'\n", n, e->name);
#else
	f = (struct tar_file_open*)kmalloc( sizeof(struct tar_file_open) );
	if(PTR_IS_ERR(f))	{
		res = -MEMALLOC;
		goto err1;
	}
	f->entry = e;
	f->meta = meta;
	SET_VFS_DATA(o, f);
	res = o->fd;
#endif

err1:
	kfree(_path);
	return res;
}

static int _ustar_read_file(struct tar_file_open* f, void* buf, size_t max)	{
	int seek, res, r;
	seek = f->entry->start_meta;
	seek += (TAR_ENTRY_SIZE / f->meta->blksize);
	r = MIN(f->entry->size, max);
	res = seek_read(f->meta->blockfd, buf, r, seek);
	return res;
}

static int _ustar_read_dir(struct tar_file_open* f, void* buf, size_t max)	{
	struct dir_entry dir = {0};
	int seek, res, r, i;
	struct tar_entry* e = f->entry, * n;
	void* nbuf = buf;
	int count;
	count = xifo_count(e->childs);
	for(i = 0; i < count; i++)	{
		n = (struct tar_entry*)xifo_item(e->childs, i);
		dir.type = e->type;
		dir.filesz = e->size;
		dir.length = DIR_ENTRY_PRESIZE + strlen(n->name) + 1;
		if(dir.length > max)	{
			memcpy(nbuf, &dir, DIR_ENTRY_PRESIZE);
			strcpy(nbuf + DIR_ENTRY_PRESIZE, n->name);
			max -= dir.length;
			nbuf += dir.length;
		}
		else	{
			// In this instance, the user must allocate a larger buffer and try
			// again
			return -SPACE_FULL;
		}
	}
	return (nbuf - buf);
}

static int ustar_read(struct vfsopen* o, void* buf, size_t max)	{
	size_t seek, r, res;
	GET_VFS_DATA(o, struct tar_file_open, f);
	if(PTR_IS_ERR(f))	return -1;

	switch(f->entry->type)	{
	case TYPE_REG:
		res = _ustar_read_file(f, buf, max);
		break;
	case TYPE_DIR:
		res = _ustar_read_dir(f, buf, max);
		break;
	default:
		printf("Don't know how to read type %i\n", f->entry->type);
		res = -1;
		break;
	}
	return res;
}
static int ustar_write(struct vfsopen* o, const void* buf, size_t max)	{
	// TODO: Must check if there is enough space
	return -1;
}
static int ustar_close(struct vfsopen* o)	{
	GET_VFS_DATA(o, struct tar_file_open, f);
	if(!PTR_IS_ERR(f))	{
		kfree(f);
	}
	return 0;
}

static struct fs_struct ustar_fs = {
	.name = "ustar",
	.open = ustar_open,
	.read = ustar_read,
	.write = ustar_write,
	.close = ustar_close,
	.perm = ACL_PERM(ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE),
};


/*
* TODO:
* - fstat device to figure out block sizes etc.
* - Open and configure cuse
* 	- Configure callback
* - Parse all metadata to 
*/
struct tar_meta* mount_ustar(int fd)	{
	int res = OK;
	struct stat statbuf;
	TZALLOC(meta, struct tar_meta);
	if(PTR_IS_ERR(meta))	{
		res = PTR_TO_ERRNO(meta);
		goto err0;
	}

	meta->blockfd = fd;

	res = fstat(fd, &statbuf);
	if(res)	{
		printf("Unable to stat info\n");
		goto err1;
	}
	meta->size = statbuf.st_size;
	meta->blksize = statbuf.st_blksize;

	res = parse_all(meta);
	if(res)	{
		goto err1;
	}
	return meta;
err1:
	kfree(meta);
err0:
	return ERR_ADDR_PTR((ptr_t)res);
}


#if defined(linux)
int main(int argc, char* argv[])	{
	int fd, cfd;
	struct tar_entry* e;
	struct tar_meta* meta;
	fd = open("../../../../rootfs.tar", O_RDWR);
	if(fd < 0)	return -1;

	meta = mount_ustar(fd);
	if(PTR_IS_ERR(meta))	{
		printf("Uname to mount ustar: %i", PTR_TO_ERRNO(meta));
		exit(1);
	}

	meta->mntpoint = "/";

	if(ustar_meta)	{
		// Insert at beginning of list
		meta->next = ustar_meta->next;
		ustar_meta->next = meta;
	}
	else	{
		ustar_meta = meta;
	}
	e = walk_path(meta->root, "/root/");
	printf("ret: %s\n", e->name);

	e = walk_path(meta->root, "/");
	printf("ret: %s\n", e->name);

	e = walk_path(meta->root, "/random.bin");
	printf("ret: %s\n", e->name);

	e = walk_path(meta->root, "/root");
	printf("ret: %s\n", e->name);

	e = walk_path(meta->root, "/root/test.txt");
	printf("ret: %s\n", e->name);

	e = walk_path(meta->root, "/garbage");
	printf("ret: %p\n", e);
	cfd = ustar_open(NULL, "/root/test.txt", 0, 0);
	cfd = ustar_open(NULL, "/", 0, 0);
	cfd = ustar_open(NULL, "/root/", 0, 0);
	cfd = ustar_open(NULL, "/root", 0, 0);
	cfd = ustar_open(NULL, "/random.bin", 0, 0);
	cfd = ustar_open(NULL, "/missing", 0, 0);
	return 0;
}
#else
int init_ustart(const char* mnt, int blockfd)	{
	int fd;
	struct tar_meta* meta;
	fd = cuse_mount(&ustar_fs, mnt, false);
	if(fd < 0)	return fd;

	meta = mount_ustar(blockfd);

	meta->mntpoint = (char*)mnt;
	meta->cusefd = fd;
	if(ustar_meta)	{
		// Insert at beginning of list
		meta->next = ustar_meta->next;
		ustar_meta->next = meta;
	}
	else	{
		ustar_meta = meta;
	}
	return 0;
}
#endif
