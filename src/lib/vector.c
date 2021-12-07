#include "lib.h"


struct Vec* vec_init(size_t items)	{
	TZALLOC(ret, struct Vec);
	ASSERT(ret);

	ret->items = (struct vec_item*)kmalloc( sizeof(struct vec_item) * items);
	ret->citems = 0;
	ret->aitems = items;
	mutex_clear(&ret->lock);

	return ret;
}

static int _vec_ensure_space(struct Vec* vec)	{
	if(vec->citems == vec->aitems - 1)	{
		vec->aitems += 8;
		vec->items = (struct vec_item*)krealloc(vec->items, sizeof(struct vec_item) * vec->aitems);
		if(PTR_IS_ERR(vec->items))	return -MEMALLOC;
	}
	return OK;
}

/* TODO: Convert to binary search */
static int _vec_search(struct Vec* vec, long key)	{
	int idx = 0;
	while(idx < vec->citems && key > vec->items[idx].key)	idx++;
	return idx;
}
static int _vec_insert_idx(struct Vec* vec, int idx, struct vec_item* item)	{
	int bytes = sizeof(struct vec_item) * (vec->citems - idx);
	if(bytes > 0)	{
		memmove(&(vec->items[idx+1]), &(vec->items[idx]), bytes);
	}
	memcpy(&(vec->items[idx]), item, sizeof(struct vec_item));
	vec->citems++;
	return OK;
}
static int _vec_remove_idx(struct Vec* vec, int idx)	{
	vec->citems--;
	if(idx < vec->citems)	{
		int bytes = sizeof(struct vec_item) * (vec->citems - idx);
		memmove(&(vec->items[idx]), &(vec->items[idx+1]), bytes);
	}
	return OK;
}

void* _vec_find(struct Vec* vec, long key, bool remove)	{
	//struct vec_item* item = NULL;
	int idx;
	void* ret = NULL;

	mutex_acquire(&vec->lock);
	idx = _vec_search(vec, key);
	if(idx >= 0 && idx < vec->citems)	{
		if(vec->items[idx].key == key)	{
			ret = vec->items[idx].item;
			if(remove)	_vec_remove_idx(vec, idx);
		}
	}
	mutex_release(&vec->lock);
	return ret;
}
int vec_insert(struct Vec* vec, void* ins, long key)	{
	int idx;
	struct vec_item item = {ins, key};

	mutex_acquire(&vec->lock);

	_vec_ensure_space(vec);

	idx = _vec_search(vec, key);
	_vec_insert_idx(vec, idx, &item);

	mutex_release(&vec->lock);

	return OK;
}
void* vec_find(struct Vec* vec, long key)	{
	return _vec_find(vec, key, false);
}
void* vec_remove(struct Vec* vec, long key)	{
	return _vec_find(vec, key, true);
}
void* vec_remove_last(struct Vec* vec)	{
	void* ret = NULL;
	mutex_acquire(&vec->lock);
	if(vec->citems > 0)	{
		ret = vec->items[--(vec->citems)].item;
	}
	mutex_release(&vec->lock);
	return ret;
}
void* vec_index(struct Vec* vec, int idx)	{
	void* ret = NULL;
	if(idx < vec->citems)	{
		ret = vec->items[idx].item;
	}
	return ret;
}
int vec_modkey(struct Vec* vec, int idx, long key)	{
	if(idx < vec->citems)	{
		vec->items[idx].key = key;
	}
	return OK;
}
int vec_destroy(struct Vec* vec)	{
	kfree(vec->items);
	kfree(vec);
	return OK;
}

