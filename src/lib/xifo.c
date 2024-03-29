#include "lib.h"

size_t xifo_count(struct XIFO* xifo) { return xifo->last - xifo->first; }


int xifo_init(struct XIFO* xifo, size_t max, size_t increment)	{
	// Allocate initial array
	void** i = (void**)kmalloc( sizeof(void*) * max );
	if(i == NULL)	return -(1);

	xifo->items = i;

	// Set max and increment
	xifo->max = max;
	xifo->increment = increment;

	// Array starts as empty
	xifo->first = xifo->last = 0;

	mutex_clear(&xifo->lock);
	return OK;
}

struct XIFO* xifo_alloc(size_t max, size_t increment)	{
	TMALLOC(ret, struct XIFO);
	if(PTR_IS_ERR(ret))	return ERR_ADDR_PTR(-MEMALLOC);

	if(xifo_init(ret, max, increment) != OK)	{
		kfree(ret);
		return ERR_ADDR_PTR(-1);
	}

	return ret;
}

void xifo_delete(struct XIFO* xifo)	{
	kfree(xifo->items);
	kfree(xifo);
}

static void xifo_move_down(struct XIFO* xifo)	{
	int items = (xifo->last - xifo->first);
	memmove(&(xifo->items[0]), &(xifo->items[xifo->first]), sizeof(void*) * items);
	/*
	// Copy all the elements
	for(i = xifo->first; i <= xifo->last; i++)	{
		xifo->items[i - xifo->first] = xifo->items[i];
	}
	*/

	// Must reset the counters
	xifo->last -= xifo->first;
	xifo->first = 0;
}

static void xifo_move_up(struct XIFO* xifo)	{
	int i;
	if(xifo->last == xifo->first)	{
		xifo->last = xifo->first = (xifo->max - 1);
		return;
	}
	// Copy all the elements
	for(i = (int)xifo->last - 1; i >= (int)xifo->first; i--)	{
		xifo->items[xifo->max - 1 + i - xifo->last] = xifo->items[i];
	}

	xifo->first += (xifo->max - xifo->last - 1);
	// Must reset the counters
	xifo->last = xifo->max - 1;
}

static int _xifo_push_back(struct XIFO* xifo, void* v)	{
	if(xifo->last < xifo->max)	{
		xifo->items[xifo->last++] = v;
		return OK;
	}
	else if(xifo->first > 0)	{
		// We have space at the front, re-align and try again
		xifo_move_down(xifo);
		return _xifo_push_back(xifo, v);
	}
	else	{
		// No more space left, allocate and try again
		void* re = NULL;
		if(xifo->increment > 0)	{
			re = krealloc(xifo->items, sizeof(void*) * (xifo->max + xifo->increment) );
			if(re == NULL)	return -(1);
		}
		else	return -1;

		// Change pointer and update values
		xifo->items = re;
		xifo->max += xifo->increment;

		return _xifo_push_back(xifo, v);
	}
}

int xifo_push_back(struct XIFO* xifo, void* v)	{
	int res;
	mutex_acquire(&xifo->lock);
	res = _xifo_push_back(xifo, v);
	mutex_release(&xifo->lock);
	return res;
}

static int _xifo_push_front(struct XIFO* xifo, void* v)	{
	if(xifo->first > 0)	{
		xifo->items[--(xifo->first)] = v;
		return OK;
	}
	else if(xifo->last < (xifo->max - 1) )	{
		// We have space at the end
		xifo_move_up(xifo);
		return xifo_push_front(xifo, v);
	}
	else	{
		// No more space left, allocate and try again
		void* re = NULL;
		if(xifo->increment > 0)	{
			re = krealloc(xifo->items, sizeof(void*) * (xifo->max + xifo->increment) );
			if(re == NULL)	return -(1);
		}
		else	return -1;

		// Change pointer and update values
		xifo->items = re;
		xifo->max += xifo->increment;

		return xifo_push_front(xifo, v);
	}
}
int xifo_push_front(struct XIFO* xifo, void* v)	{
	int res;
	mutex_acquire(&xifo->lock);
	res = _xifo_push_front(xifo, v);
	mutex_release(&xifo->lock);
	return res;
}

static void* _xifo_pop_back(struct XIFO* xifo, bool remove)	{
	void* ret = NULL;

	mutex_acquire(&xifo->lock);
	if(xifo->last == xifo->first)	goto done;

	ret = xifo->items[xifo->last - 1];
	if(remove)	xifo->last--;

done:
	mutex_release(&xifo->lock);
	return ret;
}

static void* _xifo_pop_front(struct XIFO* xifo, bool remove)	{
	void* ret = NULL;

	mutex_acquire(&xifo->lock);
	if(xifo->first == xifo->last)	goto done;
	ret = xifo->items[xifo->first];

	if(remove)	xifo->first++;

done:
	mutex_release(&xifo->lock);
	return ret;

}

void* xifo_pop_front(struct XIFO* xifo)	{
	ASSERT(PTR_IS_VALID(xifo));
	return _xifo_pop_front(xifo, true);
}
void* xifo_peep_front(struct XIFO* xifo)	{
	ASSERT(PTR_IS_VALID(xifo));
	return _xifo_pop_front(xifo, false);
}
void* xifo_pop_back(struct XIFO* xifo)	{
	ASSERT(PTR_IS_VALID(xifo));
	return _xifo_pop_back(xifo, true);
}
void* xifo_peep_back(struct XIFO* xifo)	{
	ASSERT(PTR_IS_VALID(xifo));
	return _xifo_pop_back(xifo, false);
}

void* xifo_item(struct XIFO* xifo, size_t idx)	{
	ASSERT(PTR_IS_VALID(xifo));
	void* ret = NULL;
	mutex_acquire(&xifo->lock);
	if(idx >= (xifo->last - xifo->first))	{
		goto err;
	}
	ret = xifo->items[xifo->first + idx];
err:
	mutex_release(&xifo->lock);
	return ret;
}

void* xifo_search(struct XIFO* xifo, void* val, bool (*search)(void*,void*)) {
	ASSERT(PTR_IS_VALID(xifo));
	void* ret = NULL;
	size_t i;
	mutex_acquire(&xifo->lock);
	for(i = xifo->first; i < xifo->last; i++)	{
		if(search(val, xifo->items[i]))	{
			ret = xifo->items[i];
			break;
		}
	}
	mutex_release(&xifo->lock);
	return ret;
}
