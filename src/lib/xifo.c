#include "lib.h"

size_t xifo_count(struct XIFO* xifo) { return xifo->last - xifo->first; }


int xifo_init(struct XIFO* xifo, size_t max, size_t increment)	{
	// Allocate initial array
	void** i = (void**)malloc( sizeof(void*) * max );
	if(i == NULL)	return -(1);

	xifo->items = i;

	// Set max and increment
	xifo->max = max;
	xifo->increment = increment;

	// Array starts as empty
	xifo->first = xifo->last = 0;

	return OK;
}

struct XIFO* xifo_alloc(size_t max, size_t increment)	{
	struct XIFO* ret = NULL;
	ret = (struct XIFO*)malloc(sizeof(struct XIFO));
	if(ret == NULL)	return ERR_ADDR_PTR(-1);

	if(xifo_init(ret, max, increment) != OK)	{
		free(ret);
		return ERR_ADDR_PTR(-1);
	}

	return ret;
}

static void xifo_move_down(struct XIFO* xifo)	{
	size_t i;
	// Copy all the elements
	for(i = xifo->first; i <= xifo->last; i++)	{
		xifo->items[i - xifo->first] = xifo->items[i];
	}

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
	for(i = (int)xifo->last; i >= (int)xifo->first; i--)	{
		xifo->items[xifo->max - 1 + i - xifo->last] = xifo->items[i];
	}

	xifo->first += (xifo->max - xifo->last - 1);
	// Must reset the counters
	xifo->last = xifo->max - 1;
}

int xifo_push_back(struct XIFO* xifo, void* v)	{
	if(xifo->last < (xifo->max - 1) )	{
		xifo->items[xifo->last++] = v;
		return OK;
	}
	else if(xifo->first > 0)	{
		// We have space at the front, re-align and try again
		xifo_move_down(xifo);
		return xifo_push_back(xifo, v);
	}
	else	{
		// No more space left, allocate and try again
		void* re = realloc(xifo->items, sizeof(void*) * (xifo->max + xifo->increment) );
		if(re == NULL)	return -(1);

		// Change pointer and update values
		xifo->items = re;
		xifo->max += xifo->increment;

		return xifo_push_back(xifo, v);
	}
}

int xifo_push_front(struct XIFO* xifo, void* v)	{
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
		void* re = realloc(xifo->items, sizeof(void*) * (xifo->max + xifo->increment) );
		if(re == NULL)	return -(1);

		// Change pointer and update values
		xifo->items = re;
		xifo->max += xifo->increment;

		return xifo_push_front(xifo, v);
	}
}

void* xifo_pop_back(struct XIFO* xifo)	{
	if(xifo->last == xifo->first)	return NULL;
	void* ret = xifo->items[--(xifo->last)];
	return ret;
}

void* xifo_pop_front(struct XIFO* xifo)	{
	if(xifo->first == xifo->last)	return NULL;
	void* ret = xifo->items[xifo->first++];
	return ret;
}