/**
* Tick-list is a list where the items are ordered based on how many ticks they are
* from the top. This is used in cases where multiple threads sleep for a different
* amount of time, which is subdivided into ticks. Each tick, the first list item
* is decremented and returned of the tick reaches zero.
*
* Each item in the list stores the additional number of ticks from the previous
* one in the list. Performing a downtick is therefore efficient since we only need
* to access to the first element.
*/

#include "kernel.h"

struct tlist_item {
	int64_t ticks;
	void* data;
	struct tlist_item* next;

};

struct tlist {
	struct tlist_item* first;
	int count;
	mutex_t lock;
};

int tlist_empty(struct tlist* list)	{
	return (list->count == 0);
}

/**
* Create new list where items are sorted based on the number of "ticks" they are
* from the top.
*
* Returns:
*	The list head on success and NULL on failure.
*/
struct tlist* tlist_new(void)	{
	TMALLOC(n, struct tlist);
	if(PTR_IS_ERR(n))	return n;

	n->count = 0;
	n->first = NULL;

	mutex_clear(&n->lock);
	return n;
}
void tlist_delete(struct tlist* tl)	{
	mutex_acquire(&tl->lock);
	struct tlist_item* i = tl->first, *p;
	while(i != NULL)	{
		p = i;
		i = i->next;
		kfree(p);
	}
	kfree(tl);
}

/**
* Perform downtick and return data if tick has reached zero.
*
* It's the caller's responsibility to check if multiple have reached zero. If
* this check is not performed, the data will be returned on next downtick, but
* the next downtick will be missed. The check should be performed by calling
* :c:func:`tlist_more_zero`.
*
* Parameters:
*	t: List head.
* Returns:
*	An item stored if the tick has reached zero and NULL if no tick has
* 	reached zero.
*/
void* tlist_downtick(struct tlist* t)	{
	void* ret = NULL;
	struct tlist_item* i;
	mutex_acquire(&t->lock);
	i = t->first;
	if(i != NULL)	{
		i->ticks--;
		if(i->ticks <= 0)	{
			//struct tlist_item* tt = i;
			t->first = i->next;
			ret = i->data;
			t->count--;
			kfree(i);
		}
	}
	mutex_release(&t->lock);
	return ret;
}

/**
* Check if the first item in the list has a tick of 0 and if so, return the
* value.
*
* Parameters:
*	t: List head.
*
* Returns:
* 	An item stored if the tick has reached zero and NULL if no tick has
* 	reached zero.
*/
void* tlist_more_zero(struct tlist* t)	{
	void* ret = NULL;
	mutex_acquire(&t->lock);
	if(t->first != NULL && t->first->ticks == 0)	{
		struct tlist_item* tt = t->first;
		ret = tt->data;
		t->first = tt->next;
		t->count--;
		kfree(tt);
	}
	mutex_release(&t->lock);
	return ret;
}

/**
* Removes all items from list matching the pointer given.
*/
int tlist_remove(struct tlist* t, void* remove)	{
	//int tickadd = 0;
	mutex_acquire(&t->lock);
	struct tlist_item* item = t->first, *prev = NULL;
	while(item != NULL)	{
		if(item->data == remove)	{
			//struct tlist_item* f = item;
			if(item->next != NULL)	{
				// Update ticks on next if it exists
				item->next->ticks += item->ticks;
			}

			// Update pointers
			if(prev == NULL)	WRITE_ONCE(t->first, item->next);
			else				WRITE_ONCE(prev->next, item->next);

			kfree(item);
			break;
		}
		prev = item;
		item = item->next;
	}
	mutex_release(&t->lock);
	return 0;
}

/**
* Add new item in the list.
*
* Parameters:
*	  t: List head
* 	  data: The data which should be stored
* 	  ticks: Number of ticks to be associated with data
*
* Returns:
* 	  :c:type:`OK` on success and :c:type:`MEMALLOC` on failure.
*/
int tlist_add(struct tlist* t, void* data, int64_t ticks)	{
	TZALLOC(n, struct tlist_item);
	if(PTR_IS_ERR(n))	return -(MEMALLOC);
	
	mutex_acquire(&t->lock);

	t->count++;
	n->next = NULL;
	n->data = data;

	// Special handling of first
	if(t->first == NULL)	{
		n->ticks = ticks;
		t->first = n;
	}
	else	{
		struct tlist_item* i = t->first, *p = NULL;
		while(i != NULL && ticks >= i->ticks)	{
			ticks -= i->ticks;
			p = i;
			i = i->next;
		}
		ASSERT(ticks >= 0);

		WRITE_ONCE(n->next, i);
		n->ticks = ticks;
		// Place at beginning
		if(p == NULL)	WRITE_ONCE(t->first, n);
		else			WRITE_ONCE(p->next, n);

		// Subtract ticks on the next entry
		if(i != NULL)	{
			i->ticks -= ticks;
			ASSERT_TRUE(i->ticks >= 0, "Tick count is negative\n");
		}
		// Now we need to decrement ticks on everything that comes after what
		// we've just inserted
		//i = n->next;
		/*
		while(i != NULL)	{
			i->ticks -= ticks;
			ASSERT(i->ticks >= 0, "Tick count is negative\n");
			i = i->next;
		}*/
	}

	mutex_release(&t->lock);
	return OK;
}
