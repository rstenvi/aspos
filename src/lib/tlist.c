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
	volatile uint8_t lock;
};

/**
* Create new list where items are sorted based on the number of "ticks" they are
* from the top.
*
* Returns:
*	The list head on success and NULL on failure.
*/
struct tlist* tlist_new(void)	{
	struct tlist* n = (struct tlist*)malloc(sizeof(struct tlist));
	if(n == NULL)	return NULL;

	n->count = 0;
	n->first = NULL;

	mutex_clear(&n->lock);
	return n;
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
	mutex_acquire(&t->lock);
	if(t->first != NULL)	{
		t->first->ticks--;
		if(t->first->ticks <= 0)	{
			struct tlist_item* tt = t->first;
			ret = tt->data;
			t->first = tt->next;
			t->count--;
			free(tt);
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
		free(tt);
	}
	mutex_release(&t->lock);
	return ret;
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
	struct tlist_item* n = (struct tlist_item*)malloc(sizeof(struct tlist_item));
	if(n == NULL)	return -(MEMALLOC);
	
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

		n->next = i;
		n->ticks = ticks;
		// Place at beginning
		if(p == NULL)	t->first = n;
		else			p->next = n;

		// Now we need to decrement ticks on everthing that comes after what
		// we've just inserted
		i = n->next;
		while( i != NULL)	{
			i->ticks -= ticks;
			i = i->next;
		}
	}

	mutex_release(&t->lock);
	return OK;
}
