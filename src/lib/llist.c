#include "lib.h"
#include "memory.h"


struct llist* llist_alloc(void)	{
	TZALLOC(l, struct llist);
	if(PTR_IS_ERR(l))	return l;

	l->head = NULL;
	l->count = 0;
	mutex_clear(&l->lock);
	return l;
}
void llist_delete(struct llist* list)	{
	struct llist_item* i, * p;
	mutex_acquire(&list->lock);
	i = list->head;
	while(i != NULL)	{
		p = i;
		i = i->next;
		kfree(p);
	}
	kfree(list);
}

int llist_insert(struct llist* list, void* item, long key)	{
	struct llist_item* c = NULL, * p = NULL;
	TZALLOC(i, struct llist_item);
	if(PTR_IS_ERR(i))	return -MEMALLOC;

	mutex_acquire(&list->lock);

	i->data = item;
	i->key = key;
	i->next = NULL;

	if(list->head == NULL)		{
		WRITE_ONCE(list->head, i);
	}
	else	{
		c = READ_ONCE(list->head);
		while(c != NULL && key < c->key)	{
			p = c;
			c = c->next;
		}

		WRITE_ONCE(i->next, c);
		if(c == list->head) WRITE_ONCE(list->head, i);
		else				WRITE_ONCE(p->next, i);
	}
	list->count++;
	mutex_release(&list->lock);
	return OK;
}

static void* _llist_find(struct llist* list, long key, bool remove)	{
	ASSERT(mutex_held(list->lock));
	struct llist_item* i = list->head, * p = NULL;
	void* ret = NULL;
	while(i != NULL && i->key != key)	{
		p = i;
		i = i->next;
	}
	if(i != NULL)	{
		ret = i->data;
		if(remove)	{
			if(i == list->head)	WRITE_ONCE(list->head, i->next);
			else				WRITE_ONCE(p->next, i->next);

			kfree(i);
			list->count--;
		}
	}
	//mutex_release(&list->lock);
	return ret;
}

void* llist_remove(struct llist* list, long key)	{
	void* ret = NULL;
	mutex_acquire(&list->lock);
	ret = _llist_find(list, key, true);
	mutex_release(&list->lock);
	return ret;
}
void* llist_find(struct llist* list, long key)	{
	void* ret = (void*)-1;
	mutex_acquire(&list->lock);
	ret = _llist_find(list, key, false);
	mutex_release(&list->lock);
	return ret;
}
void* llist_first(struct llist* list, bool remove, long* key)	{
	void* ret = NULL;
	struct llist_item* item;
	mutex_acquire(&list->lock);
	item = READ_ONCE(list->head);
	if(item)	{
		ret = item->data;
		if(key)	*key = item->key;
		if(remove)	{
			WRITE_ONCE(list->head, item->next);
			list->count--;
			kfree(item);
		}
	}
	mutex_release(&list->lock);
	return ret;
}
void* llist_index(struct llist* list, int idx)	{
	int i;
	void* ret = NULL;
	mutex_acquire(&list->lock);
	struct llist_item* item = list->head;
//	if(!item)	goto out;

	for(i = 0; i < idx && item != NULL; i++)	{
		item = item->next;
	}
	if(item)	{
		ret = item->data;
	}
	mutex_release(&list->lock);
	return ret;
}

bool llist_empty(struct llist* list)	{
	bool ret;
	mutex_acquire(&list->lock);
	ret = (list->head == NULL);
	mutex_release(&list->lock);
	return ret;
}
