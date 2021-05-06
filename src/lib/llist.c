#include "lib.h"


struct llist* llist_alloc(void)	{
	TMALLOC(l, struct llist);
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
	TMALLOC(i, struct llist_item);
	struct llist_item* c = NULL, * p = NULL;
	if(PTR_IS_ERR(i))	return -MEMALLOC;

	mutex_acquire(&list->lock);

	i->data = item;
	i->key = key;
	i->next = NULL;

	if(list->head == NULL)		{
		list->head = i;
	}
	else	{
		c = list->head;
		while(c != NULL && key < c->key)	{
			p = c;
			c = c->next;
		}

		i->next = c;
		if(c == list->head)	{
			list->head = i;
		}
		else	{
			p->next = i;
		}
	}
	list->count++;
	mutex_release(&list->lock);
	return OK;
}

static void* _llist_find(struct llist* list, long key, bool remove)	{
	struct llist_item* i = list->head, * p = NULL;
	void* ret = NULL;
	while(i != NULL && i->key != key)	{
		p = i;
		i = i->next;
	}
	if(i != NULL)	{
		ret = i->data;
		if(remove)	{
			if(i == list->head)	{
				list->head = i->next;
			}
			else	{
				p->next = i->next;
			}
			kfree(i);
			list->count--;
		}
	}
	return ret;
}

void* llist_remove(struct llist* list, long key)	{
	void* ret = NULL;
	mutex_acquire(&list->lock);
	ret = _llist_find(list, key, true);
	mutex_clear(&list->lock);
	return ret;
}
void* llist_find(struct llist* list, long key)	{
	void* ret = (void*)-1;
	mutex_acquire(&list->lock);
	ret = _llist_find(list, key, false);
	mutex_clear(&list->lock);
	return ret;
}
void* llist_first(struct llist* list, bool remove, long* key)	{
	void* ret = NULL;
	struct llist_item* item;
	mutex_acquire(&list->lock);
	if(list->count > 0)	{
		item = list->head;
		ret = item->data;
		if(key)	*key = item->key;
		if(remove)	{
			list->head = item->next;
			list->count--;
			kfree(item);
		}
	}
	mutex_clear(&list->lock);
	return ret;
}
void* llist_index(struct llist* list, int idx)	{
	int i;
	struct llist_item* item = list->head;
	if(list->count < i)	return NULL;
	for(i = 0; i < idx && item != NULL; i++)	{
		item = item->next;
	}
	if(!item)	return NULL;
	return (item->data);
}

bool llist_empty(struct llist* list)	{
	return (list->head == NULL);
}
