#include "lib.h"


struct llist* llist_alloc(void)	{
	struct llist* l = (struct llist*)malloc( sizeof(struct llist) );
	if(l == NULL)	return ERR_ADDR_PTR(-1);

	l->head = NULL;
	l->count = 0;
	mutex_clear(&l->lock);
	return l;
}

int llist_insert(struct llist* list, void* item, long key)	{
	struct llist_item* i = (struct llist_item*)malloc(sizeof(struct llist_item));
	struct llist_item* c = NULL, * p = NULL;
	if(i == NULL)	return -MEMALLOC;

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
			free(i);
			list->count--;
		}
	}
	return ret;
}

void* llist_remove(struct llist* list, long key)	{
	void* ret = (void*)-1;
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
