/*
 * Copyright (c) Linus Torvalds
 * Copyright (c) 2011, 2012 The University of Utah
 *
 * This file contains list-implementation code taken from Linux
 * (primarily the Linux source file `include/linux/list.h') and
 * de-kernelized for user-space programs.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

/* Taken from Linux kernel code, but de-kernelized for userspace. */
#include <stddef.h>

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

#define container_of(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

#define list_top(head, type, member)                      \
({                                    \
    struct list_head *_head = (head);                 \
    list_empty(_head) ? NULL : list_entry(_head->next, type, member); \
})

/*
 * Insert a new entry between two known consecutive entries. 
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *newn,
                  struct list_head *prev,
                  struct list_head *next)
{
    next->prev = newn;
    newn->next = next;
    newn->prev = prev;
    prev->next = newn;
}

/**
 * list_add - add a new entry
 * @newn: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *newn, struct list_head *head)
{
    __list_add(newn, head, head->next);
}

/**
 * list_add_tail - add a new entry
 * @newn: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *newn, struct list_head *head)
{
    __list_add(newn, head->prev, head);
}

/**
 * list_replace - replace old entry by new one
 * @old : the element to be replaced
 * @newn : the new element to insert
 * Note: if 'old' was empty, it will be overwritten.
 */
static inline void list_replace(struct list_head *old, struct list_head *newn)
{
    newn->next = old->next;
    newn->next->prev = newn;
    newn->prev = old->prev;
    newn->prev->next = newn;
}

/*
 * Insert a new entry between two known consecutive entries. 
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static __inline__ void __list_add_rcu(struct list_head * newn,
    struct list_head * prev,
    struct list_head * next)
{
    newn->next = next;
    newn->prev = prev;
    next->prev = newn;
    prev->next = newn;
}

/**
 * list_add_rcu - add a new entry to rcu-protected list
 * @newn: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static __inline__ void list_add_rcu(struct list_head *newn, struct list_head *head)
{
    __list_add_rcu(newn, head, head->next);
}

/**
 * list_add_tail_rcu - add a new entry to rcu-protected list
 * @newn: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static __inline__ void list_add_tail_rcu(struct list_head *newn, struct list_head *head)
{
    __list_add_rcu(newn, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = (struct list_head *)LIST_POISON1;
    entry->prev = (struct list_head *)LIST_POISON2;
}

/**
 * list_del_rcu - deletes entry from list without re-initialization
 * @entry: the element to delete from the list.
 *
 * Note: list_empty on entry does not return true after this, 
 * the entry is in an undefined state. It is useful for RCU based
 * lockfree traversal.
 *
 * In particular, it means that we can not poison the forward 
 * pointers that may still be used for walking the list.
 */
static inline void list_del_rcu(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->prev = (struct list_head *)LIST_POISON2;
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void list_del_init(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    INIT_LIST_HEAD(entry); 
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void list_move(struct list_head *list, struct list_head *head)
{
        __list_del(list->prev, list->next);
        list_add(list, head);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void list_move_tail(struct list_head *list,
                  struct list_head *head)
{
        __list_del(list->prev, list->next);
        list_add_tail(list, head);
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(struct list_head *head)
{
    return head->next == head;
}

static inline void __list_splice(struct list_head *list,
                 struct list_head *head)
{
    struct list_head *first = list->next;
    struct list_head *last = list->prev;
    struct list_head *at = head->next;

    first->prev = head;
    head->next = first;

    last->next = at;
    at->prev = last;
}

/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice(struct list_head *list, struct list_head *head)
{
    if (!list_empty(list))
        __list_splice(list, head);
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void list_splice_init(struct list_head *list,
                    struct list_head *head)
{
    if (!list_empty(list)) {
        __list_splice(list, head);
        INIT_LIST_HEAD(list);
    }
}

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

/**
 * list_for_each    -   iterate over a list
 * @pos:    the &struct list_head to use as a loop counter.
 * @head:   the head for your list.
 */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev   -   iterate over a list backwards
 * @pos:    the &struct list_head to use as a loop counter.
 * @head:   the head for your list.
 */
#define list_for_each_prev(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)
            
/**
 * list_for_each_safe   -   iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop counter.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
        pos = n, n = pos->next)

/**
 * list_for_each_entry  -   iterate over list of given type
 * @pos:    the type * to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)              \
    for (pos = list_entry((head)->next, typeof(*pos), member);  \
         &pos->member != (head);                    \
         pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_dual  -   iterate over two lists of given type
 * @pos:    the type * to use as a loop counter.
 * @pos2:   the type * to use as a loop counter.
 * @head:   the head for your list.
 * @head2:  the head for your list.
 * @member: the name of the list_struct within the struct.
 * @member2:the name of the list_struct within the struct.
 */
#define list_for_each_entry_dual(pos, pos2, head, head2, member, member2)	\
    for (pos = list_entry((head)->next, typeof(*pos), member),		\
	     pos2 = list_entry((head2)->next, typeof(*pos2), member2);	\
         &pos->member != (head) && &pos2->member2 != (head2);           \
         pos = list_entry(pos->member.next, typeof(*pos), member),	\
	     pos2 = list_entry(pos2->member2.next, typeof(*pos2), member2))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:    the type * to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)          \
    for (pos = list_entry((head)->prev, typeof(*pos), member);  \
         &pos->member != (head);                    \
         pos = list_entry(pos->member.prev, typeof(*pos), member))


/**
 * list_for_each_entry_continue -   iterate over list of given type
 *          continuing after existing point
 * @pos:    the type * to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_continue(pos, head, member)         \
    for (pos = list_entry(pos->member.next, typeof(*pos), member);  \
         &pos->member != (head);    \
         pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:    the type * to use as a loop counter.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)          \
    for (pos = list_entry((head)->next, typeof(*pos), member),  \
        n = list_entry(pos->member.next, typeof(*pos), member); \
         &pos->member != (head);                    \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))


/* 
 * Double linked lists with a single pointer list head. 
 * Mostly useful for hash tables where the two pointer list head is 
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */ 

struct hlist_head { 
    struct hlist_node *first; 
}; 

struct hlist_node { 
    struct hlist_node *next, **pprev; 
}; 

#define HLIST_HEAD_INIT { .first = NULL } 
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL) 
#define INIT_HLIST_NODE(ptr) ((ptr)->next = NULL, (ptr)->pprev = NULL)

static __inline__ int hlist_unhashed(struct hlist_node *h) 
{ 
    return !h->pprev;
} 

static __inline__ int hlist_empty(struct hlist_head *h) 
{ 
    return !h->first;
} 

static __inline__ void __hlist_del(struct hlist_node *n) 
{
    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;
    *pprev = next;  
    if (next) 
        next->pprev = pprev;
}  

static __inline__ void hlist_del(struct hlist_node *n)
{
    __hlist_del(n);
    n->next = (struct hlist_node *)LIST_POISON1;
    n->pprev = (struct hlist_node **)LIST_POISON2;
}

/**
 * hlist_del_rcu - deletes entry from hash list without re-initialization
 * @entry: the element to delete from the hash list.
 *
 * Note: list_unhashed() on entry does not return true after this, 
 * the entry is in an undefined state. It is useful for RCU based
 * lockfree traversal.
 *
 * In particular, it means that we can not poison the forward
 * pointers that may still be used for walking the hash list.
 */
static inline void hlist_del_rcu(struct hlist_node *n)
{
    __hlist_del(n);
    n->pprev = (struct hlist_node **)LIST_POISON2;
}

static __inline__ void hlist_del_init(struct hlist_node *n) 
{
    if (n->pprev)  {
        __hlist_del(n);
        INIT_HLIST_NODE(n);
    }
}  

#define hlist_del_rcu_init hlist_del_init

static __inline__ void hlist_add_head(struct hlist_node *n, struct hlist_head *h) 
{ 
    struct hlist_node *first = h->first;
    n->next = first; 
    if (first) 
        first->pprev = &n->next;
    h->first = n; 
    n->pprev = &h->first; 
} 

static __inline__ void hlist_add_head_rcu(struct hlist_node *n, struct hlist_head *h) 
{ 
    struct hlist_node *first = h->first;
    n->next = first;
    n->pprev = &h->first; 
    if (first) 
        first->pprev = &n->next;
    h->first = n; 
} 

/* next must be != NULL */
static __inline__ void hlist_add_before(struct hlist_node *n, struct hlist_node *next)
{
    n->pprev = next->pprev;
    n->next = next; 
    next->pprev = &n->next; 
    *(n->pprev) = n;
}

static __inline__ void hlist_add_after(struct hlist_node *n,
                       struct hlist_node *next)
{
    next->next  = n->next;
    *(next->pprev)  = n;
    n->next     = next;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

/* Cannot easily do prefetch unfortunately */
#define hlist_for_each(pos, head) \
    for (pos = (head)->first; pos; pos = pos->next) 

#define hlist_for_each_safe(pos, n, head) \
    for (pos = (head)->first; n = pos ? pos->next : 0, pos; \
         pos = n)

/**
 * hlist_for_each_entry - iterate over list of given type
 * @tpos:   the type * to use as a loop counter.
 * @pos:    the &struct hlist_node to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)            \
    for (pos = (head)->first;                    \
         pos && ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = pos->next)

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after existing point
 * @tpos:   the type * to use as a loop counter.
 * @pos:    the &struct hlist_node to use as a loop counter.
 * @member: the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(tpos, pos, member)         \
    for (pos = (pos)->next;                      \
         pos && ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = pos->next)

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from existing point
 * @tpos:   the type * to use as a loop counter.
 * @pos:    the &struct hlist_node to use as a loop counter.
 * @member: the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(tpos, pos, member)             \
    for (; pos && ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = pos->next)

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:   the type * to use as a loop counter.
 * @pos:    the &struct hlist_node to use as a loop counter.
 * @n:      another &struct hlist_node to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(tpos, pos, n, head, member)        \
    for (pos = (head)->first;                    \
         pos && ({ n = pos->next; 1; }) &&               \
        ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
         pos = n)

#endif /* _LINUX_LIST_H */
