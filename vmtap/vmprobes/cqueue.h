#ifndef _CIRCULAR_QUEUE_H
#define _CIRCULAR_QUEUE_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

typedef int cqueue_entry_t;

struct cqueue
{
    cqueue_entry_t *array;
    unsigned long front, rear;
    unsigned long max;
};

static inline bool
cqueue_init(struct cqueue *q, unsigned long count)
{
    q->front = q->rear = 0;
    q->max = count + 1;
    q->array = (cqueue_entry_t *) malloc( sizeof(cqueue_entry_t) * q->max );
    if (!q->array)
        return false;
    return true;
}

static inline void
cqueue_cleanup(struct cqueue *q)
{
    if (q)
    {
        if (q->array)
        {
            free(q->array);
            q->array = NULL;
        }
    }
}

static inline bool
cqueue_empty(struct cqueue *q)
{
    return (q->front == q->rear);
}

static inline bool
cqueue_full(struct cqueue *q)
{
    return (q->front == ((q->rear + 1) % q->max));
}

static inline unsigned long
cqueue_count(struct cqueue *q)
{
    return ((q->rear > q->front) ? 
            (q->rear - q->front) : 
            (q->rear + q->max - q->front));
}

static inline void
cqueue_clear(struct cqueue *q)
{
    q->front = q->rear;
}

static inline bool
cqueue_put(struct cqueue *q, cqueue_entry_t v)
{
    if (cqueue_full(q))
        return false;
    q->array[q->rear] = v;
    q->rear = (q->rear + 1) % q->max;
    return true;
}

static inline bool
cqueue_get(struct cqueue *q, cqueue_entry_t *v)
{
    if (cqueue_empty(q))
        return false;
    if (v)
        *v = q->array[q->front];
    q->front = (q->front + 1) % q->max;
    return true;
}

static inline bool
cqueue_peek(struct cqueue *q, cqueue_entry_t *v)
{
    if (cqueue_empty(q) || !v)
        return false;
    *v = q->array[q->front];
    return true;
}

static inline void 
cqueue_print(struct cqueue *q)
{
    unsigned long i;
    for (i = q->front; i != q->rear; i = (i + 1) % q->max)
        printf("[%3ld] %-6d\n", (i + 1), q->array[i]);
}

#endif /* _CIRCULAR_QUEUE_H */
