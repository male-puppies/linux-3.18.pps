#ifndef _NOS_MEMPOOL_H
#define _NOS_MEMPOOL_H

#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/ratelimit.h>

struct nos_mempool {
	spinlock_t lock;
	void *head;
	void **tail;
	int nr_used;
	int nr_free;
	const char *name;
};

static __inline void
nos_mempool_init(struct nos_mempool *pool, const char *name, int nr_used)
{
	spin_lock_init(&pool->lock);
	pool->head = NULL;
	pool->tail = &pool->head;
	pool->nr_used = nr_used;
	pool->nr_free = 0;
	pool->name = name;
}

static __inline void *
nos_mempool_get(struct nos_mempool *pool)
{
	void *data;

	spin_lock_bh(&pool->lock);
	data = pool->head;
	if (data != NULL) {
		pool->head = *(void **)data;
		if (pool->head == NULL) {
			pool->tail = &pool->head;
		}
		pool->nr_used++;
		pool->nr_free--;
	} else {
		pr_warn_ratelimited("nos_mempool oom: %s, nr_used: %d, nr_free: %d\n",
							pool->name, pool->nr_used, pool->nr_free);
	}
	spin_unlock_bh(&pool->lock);
	return data;
}

static __inline void
nos_mempool_put(struct nos_mempool *pool, void *data)
{
	spin_lock_bh(&pool->lock);
	*(void **)data = NULL;
	*pool->tail = data;
	pool->tail = (void **)data;
	pool->nr_used--;
	pool->nr_free++;
	spin_unlock_bh(&pool->lock);
}

#endif /* _NOS_MEMPOOL_H */
