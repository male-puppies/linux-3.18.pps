#include <linux/nos_track.h>
#include <linux/nos_mempool.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/slab.h>

#define NOS_USER_DATA_SIZE (NOS_USER_INFO_SIZE - 16)
#define NOS_FLOW_DATA_SIZE (NOS_FLOW_INFO_SIZE - sizeof(struct nos_flow_tuple) - 16)

struct nos_user_info {
	uint32_t magic;
	uint32_t id;
	uint32_t ip;
	uint32_t refcnt;

	char data[NOS_USER_DATA_SIZE];
};

struct nos_flow_info {
	uint32_t magic;
	uint32_t id;
	uint32_t usr_src_id;
	uint32_t usr_dst_id;

	struct nos_flow_tuple tuple;

	char data[NOS_FLOW_DATA_SIZE];
};


#define NOS_USER_TRACK_HASH_SIZE 	NOS_USER_TRACK_MAX


struct nos_track_stats *nos_track_stats;
EXPORT_SYMBOL(nos_track_stats);

static struct nos_user_track nos_user_tracks[NOS_USER_TRACK_MAX];
static struct nos_flow_track nos_flow_tracks[NOS_FLOW_TRACK_MAX];

static struct nos_mempool nos_user_track_pool;
static struct nos_mempool nos_flow_track_pool;

static struct hlist_head nos_user_track_hash[NOS_USER_TRACK_HASH_SIZE];
static spinlock_t nos_user_track_hash_lock;

static atomic_t nos_user_magic = ATOMIC_INIT(0);
static atomic_t nos_flow_magic = ATOMIC_INIT(0);

static struct nos_user_info *nos_user_info_base;
static struct nos_flow_info *nos_flow_info_base;

static struct {
	struct list_head list;
	spinlock_t lock;
} nos_track_events;


static struct nos_user_info *
nos_user_info_init(struct nos_user_track *ut)
{
	int32_t user_id = ut - nos_user_tracks;
	struct nos_user_info *ui = nos_user_info_base + user_id;

	ui->id = user_id;
	ui->ip = ut->ip;
	ui->refcnt = 1;

	memset(ui->data, 0, sizeof(ui->data));

	smp_wmb();

	ui->magic = ut->magic;

	return ui;
}

static inline void
nos_user_info_update_refcnt(struct nos_user_track *ut)
{
	int32_t user_id = ut - nos_user_tracks;
	struct nos_user_info *ui = nos_user_info_base + user_id;
	ui->refcnt = ut->refcnt;
}

static struct nos_flow_info *
nos_flow_info_init(struct nos_flow_track *ft, struct nos_flow_tuple *tuple)
{
	int32_t flow_id = ft - nos_flow_tracks;
	struct nos_flow_info *fi = nos_flow_info_base + flow_id;

	fi->id = flow_id;
	fi->usr_src_id = ft->usr_src - nos_user_tracks;
	fi->usr_dst_id = ft->usr_dst - nos_user_tracks;
	fi->tuple = *tuple;

	memset(fi->data, 0, sizeof(fi->data));

	smp_wmb();

	fi->magic = ft->magic;

	return fi;
}

static struct nos_user_track *
nos_user_track_get(uint32_t ip)
{
	struct nos_user_track *user;
	struct hlist_head *slot;
	uint32_t slot_index;

	slot_index = ip % NOS_USER_TRACK_HASH_SIZE;

	spin_lock_bh(&nos_user_track_hash_lock);

	slot = &nos_user_track_hash[slot_index];

	hlist_for_each_entry(user, slot, hash_node) {
		if (user->ip == ip) {
			spin_lock_bh(&user->lock);
			if (user->refcnt == 0) {
				spin_unlock_bh(&user->lock);
				break;
			}
			++user->refcnt;
			nos_user_info_update_refcnt(user);
			spin_unlock_bh(&user->lock);
			goto out;
		}
	}

	user = nos_mempool_get(&nos_user_track_pool);
	if (user == NULL) {
		goto out;
	}

	user->ip = ip;
	user->magic = atomic_add_return(2, &nos_user_magic);
	spin_lock_init(&user->lock);
	user->refcnt = 1;
	hlist_add_head(&user->hash_node, slot);
	nos_user_info_init(user);

	user->tbq = NULL;

#if 0
	printk("[nos_track] ADD USER: %pI4h\t(%6d / %6d)\n",
			&ip, nos_user_track_pool.nr_used, nos_user_track_pool.nr_free);
#endif

out:
	spin_unlock_bh(&nos_user_track_hash_lock);
	return user;
}

static void
nos_user_track_put(struct nos_user_track *user)
{
	struct nos_track_event *ev;
	int32_t refcnt;

	BUG_ON(user == NULL);

	spin_lock_bh(&user->lock);
	refcnt = --user->refcnt;
	nos_user_info_update_refcnt(user);
	spin_unlock_bh(&user->lock);

	BUG_ON(refcnt < 0);

	if (refcnt != 0)
		return;

	spin_lock_bh(&nos_track_events.lock);
	list_for_each_entry(ev, &nos_track_events.list, list) {
		ev->on_user_free(user);
	}
	spin_unlock_bh(&nos_track_events.lock);

	BUG_ON(user->tbq != NULL);

	// set delete mark
	nos_user_info_base[user - nos_user_tracks].magic = user->magic | 1U;

	spin_lock_bh(&nos_user_track_hash_lock);
	hlist_del(&user->hash_node);
	spin_unlock_bh(&nos_user_track_hash_lock);
#if 0
	printk("[nos_track] DEL: %pI4h\t(%6d / %6d)\n",
			&user->ip, nos_user_track_pool.nr_used - 1, nos_user_track_pool.nr_free + 1);
#endif
	nos_mempool_put(&nos_user_track_pool, user);	
}

static void
nos_track_check(struct nos_track *track)
{
	struct nos_flow_info *fi = track->flow;
	struct nos_user_info *ui_src = track->usr_src;
	struct nos_user_info *ui_dst = track->usr_dst;
	uint32_t usr_src_id = ui_src - nos_user_info_base;
	uint32_t usr_dst_id = ui_dst - nos_user_info_base;

	if (usr_src_id >= NOS_USER_TRACK_MAX || usr_src_id != fi->usr_src_id) {
		pr_warn_ratelimited("nos_flow_info error: %d, %d\n", usr_src_id, fi->usr_src_id);
	}

	if (usr_dst_id >= NOS_USER_TRACK_MAX || usr_dst_id != fi->usr_dst_id) {
		pr_warn_ratelimited("nos_flow_info error: %d, %d\n", usr_dst_id, fi->usr_dst_id);
	}
}

int
nos_track_alloc(struct nos_track *track, struct nos_flow_tuple *tuple)
{
	struct nos_flow_track *flow = NULL;
	struct nos_user_track *usr_src = NULL;
	struct nos_user_track *usr_dst = NULL;

	if (tuple->inface == NOS_FLOW_DIR_UNKNOWN)
		goto fail;

	flow = nos_mempool_get(&nos_flow_track_pool);
	if (flow == NULL)
		goto fail;

	usr_src = nos_user_track_get(tuple->ip_src);
	usr_dst = nos_user_track_get(tuple->ip_dst);

	if (usr_src == NULL || usr_dst == NULL)
		goto fail;

	if (tuple->inface == NOS_FLOW_DIR_LAN2WAN) {
		flow->usr_src = usr_src;
		flow->usr_dst = usr_dst;
	} else {
		flow->usr_src = usr_dst;
		flow->usr_dst = usr_src;
	}

	flow->magic = atomic_add_return(2, &nos_flow_magic);

	track->flow = nos_flow_info_init(flow, tuple);
	track->usr_src = &nos_user_info_base[track->flow->usr_src_id];
	track->usr_dst = &nos_user_info_base[track->flow->usr_dst_id];
	atomic64_inc(&nos_track_stats->nr_flow_alloc);

	memset(&track->tbq, 0, sizeof(track->tbq));

	return 0;

fail:
	if (flow != NULL) {
		if (usr_src != NULL)
			nos_user_track_put(usr_src);
		if (usr_dst != NULL)
			nos_user_track_put(usr_dst);
		nos_mempool_put(&nos_flow_track_pool, flow);
	}
	track->flow = NULL;
	track->usr_src = NULL;
	track->usr_dst = NULL;
	return -1;
}
EXPORT_SYMBOL(nos_track_alloc);

void
nos_track_free(struct nos_track *track)
{
	struct nos_flow_track *flow;
	struct nos_track_event *ev;
	int flow_id;

	if (track->flow == NULL) {
		return;
	}

	flow_id = track->flow - nos_flow_info_base;
	BUG_ON(flow_id < 0 || flow_id >= NOS_FLOW_TRACK_MAX);
	
	nos_track_check(track);

	flow = &nos_flow_tracks[flow_id];

	spin_lock_bh(&nos_track_events.lock);
	list_for_each_entry(ev, &nos_track_events.list, list) {
		ev->on_flow_free(&track->tbq);
	}
	spin_unlock_bh(&nos_track_events.lock);

	track->flow->magic = flow->magic | 1U; // delete mark

	nos_user_track_put(flow->usr_src);
	nos_user_track_put(flow->usr_dst);	

	nos_mempool_put(&nos_flow_track_pool, flow);

	atomic64_inc(&nos_track_stats->nr_flow_free);
}
EXPORT_SYMBOL(nos_track_free);

struct nos_user_track *
nos_get_user_track(struct nos_track *track)
{
	int user_id;

	BUG_ON(track->flow == NULL);
	BUG_ON(track->usr_src == NULL);
	BUG_ON(track->usr_dst == NULL);

	user_id = track->usr_src - nos_user_info_base;
	BUG_ON(user_id < 0 || user_id >= NOS_USER_TRACK_MAX);
	return nos_user_tracks + user_id;
}
EXPORT_SYMBOL(nos_get_user_track);

struct nos_flow_track *
nos_get_flow_track(struct nos_track *track)
{
	int flow_id;

	BUG_ON(track->flow == NULL);
	BUG_ON(track->usr_src == NULL);
	BUG_ON(track->usr_dst == NULL);

	flow_id = track->flow - nos_flow_info_base;
	BUG_ON(flow_id < 0 || flow_id >= NOS_FLOW_TRACK_MAX);
	return nos_flow_tracks + flow_id;
}
EXPORT_SYMBOL(nos_get_flow_track);

void nos_track_event_register(struct nos_track_event *ev)
{
	spin_lock_bh(&nos_track_events.lock);
	list_add_tail(&ev->list, &nos_track_events.list);
	spin_unlock_bh(&nos_track_events.lock);
}
EXPORT_SYMBOL(nos_track_event_register);

void nos_track_event_unregister(struct nos_track_event *ev)
{
	spin_lock_bh(&nos_track_events.lock);
	list_del(&ev->list);
	spin_unlock_bh(&nos_track_events.lock);
}
EXPORT_SYMBOL(nos_track_event_unregister);

int
nos_track_init()
{
	int i;

	extern struct resource nosmem_res;
	nos_user_info_base = phys_to_virt(nosmem_res.start + (4 << 20));
	nos_flow_info_base = (void *)(nos_user_info_base + NOS_USER_TRACK_MAX);
	nos_track_stats = (void *)(nos_flow_info_base + NOS_FLOW_TRACK_MAX);

	printk("nos_user_info_base: %p (phys: %lx)\n",
			nos_user_info_base, virt_to_phys(nos_user_info_base));
	printk("nos_flow_info_base: %p (phys: %lx)\n",
			nos_flow_info_base, virt_to_phys(nos_flow_info_base));
	printk("nos_track_stats: %p (phys: %lx)\n",
			nos_track_stats, virt_to_phys(nos_track_stats));

	if (virt_to_phys(nos_track_stats + 1) > nosmem_res.end) {
		printk("nosmem_res oom: [%llu - %llu]\n", (uint64_t)nosmem_res.start, (uint64_t)nosmem_res.end);
		return -1;
	}

	// delete mark: magic & 1 == 1
	memset(nos_user_info_base, 0xAF, NOS_USER_TRACK_MAX * sizeof(struct nos_user_info));
	memset(nos_flow_info_base, 0xBF, NOS_FLOW_TRACK_MAX * sizeof(struct nos_flow_info));

	nos_mempool_init(&nos_user_track_pool, "nos_user_track", NOS_USER_TRACK_MAX);
	for (i = 0; i < NOS_USER_TRACK_MAX; i++) {
		nos_mempool_put(&nos_user_track_pool, &nos_user_tracks[i]);
	}

	nos_mempool_init(&nos_flow_track_pool, "nos_flow_track", NOS_FLOW_TRACK_MAX);
	for (i = 0; i < NOS_FLOW_TRACK_MAX; i++) {
		nos_mempool_put(&nos_flow_track_pool, &nos_flow_tracks[i]);
	}

	spin_lock_init(&nos_user_track_hash_lock);
	for (i = 0; i < NOS_USER_TRACK_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&nos_user_track_hash[i]);
	}

	INIT_LIST_HEAD(&nos_track_events.list);
	spin_lock_init(&nos_track_events.lock);

	printk("nos_track_init() OK [user size: %d, flow size: %d]\n",
		   (int)sizeof(struct nos_user_info), (int)sizeof(struct nos_flow_info));

	return 0;
}
EXPORT_SYMBOL(nos_track_init);
