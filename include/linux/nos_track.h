#ifndef _NOS_TRACK_H
#define _NOS_TRACK_H

#include <linux/types.h>

#define NOS_USER_TRACK_MAX 			(1 << 19 >> 3)
#define NOS_FLOW_TRACK_MAX 			(1 << 18 >> 3)

#define NOS_USER_INFO_SIZE			(256)
#define NOS_FLOW_INFO_SIZE			(256)

#define NOS_USER_DATA_SIZE (NOS_USER_INFO_SIZE - 16)
#define NOS_FLOW_DATA_SIZE (NOS_FLOW_INFO_SIZE - sizeof(struct nos_flow_tuple) - 16)

#define NOS_FLOW_DIR_UNKNOWN		(0)
#define NOS_FLOW_DIR_LAN2WAN		(1)
#define NOS_FLOW_DIR_WAN2LAN		(2)
#define NOS_FLOW_DIR_LAN2LAN		(3)
#define NOS_FLOW_DIR_WAN2WAN		(4)

struct nos_flow_tuple {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t  proto;
	uint8_t  dir; 	//wan->lan, lan->wan, lan->lan, wan->wan.
	uint8_t  inface;  //lan | wan.
	uint8_t  dummy_pad;
};

struct nos_user_info {
	uint32_t magic;
	uint32_t id;
	uint32_t ip;
	uint32_t refcnt;

	char data[NOS_USER_DATA_SIZE]; //data store for user define struct
};

static inline void * nos_user_info_priv(struct nos_user_info * user)
{
	return (void*)user->data;
}

struct nos_flow_info {
	uint32_t magic;
	uint32_t id;
	uint32_t usr_src_id;
	uint32_t usr_dst_id;

	struct nos_flow_tuple tuple;

	char data[NOS_FLOW_DATA_SIZE]; //data store for user define struct
};

static inline void * nos_flow_info_priv(struct nos_flow_info* flow)
{
	return (void*)flow->data;
}

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>

struct tbq_backlog {
	struct list_head list;
	struct tbq_token_ctrl *tc;
	uint32_t octets;
	uint32_t weight;
	int32_t drr_deficit;
};

struct tbq_flow_backlog {
	struct tbq_backlog base;
	struct list_head packets;
	struct tbq_flow_track *tf;
};

struct tbq_flow_track {
	struct list_head list;
	uint16_t dummy;
	uint16_t app_id;
	uint32_t rule_mask;
	uint8_t weight[32];
	struct tbq_flow_backlog backlog[2];
};

struct nos_track {
	struct nos_flow_info *flow;
	struct nos_user_info *usr_src;
	struct nos_user_info *usr_dst;
	struct tbq_flow_track tbq;
};

struct nos_user_track {
	uint32_t ip;
	uint32_t magic;
	struct hlist_node hash_node;
	spinlock_t lock;
	uint32_t refcnt;
	void *tbq;
};

struct nos_flow_track {
	uint32_t magic;
	struct nos_user_track *usr_src;
	struct nos_user_track *usr_dst;
};

struct nos_track_event {
	struct list_head list;
	void (* on_user_free)(struct nos_user_track *);
	void (* on_flow_free)(struct tbq_flow_track *);
};

struct nos_track_stats {
	atomic64_t nr_flow_alloc;
	atomic64_t nr_flow_free;
	atomic64_t nr_ring_drop;
};

extern struct nos_track_stats *nos_track_stats;

int nos_track_init(void);
int nos_track_alloc(struct nos_track *track, struct nos_flow_tuple *tuple);
void nos_track_free(struct nos_track *track);

struct nos_user_track *nos_get_user_track(struct nos_track *track);
struct nos_flow_track *nos_get_flow_track(struct nos_track *track);

void nos_track_event_register(struct nos_track_event *ev);
void nos_track_event_unregister(struct nos_track_event *ev);

/* common apis */
static inline nos_get_flow_info(struct nos_track* nos)
{
	return nos->flow;
}

static inline nos_get_user_info(struct nos_track* nos)
{	
	return nos->usr_src;
}

static inline nos_get_peer_info(struct nos_track *nos)
{
	return nos->usr_dst;
}

#endif /* __KERNEL__ */


#endif /* _NOS_TRACK_H */
