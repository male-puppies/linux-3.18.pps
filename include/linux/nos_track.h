#ifndef _NOS_TRACK_H
#define _NOS_TRACK_H

#include <linux/types.h>

#define NOS_USER_TRACK_MAX 			(1 << 19 >> 3)
#define NOS_FLOW_TRACK_MAX 			(1 << 18 >> 3)

#define NOS_USER_INFO_SIZE			(32)
#define NOS_FLOW_INFO_SIZE			(64)

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

struct nos_user_info;
struct nos_flow_info;


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
	uint16_t uname_match;	//mo
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

#endif /* __KERNEL__ */


#endif /* _NOS_TRACK_H */