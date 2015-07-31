#ifndef __NOS_SKB_H__
#define __NOS_SKB_H__

#include <linux/types.h>
#include <linux/if.h>

#define NOS_QOS_LINE_MAX 	(8)

struct tbq_packet_ctrl {
	struct tbq_bucket_sched *bucket_sched;
	struct tbq_user_sched *user_sched;
	uint32_t rule_mask;
	uint32_t pkt_len;
};

struct nos_skb_info {
	struct tbq_packet_ctrl pc;
};

#endif	//__NOS_SKB_H__