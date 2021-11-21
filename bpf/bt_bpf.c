#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>

#include "ethertypes.h"

char LICENSE[] SEC("license") = "GPL";

SEC("bt_pppoe_ingress")
int _bt_pppoe_ingress(struct __sk_buff *skb) {
	void *end  = (void*)(long)skb->data_end;
	void *data = (void*)(long)skb->data;

	struct ethhdr *eth = data;

	if (data + sizeof(*eth) > end) return TC_ACT_OK;

	if (eth->h_proto != 0x6388) return TC_ACT_OK;

	eth->h_proto = ___constant_swab16((PPPOE_ETHERTYPE_SUB));
	return TC_ACT_OK;
}

SEC("bt_pppoe_egress")
int _bt_pppoe_egress(struct __sk_buff *skb) {
	void *end  = (void*)(long)skb->data_end;
	void *data = (void*)(long)skb->data;

	struct ethhdr *eth = data;

	if (data + sizeof(*eth) > end) return TC_ACT_OK;

	/*if (eth->h_proto == ___constant_swab16((PPPOE_ETHERTYPE_SUB))) return TC_ACT_SHOT;
	if (eth->h_proto == ___constant_swab16((ROUTER_ETHERTYPE_SUB))) return TC_ACT_SHOT;
	if (eth->h_proto == ___constant_swab16((ONT_ETHERTYPE_SUB))) return TC_ACT_SHOT;
	*/

	if (eth->h_proto != ___constant_swab16((0x8863)) && eth->h_proto != ___constant_swab16((0x8864))) return TC_ACT_SHOT;

	return TC_ACT_OK;
}
