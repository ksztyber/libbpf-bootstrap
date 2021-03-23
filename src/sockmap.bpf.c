#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
#define MAX_ENTRIES 3
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} sock_map SEC(".maps");

SEC("sk_skb/stream_parser")
int sk_parser(struct __sk_buff *skb)
{
	bpf_printk("parser: %d (%p)", skb->len, skb);
	return skb->len;
}

uint32_t current;

SEC("sk_skb/stream_verdict")
int sk_verdict(struct __sk_buff *skb)
{
	uint32_t idx = current + 1;

	current = idx % (MAX_ENTRIES - 1);

	bpf_printk("verdict: %u, %d (%p)", idx, skb->len, skb);
	return bpf_sk_redirect_map(skb, &sock_map, idx, 0);
}

