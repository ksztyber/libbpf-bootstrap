#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "nvmf.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct nvmf_sk_redirect);
} sk_storage_map SEC(".maps");

static struct nvmf_sk_redirect *
skb_get_redirect(struct __sk_buff *skb)
{
	if (!skb->sk) {
		return 0;
	}

	return bpf_sk_storage_get(&sk_storage_map, skb->sk, 0, 0);
}

SEC("sk_skb/stream_parser")
int sk_parser(struct __sk_buff *skb)
{
	struct nvmf_sk_redirect *redirect;

	redirect = skb_get_redirect(skb);
	if (!redirect) {
		bpf_printk("parser: failed to retrieve sk_redirect");
		return -1;
	}

	/* Flip the current index between the ctrl/data sockets */
	redirect->current_idx = redirect->current_idx == redirect->ctrl_idx ?
				redirect->data_idx : redirect->ctrl_idx;

	return 1;
}

SEC("sk_skb/stream_verdict")
int sk_verdict(struct __sk_buff *skb)
{
	struct nvmf_sk_redirect *redirect;

	redirect = skb_get_redirect(skb);
	if (!redirect) {
		bpf_printk("verdict: failed to retrieve sk_redirect");
		return SK_DROP;
	}

	return bpf_sk_redirect_map(skb, &sock_map, redirect->current_idx, 0);
}
