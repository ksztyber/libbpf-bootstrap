#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "nvmf.bpf.h"
#include "nvmf_spec.bpf.h"

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

#define min(a, b) ((a) < (b) ? (a) : (b))

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
	struct nvmf_tcp_common_pdu_hdr hdr;
	int rc = 0, len = 0, skb_offset = 0;

	redirect = skb_get_redirect(skb);
	if (!redirect) {
		bpf_printk("parser: failed to retrieve sk_redirect");
		return -1;
	}

	/* Invalidate current idx to make sure we don't redirect to a wrong soket by mistake */
	redirect->current_idx = -1;
	/* If pdu_len is not set it means that we're receiving a new PDU */
	if (redirect->pdu_len == 0) {
		skb_offset = bpf_skb_get_parse_offset(skb);
		if (skb->len - skb_offset < sizeof(hdr)) {
			return 0;
		}

		rc = bpf_skb_load_bytes(skb, skb_offset, &hdr, sizeof(hdr));
		if (rc != 0) {
			bpf_printk("parser: failed to load the header: %d (offset: %d)", rc,
				   skb_offset);
			return -1;
		}

		/* Perform some basic sanity check on hdr.plen to make sure that, at least, it
		 * covers the common PDU header
		 */
		if (hdr.plen < sizeof(hdr)) {
			bpf_printk("parser: unexpected pdu length: %d", hdr.plen);
			return -1;
		}

		/* We redirect everything up until the data (including header's digest and padding)
		 * to the control socket.  Data and its digest, if present, is redirected to the
		 * data socket.
		 */
		switch (hdr.pdu_type) {
		case NVMF_TCP_PDU_TYPE_IC_REQ:
		case NVMF_TCP_PDU_TYPE_IC_RESP:
		case NVMF_TCP_PDU_TYPE_H2C_TERM_REQ:
		case NVMF_TCP_PDU_TYPE_C2H_TERM_REQ:
		case NVMF_TCP_PDU_TYPE_CAPSULE_RESP:
		case NVMF_TCP_PDU_TYPE_R2T:
			redirect->pdu_headlen = hdr.plen;
			break;
		case NVMF_TCP_PDU_TYPE_CAPSULE_CMD:
		case NVMF_TCP_PDU_TYPE_C2H_DATA:
		case NVMF_TCP_PDU_TYPE_H2C_DATA:
			if (hdr.pdo != 0) {
				if (hdr.pdo > hdr.plen || hdr.pdo < sizeof(hdr)) {
					bpf_printk("parser: invalid pdo value: %d, plen: %d, type %d",
						   hdr.pdo, hdr.plen, hdr.pdu_type);
					return -1;
				}

				redirect->pdu_headlen = hdr.pdo;
			} else {
				redirect->pdu_headlen = hdr.plen;
			}
			break;
		default:
			bpf_printk("parser: unkown PDU type: %d", hdr.pdu_type);
			return -1;
		}

		redirect->pdu_offset = 0;
		redirect->pdu_len = hdr.plen;
		redirect->current_idx = redirect->ctrl_idx;
		len = redirect->pdu_headlen;
	} else {
		/* We always redirect complete header to the control socket, so if we're here, we
		 * must be looking at the data portion of the PDU.
		 */
		if (redirect->pdu_offset < redirect->pdu_headlen ||
		    redirect->pdu_offset >= redirect->pdu_len) {
			bpf_printk("parser: unexpected pdu offset: %d, headlen: %d pdulen: %d",
				   redirect->pdu_offset, redirect->pdu_headlen, redirect->pdu_len);
			return -1;
		}

		redirect->current_idx = redirect->data_idx;
		len = min(redirect->pdu_len - redirect->pdu_offset, skb->len);
	}

	redirect->pdu_offset += len;
	if (redirect->pdu_offset > redirect->pdu_len) {
		bpf_printk("parser: pdu offset exceeds length: %d > %d",
			   redirect->pdu_offset, redirect->pdu_len);
		return -1;
	} else if (redirect->pdu_offset == redirect->pdu_len) {
		/* The whole PDU has been parsed  */
		redirect->pdu_len = 0;
	}

	return len;
}

SEC("sk_skb/stream_verdict")
int sk_verdict(struct __sk_buff *skb)
{
	struct nvmf_sk_redirect *redirect;
	int current_idx;

	redirect = skb_get_redirect(skb);
	if (!redirect) {
		bpf_printk("verdict: failed to retrieve sk_redirect");
		return SK_DROP;
	}

	current_idx = redirect->current_idx;
	if (current_idx < 0) {
		bpf_printk("verdict: received invalid socket idx: %d", current_idx);
		return SK_DROP;
	}

	return bpf_sk_redirect_map(skb, &sock_map, current_idx, 0);
}
