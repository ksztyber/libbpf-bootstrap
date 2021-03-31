#ifndef NVMF_BPF_H
#define NVMF_BPF_H

/* This structure is bound to the socket representing an incoming connection.  The eBPF programs
 * uses it tie the incoming sk_buff with the two (ctrl/data) sockets.
 */
struct nvmf_sk_redirect {
	/* Control/data socket indices within the sock_map */
	int ctrl_idx;
	int data_idx;
	/* Index of the socket (ctrl/data) to send the current chunk to */
	int current_idx;
	/* Properties of the currently parsed PDU */
	uint32_t pdu_len;
	uint32_t pdu_headlen;
	uint32_t pdu_offset;
};

#endif
