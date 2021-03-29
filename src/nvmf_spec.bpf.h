#ifndef NVMF_BPF_SPEC_H
#define NVMF_BPF_SPEC_H

/*
 * Most of these definitions are copied from SPDK.
 */

/** NVMe/TCP PDU type */
enum nvmf_tcp_pdu_type {
	/** Initialize Connection Request (ICReq) */
	NVMF_TCP_PDU_TYPE_IC_REQ		= 0x00,

	/** Initialize Connection Response (ICResp) */
	NVMF_TCP_PDU_TYPE_IC_RESP		= 0x01,

	/** Terminate Connection Request (TermReq) */
	NVMF_TCP_PDU_TYPE_H2C_TERM_REQ		= 0x02,

	/** Terminate Connection Response (TermResp) */
	NVMF_TCP_PDU_TYPE_C2H_TERM_REQ		= 0x03,

	/** Command Capsule (CapsuleCmd) */
	NVMF_TCP_PDU_TYPE_CAPSULE_CMD		= 0x04,

	/** Response Capsule (CapsuleRsp) */
	NVMF_TCP_PDU_TYPE_CAPSULE_RESP		= 0x05,

	/** Host To Controller Data (H2CData) */
	NVMF_TCP_PDU_TYPE_H2C_DATA		= 0x06,

	/** Controller To Host Data (C2HData) */
	NVMF_TCP_PDU_TYPE_C2H_DATA		= 0x07,

	/** Ready to Transfer (R2T) */
	NVMF_TCP_PDU_TYPE_R2T			= 0x09,
};

/** Common NVMe/TCP PDU header */
struct nvmf_tcp_common_pdu_hdr {
	/** PDU type (\ref spdk_nvme_tcp_pdu_type) */
	uint8_t				pdu_type;

	/** pdu_type-specific flags */
	uint8_t				flags;

	/** Length of PDU header (not including the Header Digest) */
	uint8_t				hlen;

	/** PDU Data Offset from the start of the PDU */
	uint8_t				pdo;

	/** Total number of bytes in PDU, including pdu_hdr */
	uint32_t			plen;
} __attribute__((packed));

#endif
