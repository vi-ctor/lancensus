/* SPDX-License-Identifier: MIT */
/* Event layout shared by the BPF program and the userspace loader. */
#ifndef LANCENSUS_H
#define LANCENSUS_H

#include <linux/types.h>

#define LC_MAX_PAYLOAD 1500   /* bytes of UDP payload copied per packet   */
#define LC_PAYLOAD_BUF 2048   /* power of two: lets the verifier bound it */

struct lc_event {
	__u32 ifindex;
	__u16 vlan;           /* 802.1Q VID, 0 if untagged */
	__u8  family;         /* 4 or 6 */
	__u8  pad;
	__u8  src_mac[6];
	__u16 sport;          /* host byte order */
	__u16 dport;          /* host byte order */
	__u16 payload_len;
	__u8  src_ip[16];     /* IPv4 uses the first 4 bytes */
	__u8  payload[LC_PAYLOAD_BUF];
};

#endif
