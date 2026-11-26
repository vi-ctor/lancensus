// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * lancensus: tc ingress classifier.
 *
 * Passive by design: every path returns TC_ACT_OK, nothing is dropped,
 * rewritten or sent. The kernel side only does the cheap part: find UDP
 * discovery traffic (mDNS 5353, SSDP 1900, DHCP client->server 68->67)
 * and hand the payload to userspace through a ring buffer. Parsing the
 * protocols happens in userspace where it is easy to test and fuzz.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lancensus.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

struct vlan_tag {
	__be16 tci;
	__be16 proto;
};

static __always_inline int wanted(__u16 sport, __u16 dport)
{
	return sport == 5353 || dport == 5353 ||
	       sport == 1900 || dport == 1900 ||
	       (sport == 68 && dport == 67);
}

SEC("tc")
int lancensus_ingress(struct __sk_buff *skb)
{
	struct ethhdr eth;
	struct udphdr udp;
	struct lc_event *e;
	__u8 family, saddr[16] = {};
	__u32 off = sizeof(eth), l4off, n, avail;
	__u16 proto, vlan = 0, sport, dport, ulen;

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_OK;
	proto = bpf_ntohs(eth.h_proto);

	/* VLAN tag: usually offloaded into skb metadata, sometimes in-band. */
	if (skb->vlan_present)
		vlan = skb->vlan_tci & 0x0fff;
	if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
		struct vlan_tag vt;

		if (bpf_skb_load_bytes(skb, off, &vt, sizeof(vt)) < 0)
			return TC_ACT_OK;
		vlan = bpf_ntohs(vt.tci) & 0x0fff;
		proto = bpf_ntohs(vt.proto);
		off += sizeof(vt);
	}

	if (proto == ETH_P_IP) {
		struct iphdr ip;

		if (bpf_skb_load_bytes(skb, off, &ip, sizeof(ip)) < 0)
			return TC_ACT_OK;
		if (ip.protocol != IPPROTO_UDP || ip.ihl < 5)
			return TC_ACT_OK;
		if (ip.frag_off & bpf_htons(0x3fff))   /* MF or offset: skip fragments */
			return TC_ACT_OK;
		family = 4;
		__builtin_memcpy(saddr, &ip.saddr, 4);
		l4off = off + ip.ihl * 4;
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;

		if (bpf_skb_load_bytes(skb, off, &ip6, sizeof(ip6)) < 0)
			return TC_ACT_OK;
		if (ip6.nexthdr != IPPROTO_UDP)        /* no extension-header walk (yet) */
			return TC_ACT_OK;
		family = 6;
		__builtin_memcpy(saddr, &ip6.saddr, 16);
		l4off = off + sizeof(ip6);
	} else {
		return TC_ACT_OK;
	}

	if (bpf_skb_load_bytes(skb, l4off, &udp, sizeof(udp)) < 0)
		return TC_ACT_OK;
	sport = bpf_ntohs(udp.source);
	dport = bpf_ntohs(udp.dest);
	if (!wanted(sport, dport))
		return TC_ACT_OK;

	ulen = bpf_ntohs(udp.len);
	n = ulen > sizeof(udp) ? ulen - sizeof(udp) : 0;
	avail = skb->len > l4off + sizeof(udp) ? skb->len - l4off - sizeof(udp) : 0;
	if (n > avail)
		n = avail;
	if (n > LC_MAX_PAYLOAD)
		n = LC_MAX_PAYLOAD;
	if (n == 0)
		return TC_ACT_OK;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return TC_ACT_OK;

	e->ifindex = skb->ifindex;
	e->vlan = vlan;
	e->family = family;
	e->pad = 0;
	__builtin_memcpy(e->src_mac, eth.h_source, 6);
	__builtin_memcpy(e->src_ip, saddr, 16);
	e->sport = sport;
	e->dport = dport;
	e->payload_len = 0;
	/* n is already in [1, LC_MAX_PAYLOAD]; this keeps the value but gives the
	 * verifier a bound of [1, LC_PAYLOAD_BUF] on the exact register it checks
	 * (clang may otherwise test one copy of n and pass another). */
	n = ((n - 1) & (LC_PAYLOAD_BUF - 1)) + 1;
	if (bpf_skb_load_bytes(skb, l4off + sizeof(udp), e->payload, n) == 0)
		e->payload_len = n;

	bpf_ringbuf_submit(e, 0);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
