// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

#include "capture.h"
#include "eth.h"
#include "graph.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "l4.h"
#include "lisp.h"
#include "mbuf.h"
#include "nat_datapath.h"
#include "rxtx.h"

#include <gr_lisp.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_udp.h>

#include <netinet/in.h>
#include <string.h>

enum {
	IP_INPUT = 0,
	IP6_INPUT,
	NO_TUNNEL,
	BAD_LENGTH,
	BAD_FLAGS,
	BAD_RLOC,
	UNKNOWN_RLOC,
	UNKNOWN_EID,
	BAD_VERSION,
	ECN_DROP,
	IFACE_DOWN,
	EDGE_COUNT,
};

int trace_lisp_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_lisp_data *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	size_t n = 0;

	SAFE_BUF(snprintf, len, "iid=%u", t->iid);
	if (t->rloc.af != GR_AF_UNSPEC)
		SAFE_BUF(snprintf, len, " rloc=" ADDR_F, ADDR_W(t->rloc.af), &t->rloc.addr);
	if (t->iface_id != GR_IFACE_ID_UNDEF)
		SAFE_BUF(snprintf, len, " iface=%s", iface ? iface->name : "[deleted]");

	return n;
err:
	return -1;
}

// RFC 6040 section 4.2. Return -1 when the packet must be dropped.
static inline int lisp_decap_tos(uint8_t inner, uint8_t outer) {
	uint8_t ecn = IPTOS_ECN(inner);

	switch (IPTOS_ECN(outer)) {
	case IPTOS_ECN_CE:
		if (ecn == IPTOS_ECN_NOT_ECT)
			return -1;
		ecn = IPTOS_ECN_CE;
		break;
	case IPTOS_ECN_ECT1:
		if (ecn == IPTOS_ECN_ECT0)
			ecn = IPTOS_ECN_ECT1;
		break;
	}

	return (outer & ~IPTOS_ECN_MASK) | ecn;
}

static inline rte_be16_t hdr_word(const void *field) {
	rte_be16_t word;
	memcpy(&word, field, sizeof(word));
	return word;
}

static inline int lisp_decap_ip4(struct rte_ipv4_hdr *ip, uint8_t outer_tos, uint8_t outer_ttl) {
	rte_be16_t old;
	int tos;

	tos = lisp_decap_tos(ip->type_of_service, outer_tos);
	if (tos < 0)
		return -1;

	if (tos != ip->type_of_service) {
		old = hdr_word(&ip->version_ihl);
		ip->type_of_service = tos;
		ip->hdr_checksum = fixup_checksum_16(
			ip->hdr_checksum, old, hdr_word(&ip->version_ihl)
		);
	}
	if (outer_ttl < ip->time_to_live) {
		old = hdr_word(&ip->time_to_live);
		ip->time_to_live = outer_ttl;
		ip->hdr_checksum = fixup_checksum_16(
			ip->hdr_checksum, old, hdr_word(&ip->time_to_live)
		);
	}

	return 0;
}

static inline int lisp_decap_ip6(struct rte_ipv6_hdr *ip, uint8_t outer_tos, uint8_t outer_ttl) {
	uint32_t vtc_flow = rte_be_to_cpu_32(ip->vtc_flow);
	int tos;

	tos = lisp_decap_tos((vtc_flow & RTE_IPV6_HDR_TC_MASK) >> RTE_IPV6_HDR_TC_SHIFT, outer_tos);
	if (tos < 0)
		return -1;

	vtc_flow &= ~RTE_IPV6_HDR_TC_MASK;
	vtc_flow |= (uint32_t)tos << RTE_IPV6_HDR_TC_SHIFT;
	ip->vtc_flow = rte_cpu_to_be_32(vtc_flow);
	if (outer_ttl < ip->hop_limits)
		ip->hop_limits = outer_ttl;

	return 0;
}

static inline bool
lisp_nh_is_rloc(const struct nexthop *nh, const struct iface *iface, const struct l3_addr *rloc) {
	return nh->type == GR_NH_T_LISP && nh->iface_id == iface->id
		&& l3_addr_eq(&nexthop_info_lisp(nh)->rloc, rloc);
}

// Get the nexthop of the mapping of the inner source that has the RLOC the packet comes from.
static inline const struct nexthop *lisp_eid_lookup(
	const struct iface *iface,
	const struct rte_mbuf *m,
	rte_edge_t edge,
	const struct l3_addr *rloc
) {
	const struct nexthop *nh, *member;

	if (edge == IP_INPUT) {
		const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, const void *);
		nh = fib4_lookup_raw(iface->vrf_id, ip->src_addr);
	} else {
		const struct rte_ipv6_hdr *ip = rte_pktmbuf_mtod(m, const void *);
		nh = fib6_lookup_raw(iface->vrf_id, GR_IFACE_ID_UNDEF, &ip->src_addr);
	}
	if (nh == NULL)
		return NULL;

	if (nh->type != GR_NH_T_GROUP)
		return lisp_nh_is_rloc(nh, iface, rloc) ? nh : NULL;

	nexthop_group_foreach (member, nexthop_info_group(nh)) {
		if (lisp_nh_is_rloc(member, iface, rloc))
			return member;
	}

	return NULL;
}

static uint16_t
lisp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct nexthop *peer, *last_peer;
	const struct iface *last_peer_iface;
	const struct iface_info_lisp *lisp;
	struct l3_addr rloc, last_rloc;
	struct eth_input_mbuf_data *e;
	uint16_t vrf_id, last_vrf_id;
	uint8_t outer_tos, outer_ttl;
	const struct lisp_hdr *lh;
	uint32_t iid, last_iid;
	struct iface *iface;
	struct rte_mbuf *m;
	rte_edge_t edge;
	bool local;

	IFACE_STATS_VARS(rx, self);

	last_vrf_id = GR_VRF_ID_UNDEF;
	last_peer_iface = NULL;
	last_peer = NULL;
	last_iid = 0;
	iface = NULL;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		rloc.af = GR_AF_UNSPEC;
		lisp = NULL;
		iid = 0;

		if (rte_pktmbuf_data_len(m) < LISP_ENCAP_LEN + sizeof(struct rte_ipv4_hdr)) {
			edge = BAD_LENGTH;
			goto next;
		}

		lh = rte_pktmbuf_mtod_offset(
			m, const struct lisp_hdr *, sizeof(struct rte_udp_hdr)
		);
		if (lh->flags & LISP_F_KK) {
			edge = BAD_FLAGS;
			goto next;
		}
		if (lh->flags & LISP_F_I)
			iid = lisp_decode_iid(lh->iid_lsb);

		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			const struct ip_local_mbuf_data *d = ip_local_mbuf_data(m);
			vrf_id = d->vrf_id;
			outer_tos = d->tos;
			outer_ttl = d->ttl;
			rloc.af = GR_AF_IP4;
			rloc.ipv4 = d->src;
		} else {
			const struct ip6_local_mbuf_data *d = ip6_local_mbuf_data(m);
			vrf_id = d->iface->vrf_id;
			outer_tos = d->tc;
			outer_ttl = d->hop_limit;
			rloc.af = GR_AF_IP6;
			rloc.ipv6 = d->src;
		}

		if (iid != last_iid || vrf_id != last_vrf_id || iface == NULL) {
			iface = lisp_get_iface(iid, vrf_id);
			last_vrf_id = vrf_id;
			last_iid = iid;
		}
		if (iface == NULL) {
			edge = NO_TUNNEL;
			goto next;
		}
		if (!(iface->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}

		lisp = iface_info_lisp(iface);
		if (rloc.af == GR_AF_IP4)
			local = ip_local_mbuf_data(m)->dst == lisp->local;
		else
			local = rte_ipv6_addr_eq(&ip6_local_mbuf_data(m)->dst, &lisp->local6);
		if (!local) {
			edge = BAD_RLOC;
			goto next;
		}

		peer = NULL;
		if (lisp->rloc_filter || (lisp->n_stats != 0 && !lisp->eid_filter)) {
			if (iface != last_peer_iface || !l3_addr_eq(&rloc, &last_rloc)) {
				last_peer = lisp_rloc_lookup(iface->id, &rloc);
				last_peer_iface = iface;
				last_rloc = rloc;
			}
			peer = last_peer;
			if (peer == NULL && lisp->rloc_filter) {
				edge = UNKNOWN_RLOC;
				goto next;
			}
		}

		rte_pktmbuf_adj(m, LISP_ENCAP_LEN);

		switch (rte_pktmbuf_mtod(m, const struct rte_ipv4_hdr *)->version) {
		case IPVERSION:
			if (lisp_decap_ip4(rte_pktmbuf_mtod(m, void *), outer_tos, outer_ttl) < 0) {
				edge = ECN_DROP;
				goto next;
			}
			edge = IP_INPUT;
			break;
		case IP6_VERSION:
			if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ipv6_hdr)) {
				edge = BAD_LENGTH;
				goto next;
			}
			if (lisp_decap_ip6(rte_pktmbuf_mtod(m, void *), outer_tos, outer_ttl) < 0) {
				edge = ECN_DROP;
				goto next;
			}
			edge = IP6_INPUT;
			break;
		default:
			edge = BAD_VERSION;
			goto next;
		}

		if (lisp->eid_filter) {
			peer = lisp_eid_lookup(iface, m, edge, &rloc);
			if (peer == NULL) {
				edge = UNKNOWN_EID;
				goto next;
			}
		}

		m->ol_flags &= ~(RTE_MBUF_F_RX_IP_CKSUM_MASK | RTE_MBUF_F_RX_L4_CKSUM_MASK);
		m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_NONE | RTE_MBUF_F_RX_L4_CKSUM_NONE;

		IFACE_STATS_INC(rx, self, m, iface);
		if (peer != NULL)
			nexthop_stats_rx(peer, m);
		if (unlikely(iface->flags & GR_IFACE_F_CAPTURE)) {
			// capture_enqueue() reads a VLAN ID from the mbuf private data
			iface_mbuf_data(m)->vlan_id = 0;
			capture_enqueue(iface, GR_CAPTURE_DIR_IN, m);
		}

		e = eth_input_mbuf_data(m);
		e->iface = iface;
		e->domain = ETH_DOMAIN_LOCAL;
		e->nh = NULL;
next:
		if (gr_mbuf_is_traced(m) || (lisp && iface->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct trace_lisp_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->iid = iid;
			t->iface_id = lisp ? iface->id : GR_IFACE_ID_UNDEF;
			t->rloc = rloc;
		}
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	IFACE_STATS_FLUSH(rx, self);

	return nb_objs;
}

static void lisp_input_register(void) {
	l4_input_register_port(IPPROTO_UDP, RTE_BE16(GR_LISP_DATA_PORT), "lisp_input");
	ip6_input_local_udp_zero_cksum_allow(RTE_BE16(GR_LISP_DATA_PORT));
}

static struct rte_node_register lisp_input_node = {
	.name = "lisp_input",

	.process = lisp_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[NO_TUNNEL] = "lisp_input_no_tunnel",
		[BAD_LENGTH] = "lisp_input_bad_length",
		[BAD_FLAGS] = "lisp_input_bad_flags",
		[BAD_RLOC] = "lisp_input_bad_rloc",
		[UNKNOWN_RLOC] = "lisp_input_unknown_rloc",
		[UNKNOWN_EID] = "lisp_input_unknown_eid",
		[BAD_VERSION] = "lisp_input_bad_version",
		[ECN_DROP] = "lisp_input_ecn_drop",
		[IFACE_DOWN] = "iface_input_admin_down",
	},
};

static struct gr_node_info lisp_input_info = {
	.node = &lisp_input_node,
	.type = GR_NODE_T_L3,
	.register_callback = lisp_input_register,
	.trace_format = trace_lisp_format,
};

GR_NODE_REGISTER(lisp_input_info);

GR_DROP_REGISTER(lisp_input_no_tunnel);
GR_DROP_REGISTER(lisp_input_bad_length);
GR_DROP_REGISTER(lisp_input_bad_flags);
GR_DROP_REGISTER(lisp_input_bad_rloc);
GR_DROP_REGISTER(lisp_input_unknown_rloc);
GR_DROP_REGISTER(lisp_input_unknown_eid);
GR_DROP_REGISTER(lisp_input_bad_version);
GR_DROP_REGISTER(lisp_input_ecn_drop);

#ifdef __GROUT_UNIT_TEST__
#include "_cmocka.h"

#include <stdlib.h>

struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
struct iface_stats (*iface_stats)[RTE_MAX_LCORE];
struct nexthop_stats *nexthop_stats[RTE_MAX_LCORE];
_Atomic(struct capture_session *) *iface_capture;
__thread gr_wallclock_ns_t wallclock_snapshot_ns = 1;
__thread bool clock_trusted = true;
uint64_t capture_dynflag;
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(void, l4_input_register_port(uint8_t, rte_be16_t, const char *));
mock_func(void, ip6_input_local_udp_zero_cksum_allow(rte_be16_t));
mock_func(struct iface *, iface_from_id(uint16_t));

struct iface *lisp_get_iface(uint32_t iid, uint16_t encap_vrf_id) {
	check_expected_uint(iid);
	check_expected_uint(encap_vrf_id);
	return (struct iface *)mock();
}

const struct nexthop *fib4_lookup_raw(uint16_t vrf_id, ip4_addr_t ip) {
	check_expected_uint(vrf_id);
	check_expected_uint(ip);
	return (const struct nexthop *)mock();
}

const struct nexthop *
fib6_lookup_raw(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	check_expected_uint(vrf_id);
	check_expected_uint(iface_id);
	check_expected_ptr(ip);
	return (const struct nexthop *)mock();
}

static struct l3_addr looked_up_rloc;

struct nexthop *lisp_rloc_lookup(uint16_t iface_id, const struct l3_addr *rloc) {
	check_expected_uint(iface_id);
	looked_up_rloc = *rloc;
	return (struct nexthop *)mock();
}

#define TEST_IID 101
#define TEST_EID_VRF 3
#define TEST_RLOC_VRF 2
#define TEST_LOCAL RTE_IPV4(192, 0, 2, 1)
#define TEST_REMOTE RTE_IPV4(192, 0, 2, 5)
#define TEST_LOCAL_EID RTE_IPV4(10, 1, 0, 2)
#define TEST_REMOTE_EID RTE_IPV4(10, 2, 0, 2)
#define TEST_SRC_PORT 50000
#define TEST_INNER_TTL 64
#define TEST_OUTER_TTL 60
#define TEST_LOW_TTL 2
#define TEST_FLOW_LABEL 0x12345
#define TEST_PAYLOAD_LEN 16
#define TEST_STATS_ID 1

static const struct rte_ipv6_addr test_local6 = RTE_IPV6(0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 1);
static const struct rte_ipv6_addr test_remote6 = RTE_IPV6(0x2001, 0xdb8, 0xb, 0, 0, 0, 0, 1);
static const struct rte_ipv6_addr test_remote_eid6 = RTE_IPV6(0xfd00, 2, 0, 0, 0, 0, 0, 2);

struct fake_mbuf {
	struct rte_udp_hdr udp;
	struct lisp_hdr lisp;
	union {
		struct rte_ipv4_hdr ip4;
		struct rte_ipv6_hdr ip6;
	};
	uint8_t payload[TEST_PAYLOAD_LEN];
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static alignas(
	RTE_CACHE_LINE_SIZE
) uint8_t lisp_iface_buf[sizeof(struct iface) + sizeof(struct iface_info_lisp)];
static struct iface *const lisp_iface = (struct iface *)lisp_iface_buf;
static struct nexthop_stats test_nh_stats[TEST_STATS_ID + 1];
static struct nexthop rloc_nh;
static struct iface port_iface;

static int setup(void **) {
	struct iface_info_lisp *lisp;

	memset(lisp_iface_buf, 0, sizeof(lisp_iface_buf));
	lisp_iface->type = GR_IFACE_TYPE_LISP;
	lisp_iface->id = 1;
	lisp_iface->flags = GR_IFACE_F_UP;
	lisp_iface->vrf_id = TEST_EID_VRF;
	lisp = iface_info_lisp(lisp_iface);
	lisp->iid = TEST_IID;
	lisp->encap_vrf_id = TEST_RLOC_VRF;
	lisp->local = RTE_BE32(TEST_LOCAL);
	lisp->local6 = test_local6;

	port_iface.vrf_id = TEST_RLOC_VRF;

	memset(test_nh_stats, 0, sizeof(test_nh_stats));
	nexthop_stats[0] = test_nh_stats;
	memset(&rloc_nh, 0, sizeof(rloc_nh));
	rloc_nh.type = GR_NH_T_LISP;
	rloc_nh.iface_id = lisp_iface->id;
	rloc_nh.stats_id = TEST_STATS_ID;
	nexthop_info_lisp(&rloc_nh)->rloc.af = GR_AF_IP4;
	nexthop_info_lisp(&rloc_nh)->rloc.ipv4 = RTE_BE32(TEST_REMOTE);
	memset(&looked_up_rloc, 0, sizeof(looked_up_rloc));

	free(iface_stats);
	iface_stats = calloc(2, sizeof(*iface_stats));
	RTE_PER_LCORE(_lcore_id) = 0;

	return iface_stats == NULL ? -1 : 0;
}

static void fake_mbuf_init(struct fake_mbuf *fm) {
	struct ip_local_mbuf_data *d;

	memset(fm, 0, sizeof(*fm));

	fm->udp.src_port = RTE_BE16(TEST_SRC_PORT);
	fm->udp.dst_port = RTE_BE16(GR_LISP_DATA_PORT);
	fm->lisp.flags = LISP_F_I;
	fm->lisp.iid_lsb = lisp_encode_iid(TEST_IID);

	fm->ip4.version_ihl = IPV4_VERSION_IHL;
	fm->ip4.total_length = rte_cpu_to_be_16(sizeof(fm->ip4) + sizeof(fm->payload));
	fm->ip4.time_to_live = TEST_INNER_TTL;
	fm->ip4.next_proto_id = IPPROTO_RAW;
	fm->ip4.src_addr = RTE_BE32(TEST_REMOTE_EID);
	fm->ip4.dst_addr = RTE_BE32(TEST_LOCAL_EID);
	fm->ip4.hdr_checksum = rte_ipv4_cksum(&fm->ip4);

	fm->mbuf.buf_addr = &fm->udp;
	fm->mbuf.data_len = LISP_ENCAP_LEN + sizeof(fm->ip4) + sizeof(fm->payload);
	fm->mbuf.pkt_len = fm->mbuf.data_len;
	fm->mbuf.nb_segs = 1;
	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV4;
	fm->mbuf.ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD;

	d = ip_local_mbuf_data(&fm->mbuf);
	d->iface = &port_iface;
	d->src = RTE_BE32(TEST_REMOTE);
	d->dst = RTE_BE32(TEST_LOCAL);
	d->vrf_id = TEST_RLOC_VRF;
	d->proto = IPPROTO_UDP;
	d->ttl = TEST_OUTER_TTL;
	d->tos = 0;
}

static void fake_mbuf_outer6(struct fake_mbuf *fm, uint8_t tc) {
	struct ip6_local_mbuf_data *d;

	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV6;
	d = ip6_local_mbuf_data(&fm->mbuf);
	memset(d, 0, sizeof(*d));
	d->iface = &port_iface;
	d->src = test_remote6;
	d->dst = test_local6;
	d->proto = IPPROTO_UDP;
	d->hop_limit = TEST_OUTER_TTL;
	d->tc = tc;
}

static void fake_mbuf_inner6(struct fake_mbuf *fm, uint8_t tc) {
	memset(&fm->ip6, 0, sizeof(fm->ip6));
	fm->ip6.vtc_flow = rte_cpu_to_be_32(
		(IP6_VERSION << IP6_VERSION_SHIFT) | (tc << RTE_IPV6_HDR_TC_SHIFT) | TEST_FLOW_LABEL
	);
	fm->ip6.payload_len = rte_cpu_to_be_16(sizeof(fm->payload));
	fm->ip6.proto = IPPROTO_RAW;
	fm->ip6.hop_limits = TEST_INNER_TTL;
	fm->mbuf.data_len = LISP_ENCAP_LEN + sizeof(fm->ip6) + sizeof(fm->payload);
	fm->mbuf.pkt_len = fm->mbuf.data_len;
}

static void expect_lookup(uint32_t iid, struct iface *iface) {
	expect_uint_value(lisp_get_iface, iid, iid);
	expect_uint_value(lisp_get_iface, encap_vrf_id, TEST_RLOC_VRF);
	will_return(lisp_get_iface, iface);
}

static void expect_drop(struct fake_mbuf *fm, rte_edge_t edge) {
	void *obj = &fm->mbuf;

	expect_uint_value(rte_node_enqueue_x1, next, edge);
	lisp_input_process(NULL, NULL, &obj, 1);
}

static void expect_decap(struct fake_mbuf *fm, rte_edge_t edge) {
	expect_lookup(TEST_IID, lisp_iface);
	expect_drop(fm, edge);
}

static void expect_rloc_lookup(struct nexthop *nh) {
	expect_uint_value(lisp_rloc_lookup, iface_id, lisp_iface->id);
	will_return(lisp_rloc_lookup, nh);
}

static void assert_nh_stats(uint64_t packets, uint64_t bytes) {
	assert_int_equal(test_nh_stats[TEST_STATS_ID].rx_packets, packets);
	assert_int_equal(test_nh_stats[TEST_STATS_ID].rx_bytes, bytes);
}

static void lisp_input_ip4(void **) {
	const struct eth_input_mbuf_data *e;
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	expect_decap(&fm, IP_INPUT);

	assert_ptr_equal(rte_pktmbuf_mtod(&fm.mbuf, void *), &fm.ip4);
	assert_int_equal(fm.mbuf.pkt_len, sizeof(fm.ip4) + sizeof(fm.payload));
	e = eth_input_mbuf_data(&fm.mbuf);
	assert_ptr_equal(e->iface, lisp_iface);
	assert_int_equal(e->domain, ETH_DOMAIN_LOCAL);
	assert_null(e->nh);
	assert_int_equal(
		fm.mbuf.ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK, RTE_MBUF_F_RX_IP_CKSUM_NONE
	);
	assert_int_equal(
		fm.mbuf.ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK, RTE_MBUF_F_RX_L4_CKSUM_NONE
	);
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 1);
	assert_int_equal(
		iface_get_stats(0, lisp_iface->id)->rx_bytes, sizeof(fm.ip4) + sizeof(fm.payload)
	);
}

static void lisp_input_ip6(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm, 0);
	expect_decap(&fm, IP6_INPUT);

	assert_ptr_equal(rte_pktmbuf_mtod(&fm.mbuf, void *), &fm.ip6);
	assert_ptr_equal(eth_input_mbuf_data(&fm.mbuf)->iface, lisp_iface);
}

static void lisp_input_outer6(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fake_mbuf_outer6(&fm, 0);
	expect_decap(&fm, IP_INPUT);

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm, 0);
	fake_mbuf_outer6(&fm, 0);
	expect_decap(&fm, IP6_INPUT);
}

static void lisp_input_no_iid(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.lisp.flags = 0;
	expect_lookup(0, NULL);
	expect_drop(&fm, NO_TUNNEL);
}

static void lisp_input_unknown_iid(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.lisp.iid_lsb = lisp_encode_iid(GR_LISP_IID_MAX);
	expect_lookup(GR_LISP_IID_MAX, NULL);
	expect_drop(&fm, NO_TUNNEL);
}

static void lisp_input_ignored_flags(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.lisp.flags = LISP_F_N | LISP_F_L | LISP_F_E | LISP_F_V | LISP_F_I | LISP_F_R;
	memset(fm.lisp.nonce, UINT8_MAX, sizeof(fm.lisp.nonce));
	fm.lisp.iid_lsb = lisp_encode_iid(TEST_IID) | RTE_BE32(UINT8_MAX);
	expect_decap(&fm, IP_INPUT);
}

static void lisp_input_encrypted(void **) {
	struct fake_mbuf fm;

	for (uint8_t kk = 1; kk <= LISP_F_KK; kk++) {
		fake_mbuf_init(&fm);
		fm.lisp.flags |= kk;
		expect_drop(&fm, BAD_FLAGS);
	}
}

static void lisp_input_too_short(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.mbuf.data_len = fm.mbuf.pkt_len = LISP_ENCAP_LEN + sizeof(fm.ip4) - 1;
	expect_drop(&fm, BAD_LENGTH);

	fake_mbuf_init(&fm);
	fm.mbuf.data_len = LISP_ENCAP_LEN;
	fm.mbuf.nb_segs = 2;
	expect_drop(&fm, BAD_LENGTH);

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm, 0);
	fm.mbuf.data_len = fm.mbuf.pkt_len = LISP_ENCAP_LEN + sizeof(fm.ip6) - 1;
	expect_decap(&fm, BAD_LENGTH);
}

static void lisp_input_bad_version(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.ip4.version = IP6_VERSION + 1;
	expect_decap(&fm, BAD_VERSION);
}

static void lisp_input_bad_rloc(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	ip_local_mbuf_data(&fm.mbuf)->dst = RTE_BE32(TEST_REMOTE);
	expect_decap(&fm, BAD_RLOC);

	fake_mbuf_init(&fm);
	fake_mbuf_outer6(&fm, 0);
	ip6_local_mbuf_data(&fm.mbuf)->dst = test_remote6;
	expect_decap(&fm, BAD_RLOC);

	iface_info_lisp(lisp_iface)->local = 0;
	fake_mbuf_init(&fm);
	expect_decap(&fm, BAD_RLOC);
}

static void lisp_input_iface_down(void **) {
	struct fake_mbuf fm;

	lisp_iface->flags &= ~GR_IFACE_F_UP;
	fake_mbuf_init(&fm);
	expect_decap(&fm, IFACE_DOWN);
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 0);
}

static void lisp_input_burst(void **) {
	struct fake_mbuf fm[3];
	void *objs[3];

	for (unsigned i = 0; i < ARRAY_DIM(fm); i++) {
		fake_mbuf_init(&fm[i]);
		objs[i] = &fm[i].mbuf;
	}
	fm[2].lisp.iid_lsb = lisp_encode_iid(TEST_IID + 1);

	expect_lookup(TEST_IID, lisp_iface);
	expect_uint_value(rte_node_enqueue_x1, next, IP_INPUT);
	expect_uint_value(rte_node_enqueue_x1, next, IP_INPUT);
	expect_lookup(TEST_IID + 1, NULL);
	expect_uint_value(rte_node_enqueue_x1, next, NO_TUNNEL);
	lisp_input_process(NULL, NULL, objs, ARRAY_DIM(objs));

	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 2);
}

static void lisp_input_rloc_stats(void **) {
	const struct l3_addr remote4 = {.af = GR_AF_IP4, .ipv4 = RTE_BE32(TEST_REMOTE)};
	const struct l3_addr remote6 = {.af = GR_AF_IP6, .ipv6 = test_remote6};
	struct fake_mbuf fm;

	// Without counted nexthop, the source is not looked up.
	fake_mbuf_init(&fm);
	expect_decap(&fm, IP_INPUT);
	assert_nh_stats(0, 0);

	iface_info_lisp(lisp_iface)->n_stats = 1;
	fake_mbuf_init(&fm);
	expect_rloc_lookup(&rloc_nh);
	expect_decap(&fm, IP_INPUT);
	assert_true(l3_addr_eq(&looked_up_rloc, &remote4));
	assert_nh_stats(1, sizeof(fm.ip4) + sizeof(fm.payload));

	// A source which is not the RLOC of a nexthop is accepted, not counted.
	fake_mbuf_init(&fm);
	fake_mbuf_outer6(&fm, 0);
	expect_rloc_lookup(NULL);
	expect_decap(&fm, IP_INPUT);
	assert_true(l3_addr_eq(&looked_up_rloc, &remote6));
	assert_nh_stats(1, sizeof(fm.ip4) + sizeof(fm.payload));
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 3);

	// A dropped packet is not counted.
	fake_mbuf_init(&fm);
	fm.ip4.version_ihl = 0;
	expect_rloc_lookup(&rloc_nh);
	expect_decap(&fm, BAD_VERSION);
	assert_nh_stats(1, sizeof(fm.ip4) + sizeof(fm.payload));
}

static void lisp_input_rloc_filter(void **) {
	struct fake_mbuf fm;

	iface_info_lisp(lisp_iface)->rloc_filter = true;

	fake_mbuf_init(&fm);
	expect_rloc_lookup(NULL);
	expect_decap(&fm, UNKNOWN_RLOC);
	assert_int_equal(fm.mbuf.pkt_len, fm.mbuf.data_len);
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 0);

	// The nexthop of the source does not need to have stats.
	rloc_nh.stats_id = 0;
	fake_mbuf_init(&fm);
	expect_rloc_lookup(&rloc_nh);
	expect_decap(&fm, IP_INPUT);
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 1);
	assert_nh_stats(0, 0);
}

static void lisp_input_rloc_burst(void **) {
	struct fake_mbuf fm[3];
	void *objs[3];

	iface_info_lisp(lisp_iface)->n_stats = 1;
	for (unsigned i = 0; i < ARRAY_DIM(fm); i++) {
		fake_mbuf_init(&fm[i]);
		objs[i] = &fm[i].mbuf;
	}
	fake_mbuf_outer6(&fm[2], 0);

	// One lookup for the consecutive packets of the same source.
	expect_lookup(TEST_IID, lisp_iface);
	expect_rloc_lookup(&rloc_nh);
	expect_uint_value(rte_node_enqueue_x1, next, IP_INPUT);
	expect_uint_value(rte_node_enqueue_x1, next, IP_INPUT);
	expect_rloc_lookup(NULL);
	expect_uint_value(rte_node_enqueue_x1, next, IP_INPUT);
	lisp_input_process(NULL, NULL, objs, ARRAY_DIM(objs));

	assert_nh_stats(2, 2 * (sizeof(fm[0].ip4) + sizeof(fm[0].payload)));
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 3);
}

static void expect_eid4(const struct nexthop *nh) {
	expect_uint_value(fib4_lookup_raw, vrf_id, TEST_EID_VRF);
	expect_uint_value(fib4_lookup_raw, ip, RTE_BE32(TEST_REMOTE_EID));
	will_return(fib4_lookup_raw, nh);
}

static void lisp_input_eid_filter(void **) {
	const uint64_t inner_len = sizeof(struct rte_ipv4_hdr) + TEST_PAYLOAD_LEN;
	struct nexthop other_rloc_nh, other_iface_nh, l3_nh;
	struct fake_mbuf fm;

	other_rloc_nh = rloc_nh;
	nexthop_info_lisp(&other_rloc_nh)->rloc.ipv4 = RTE_BE32(TEST_LOCAL);
	other_iface_nh = rloc_nh;
	other_iface_nh.iface_id = lisp_iface->id + 1;
	memset(&l3_nh, 0, sizeof(l3_nh));
	l3_nh.type = GR_NH_T_L3;

	// The RLOC index is not used, even with counted nexthops.
	iface_info_lisp(lisp_iface)->eid_filter = true;
	iface_info_lisp(lisp_iface)->n_stats = 1;

	fake_mbuf_init(&fm);
	expect_eid4(&rloc_nh);
	expect_decap(&fm, IP_INPUT);
	assert_nh_stats(1, inner_len);

	// No mapping, a route that is not a mapping, another RLOC, another interface.
	const struct nexthop *mismatch[] = {NULL, &l3_nh, &other_rloc_nh, &other_iface_nh};
	for (unsigned i = 0; i < ARRAY_DIM(mismatch); i++) {
		fake_mbuf_init(&fm);
		expect_eid4(mismatch[i]);
		expect_decap(&fm, UNKNOWN_EID);
	}
	assert_nh_stats(1, inner_len);
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->rx_packets, 1);

	// An IPv6 source EID.
	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm, 0);
	fm.ip6.src_addr = test_remote_eid6;
	expect_uint_value(fib6_lookup_raw, vrf_id, TEST_EID_VRF);
	expect_uint_value(fib6_lookup_raw, iface_id, GR_IFACE_ID_UNDEF);
	expect_memory(fib6_lookup_raw, ip, &test_remote_eid6, sizeof(test_remote_eid6));
	will_return(fib6_lookup_raw, &rloc_nh);
	expect_decap(&fm, IP6_INPUT);
	assert_nh_stats(2, inner_len + sizeof(struct rte_ipv6_hdr) + TEST_PAYLOAD_LEN);
}

static void lisp_input_eid_filter_group(void **) {
	struct nh_group_member members[3];
	struct nexthop group_nh, other_nh;
	struct fake_mbuf fm;

	other_nh = rloc_nh;
	other_nh.stats_id = 0;
	nexthop_info_lisp(&other_nh)->rloc.ipv4 = RTE_BE32(TEST_LOCAL);

	memset(members, 0, sizeof(members));
	members[0].nh = &other_nh;
	members[1].nh = &rloc_nh;
	memset(&group_nh, 0, sizeof(group_nh));
	group_nh.type = GR_NH_T_GROUP;
	nexthop_info_group(&group_nh)->n_members = 2;
	nexthop_info_group(&group_nh)->members = members;

	iface_info_lisp(lisp_iface)->eid_filter = true;

	// The source RLOC is one of the RLOCs of the mapping.
	fake_mbuf_init(&fm);
	expect_eid4(&group_nh);
	expect_decap(&fm, IP_INPUT);
	assert_nh_stats(1, sizeof(fm.ip4) + sizeof(fm.payload));

	// It is not one of them anymore.
	members[1].nh = NULL;
	fake_mbuf_init(&fm);
	expect_eid4(&group_nh);
	expect_decap(&fm, UNKNOWN_EID);
	assert_nh_stats(1, sizeof(fm.ip4) + sizeof(fm.payload));
}

static void lisp_input_ttl(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	expect_decap(&fm, IP_INPUT);
	assert_int_equal(fm.ip4.time_to_live, TEST_OUTER_TTL);
	assert_int_equal(rte_ipv4_cksum(&fm.ip4), 0);

	fake_mbuf_init(&fm);
	fm.ip4.time_to_live = TEST_LOW_TTL;
	fm.ip4.hdr_checksum = 0;
	fm.ip4.hdr_checksum = rte_ipv4_cksum(&fm.ip4);
	expect_decap(&fm, IP_INPUT);
	assert_int_equal(fm.ip4.time_to_live, TEST_LOW_TTL);
	assert_int_equal(rte_ipv4_cksum(&fm.ip4), 0);

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm, 0);
	expect_decap(&fm, IP6_INPUT);
	assert_int_equal(fm.ip6.hop_limits, TEST_OUTER_TTL);

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm, 0);
	fm.ip6.hop_limits = TEST_LOW_TTL;
	expect_decap(&fm, IP6_INPUT);
	assert_int_equal(fm.ip6.hop_limits, TEST_LOW_TTL);
}

static void lisp_input_keeps_bad_checksum(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.ip4.hdr_checksum = ~fm.ip4.hdr_checksum;
	ip_local_mbuf_data(&fm.mbuf)->tos = IPTOS_DSCP_EF;
	expect_decap(&fm, IP_INPUT);
	assert_int_equal(fm.ip4.time_to_live, TEST_OUTER_TTL);
	assert_int_equal(fm.ip4.type_of_service, IPTOS_DSCP_EF);
	assert_int_not_equal(rte_ipv4_cksum(&fm.ip4), 0);
}

static void lisp_input_dscp(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.ip4.type_of_service = IPTOS_DSCP_AF11;
	fm.ip4.hdr_checksum = 0;
	fm.ip4.hdr_checksum = rte_ipv4_cksum(&fm.ip4);
	ip_local_mbuf_data(&fm.mbuf)->tos = IPTOS_DSCP_EF;
	expect_decap(&fm, IP_INPUT);
	assert_int_equal(fm.ip4.type_of_service, IPTOS_DSCP_EF);
	assert_int_equal(rte_ipv4_cksum(&fm.ip4), 0);

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm, IPTOS_DSCP_AF11);
	fake_mbuf_outer6(&fm, IPTOS_DSCP_EF);
	expect_decap(&fm, IP6_INPUT);
	assert_int_equal(
		rte_be_to_cpu_32(fm.ip6.vtc_flow),
		(IP6_VERSION << IP6_VERSION_SHIFT) | (IPTOS_DSCP_EF << RTE_IPV6_HDR_TC_SHIFT)
			| TEST_FLOW_LABEL
	);
}

// RFC 6040 figure 4: rows are the inner ECN field, columns the outer one.
#define ECN_COUNT (IPTOS_ECN_MASK + 1)
#define NOT_ECT IPTOS_ECN_NOT_ECT
#define ECT1 IPTOS_ECN_ECT1
#define ECT0 IPTOS_ECN_ECT0
#define CE IPTOS_ECN_CE
#define DROP -1
static const int8_t ecn_decap[ECN_COUNT][ECN_COUNT] = {
	[NOT_ECT] = {[NOT_ECT] = NOT_ECT, [ECT1] = NOT_ECT, [ECT0] = NOT_ECT, [CE] = DROP},
	[ECT1] = {[NOT_ECT] = ECT1, [ECT1] = ECT1, [ECT0] = ECT1, [CE] = CE},
	[ECT0] = {[NOT_ECT] = ECT0, [ECT1] = ECT1, [ECT0] = ECT0, [CE] = CE},
	[CE] = {[NOT_ECT] = CE, [ECT1] = CE, [ECT0] = CE, [CE] = CE},
};

static void lisp_input_ecn(void **) {
	struct fake_mbuf fm;

	for (uint8_t inner = 0; inner < ECN_COUNT; inner++) {
		for (uint8_t outer = 0; outer < ECN_COUNT; outer++) {
			int expected = ecn_decap[inner][outer];

			fake_mbuf_init(&fm);
			fm.ip4.type_of_service = inner;
			fm.ip4.hdr_checksum = 0;
			fm.ip4.hdr_checksum = rte_ipv4_cksum(&fm.ip4);
			ip_local_mbuf_data(&fm.mbuf)->tos = outer;
			expect_decap(&fm, expected == DROP ? ECN_DROP : IP_INPUT);
			if (expected != DROP) {
				assert_int_equal(fm.ip4.type_of_service, expected);
				assert_int_equal(rte_ipv4_cksum(&fm.ip4), 0);
			}

			fake_mbuf_init(&fm);
			fake_mbuf_inner6(&fm, inner);
			fake_mbuf_outer6(&fm, outer);
			expect_decap(&fm, expected == DROP ? ECN_DROP : IP6_INPUT);
			if (expected != DROP)
				assert_int_equal(
					(rte_be_to_cpu_32(fm.ip6.vtc_flow) & RTE_IPV6_HDR_TC_MASK)
						>> RTE_IPV6_HDR_TC_SHIFT,
					expected
				);
		}
	}
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(lisp_input_ip4, setup),
		cmocka_unit_test_setup(lisp_input_ip6, setup),
		cmocka_unit_test_setup(lisp_input_outer6, setup),
		cmocka_unit_test_setup(lisp_input_no_iid, setup),
		cmocka_unit_test_setup(lisp_input_unknown_iid, setup),
		cmocka_unit_test_setup(lisp_input_ignored_flags, setup),
		cmocka_unit_test_setup(lisp_input_encrypted, setup),
		cmocka_unit_test_setup(lisp_input_too_short, setup),
		cmocka_unit_test_setup(lisp_input_bad_version, setup),
		cmocka_unit_test_setup(lisp_input_bad_rloc, setup),
		cmocka_unit_test_setup(lisp_input_iface_down, setup),
		cmocka_unit_test_setup(lisp_input_burst, setup),
		cmocka_unit_test_setup(lisp_input_rloc_stats, setup),
		cmocka_unit_test_setup(lisp_input_rloc_filter, setup),
		cmocka_unit_test_setup(lisp_input_rloc_burst, setup),
		cmocka_unit_test_setup(lisp_input_eid_filter, setup),
		cmocka_unit_test_setup(lisp_input_eid_filter_group, setup),
		cmocka_unit_test_setup(lisp_input_ttl, setup),
		cmocka_unit_test_setup(lisp_input_keeps_bad_checksum, setup),
		cmocka_unit_test_setup(lisp_input_dscp, setup),
		cmocka_unit_test_setup(lisp_input_ecn, setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
