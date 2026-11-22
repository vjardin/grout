// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

#include "capture.h"
#include "graph.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "lisp.h"
#include "mbuf.h"
#include "rxtx.h"

#include <gr_lisp.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_udp.h>

enum {
	IP_OUTPUT = 0,
	IP6_OUTPUT,
	NO_RLOC,
	NO_LOCAL_RLOC,
	NO_ROUTE,
	NO_HEADROOM,
	IFACE_DOWN,
	EDGE_COUNT,
};

// First of the dynamic ports (RFC 6335 section 6).
#define EPHEMERAL_PORT_START 49152
#define EPHEMERAL_PORT_MASK (UINT16_MAX - EPHEMERAL_PORT_START)

static inline rte_be16_t lisp_src_port(uint32_t hash) {
	return rte_cpu_to_be_16(EPHEMERAL_PORT_START + (hash & EPHEMERAL_PORT_MASK));
}

static inline uint16_t lisp_headers_len(const struct l3_addr *rloc) {
	if (rloc->af == GR_AF_IP4)
		return sizeof(struct lisp_template_ipv4);
	return sizeof(struct lisp_template_ipv6);
}

// Make room for the outer headers, without prepending them yet.
static inline bool lisp_reserve_headers(struct rte_mbuf *m, uint16_t len) {
	uint8_t *room = gr_mbuf_prepend(m, room, len - sizeof(*room));

	if (unlikely(room == NULL))
		return false;

	rte_pktmbuf_adj(m, len);

	return true;
}

static uint16_t
lisp_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_lisp *lisp;
	const struct nexthop *nh, *via;
	struct lisp_template_ipv4 *h4;
	struct lisp_template_ipv6 *h6;
	const struct l3_addr *rloc;
	const struct iface *iface;
	struct rte_mbuf *m;
	uint8_t tos, ttl;
	rte_edge_t edge;
	uint16_t len;

	IFACE_STATS_VARS(tx, self);

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		iface = mbuf_data(m)->iface;
		nh = l3_mbuf_data(m)->nh;
		lisp = iface_info_lisp(iface);
		rloc = NULL;

		if (!(iface->flags & GR_IFACE_F_UP)) {
			edge = IFACE_DOWN;
			goto next;
		}
		if (nh->type != GR_NH_T_LISP) {
			edge = NO_RLOC;
			goto next;
		}
		rloc = &nexthop_info_lisp(nh)->rloc;

		switch (rloc->af) {
		case GR_AF_IP4:
			if (lisp->local == 0) {
				edge = NO_LOCAL_RLOC;
				goto next;
			}
			via = fib4_lookup(lisp->encap_vrf_id, rloc->ipv4, m->hash.rss);
			break;
		case GR_AF_IP6:
			if (rte_ipv6_addr_is_unspec(&lisp->local6)) {
				edge = NO_LOCAL_RLOC;
				goto next;
			}
			via = fib6_lookup(
				lisp->encap_vrf_id, GR_IFACE_ID_UNDEF, &rloc->ipv6, m->hash.rss
			);
			break;
		default:
			edge = NO_RLOC;
			goto next;
		}
		if (via == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, const void *);
			len = rte_be_to_cpu_16(ip->total_length);
			tos = ip->type_of_service;
			ttl = ip->time_to_live;
		} else {
			const struct rte_ipv6_hdr *ip = rte_pktmbuf_mtod(m, const void *);
			len = rte_be_to_cpu_16(ip->payload_len) + sizeof(*ip);
			tos = (rte_be_to_cpu_32(ip->vtc_flow) & RTE_IPV6_HDR_TC_MASK)
				>> RTE_IPV6_HDR_TC_SHIFT;
			ttl = ip->hop_limits;
		}

		// A packet that cannot be encapsulated is not counted.
		if (unlikely(!lisp_reserve_headers(m, lisp_headers_len(rloc)))) {
			edge = NO_HEADROOM;
			goto next;
		}

		IFACE_STATS_INC(tx, self, m, iface);
		nexthop_stats_tx(nh, m);
		if (unlikely(iface->flags & GR_IFACE_F_CAPTURE)) {
			// capture_enqueue() reads a VLAN ID from the mbuf private data
			iface_mbuf_data(m)->vlan_id = 0;
			capture_enqueue(iface, GR_CAPTURE_DIR_OUT, m);
		}

		if (rloc->af == GR_AF_IP4) {
			h4 = gr_mbuf_prepend(m, h4);
			*h4 = lisp->template4;
			h4->ip.type_of_service = tos;
			h4->ip.total_length = rte_cpu_to_be_16(len + sizeof(*h4));
			h4->ip.time_to_live = ttl;
			h4->ip.dst_addr = rloc->ipv4;
			h4->ip.hdr_checksum = rte_ipv4_cksum(&h4->ip);
			h4->udp.src_port = lisp_src_port(m->hash.rss);
			h4->udp.dgram_len = rte_cpu_to_be_16(
				len + sizeof(h4->udp) + sizeof(h4->lisp)
			);
			edge = IP_OUTPUT;
		} else {
			h6 = gr_mbuf_prepend(m, h6);
			*h6 = lisp->template6;
			h6->ip.vtc_flow = rte_cpu_to_be_32(
				(IP6_VERSION << IP6_VERSION_SHIFT) | (tos << RTE_IPV6_HDR_TC_SHIFT)
				| (m->hash.rss & RTE_IPV6_HDR_FL_MASK)
			);
			h6->ip.payload_len = rte_cpu_to_be_16(
				len + sizeof(h6->udp) + sizeof(h6->lisp)
			);
			h6->ip.hop_limits = ttl;
			h6->ip.dst_addr = rloc->ipv6;
			h6->udp.src_port = lisp_src_port(m->hash.rss);
			h6->udp.dgram_len = h6->ip.payload_len;
			edge = IP6_OUTPUT;
		}
		l3_mbuf_data(m)->nh = via;
next:
		if (gr_mbuf_is_traced(m)) {
			struct trace_lisp_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->iid = lisp->iid;
			t->iface_id = iface->id;
			if (rloc != NULL)
				t->rloc = *rloc;
			else
				t->rloc.af = GR_AF_UNSPEC;
		}
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	IFACE_STATS_FLUSH(tx, self);

	return nb_objs;
}

static void lisp_output_register(void) {
	ip_output_register_interface_type(GR_IFACE_TYPE_LISP, "lisp_output");
	ip6_output_register_interface_type(GR_IFACE_TYPE_LISP, "lisp_output");
}

static struct rte_node_register lisp_output_node = {
	.name = "lisp_output",

	.process = lisp_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip_output",
		[IP6_OUTPUT] = "ip6_output",
		[NO_RLOC] = "lisp_output_no_rloc",
		[NO_LOCAL_RLOC] = "lisp_output_no_local_rloc",
		[NO_ROUTE] = "lisp_output_no_route",
		[NO_HEADROOM] = "error_no_headroom",
		[IFACE_DOWN] = "iface_input_admin_down",
	},
};

static struct gr_node_info lisp_output_info = {
	.node = &lisp_output_node,
	.type = GR_NODE_T_L3,
	.register_callback = lisp_output_register,
	.trace_format = trace_lisp_format,
};

GR_NODE_REGISTER(lisp_output_info);

GR_DROP_REGISTER(lisp_output_no_rloc);
GR_DROP_REGISTER(lisp_output_no_local_rloc);
GR_DROP_REGISTER(lisp_output_no_route);

#ifdef __GROUT_UNIT_TEST__
#include "_cmocka.h"

#include <netinet/in.h>
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
mock_func(int, trace_lisp_format(char *, size_t, const void *, size_t));
mock_func(void, ip_output_register_interface_type(gr_iface_type_t, const char *));
mock_func(void, ip6_output_register_interface_type(gr_iface_type_t, const char *));

const struct nexthop *fib4_lookup(uint16_t vrf_id, ip4_addr_t ip, uint32_t flow_id) {
	check_expected_uint(vrf_id);
	check_expected_uint(ip);
	check_expected_uint(flow_id);
	return (const struct nexthop *)mock();
}

const struct nexthop *
fib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip, uint32_t flow_id) {
	check_expected_uint(vrf_id);
	check_expected_uint(iface_id);
	check_expected_ptr(ip);
	check_expected_uint(flow_id);
	return (const struct nexthop *)mock();
}

#define TEST_IID 101
#define TEST_EID_VRF 3
#define TEST_RLOC_VRF 2
#define TEST_LOCAL RTE_IPV4(192, 0, 2, 1)
#define TEST_REMOTE RTE_IPV4(192, 0, 2, 5)
#define TEST_LOCAL_EID RTE_IPV4(10, 1, 0, 2)
#define TEST_REMOTE_EID RTE_IPV4(10, 2, 0, 2)
#define TEST_HASH 0xdeadbeef
#define TEST_TOS (IPTOS_DSCP_EF | IPTOS_ECN_ECT1)
#define TEST_TTL 17
#define TEST_FLOW_LABEL 0x12345
#define TEST_PAYLOAD_LEN 16
#define TEST_IP4_LEN (sizeof(struct rte_ipv4_hdr) + TEST_PAYLOAD_LEN)
#define TEST_IP6_LEN (sizeof(struct rte_ipv6_hdr) + TEST_PAYLOAD_LEN)
#define TEST_STATS_ID 1

static const struct rte_ipv6_addr test_local6 = RTE_IPV6(0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 1);
static const struct rte_ipv6_addr test_remote6 = RTE_IPV6(0x2001, 0xdb8, 0xb, 0, 0, 0, 0, 1);

struct fake_mbuf {
	uint8_t headroom[RTE_PKTMBUF_HEADROOM];
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
static struct nexthop rloc4_nh, rloc6_nh;
static struct nexthop underlay_nh;

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
	lisp_templates_init(lisp);

	// Only the IPv4 RLOC is counted.
	memset(test_nh_stats, 0, sizeof(test_nh_stats));
	nexthop_stats[0] = test_nh_stats;

	memset(&rloc4_nh, 0, sizeof(rloc4_nh));
	rloc4_nh.type = GR_NH_T_LISP;
	rloc4_nh.stats_id = TEST_STATS_ID;
	nexthop_info_lisp(&rloc4_nh)->rloc.af = GR_AF_IP4;
	nexthop_info_lisp(&rloc4_nh)->rloc.ipv4 = RTE_BE32(TEST_REMOTE);

	memset(&rloc6_nh, 0, sizeof(rloc6_nh));
	rloc6_nh.type = GR_NH_T_LISP;
	nexthop_info_lisp(&rloc6_nh)->rloc.af = GR_AF_IP6;
	nexthop_info_lisp(&rloc6_nh)->rloc.ipv6 = test_remote6;

	memset(&underlay_nh, 0, sizeof(underlay_nh));
	underlay_nh.type = GR_NH_T_L3;

	free(iface_stats);
	iface_stats = calloc(2, sizeof(*iface_stats));
	RTE_PER_LCORE(_lcore_id) = 0;

	return iface_stats == NULL ? -1 : 0;
}

static void fake_mbuf_init(struct fake_mbuf *fm) {
	memset(fm, 0, sizeof(*fm));

	fm->ip4.version_ihl = IPV4_VERSION_IHL;
	fm->ip4.type_of_service = TEST_TOS;
	fm->ip4.total_length = rte_cpu_to_be_16(TEST_IP4_LEN);
	fm->ip4.time_to_live = TEST_TTL;
	fm->ip4.next_proto_id = IPPROTO_RAW;
	fm->ip4.src_addr = RTE_BE32(TEST_LOCAL_EID);
	fm->ip4.dst_addr = RTE_BE32(TEST_REMOTE_EID);
	fm->ip4.hdr_checksum = rte_ipv4_cksum(&fm->ip4);

	fm->mbuf.buf_addr = fm->headroom;
	fm->mbuf.buf_len = offsetof(struct fake_mbuf, mbuf);
	fm->mbuf.data_off = sizeof(fm->headroom);
	fm->mbuf.data_len = TEST_IP4_LEN;
	fm->mbuf.pkt_len = TEST_IP4_LEN;
	fm->mbuf.nb_segs = 1;
	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV4;
	fm->mbuf.hash.rss = TEST_HASH;

	mbuf_data(&fm->mbuf)->iface = lisp_iface;
	l3_mbuf_data(&fm->mbuf)->nh = &rloc4_nh;
}

static void fake_mbuf_inner6(struct fake_mbuf *fm) {
	memset(&fm->ip6, 0, sizeof(fm->ip6));
	fm->ip6.vtc_flow = rte_cpu_to_be_32(
		(IP6_VERSION << IP6_VERSION_SHIFT) | (TEST_TOS << RTE_IPV6_HDR_TC_SHIFT)
		| TEST_FLOW_LABEL
	);
	fm->ip6.payload_len = rte_cpu_to_be_16(TEST_PAYLOAD_LEN);
	fm->ip6.proto = IPPROTO_RAW;
	fm->ip6.hop_limits = TEST_TTL;
	fm->mbuf.data_len = TEST_IP6_LEN;
	fm->mbuf.pkt_len = TEST_IP6_LEN;
	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV6;
}

static void expect_fib4(const struct nexthop *nh) {
	expect_uint_value(fib4_lookup, vrf_id, TEST_RLOC_VRF);
	expect_uint_value(fib4_lookup, ip, RTE_BE32(TEST_REMOTE));
	expect_uint_value(fib4_lookup, flow_id, TEST_HASH);
	will_return(fib4_lookup, nh);
}

static void expect_fib6(const struct nexthop *nh) {
	expect_uint_value(fib6_lookup, vrf_id, TEST_RLOC_VRF);
	expect_uint_value(fib6_lookup, iface_id, GR_IFACE_ID_UNDEF);
	expect_memory(fib6_lookup, ip, &test_remote6, sizeof(test_remote6));
	expect_uint_value(fib6_lookup, flow_id, TEST_HASH);
	will_return(fib6_lookup, nh);
}

static void expect_output(struct fake_mbuf *fm, rte_edge_t edge) {
	void *obj = &fm->mbuf;

	expect_uint_value(rte_node_enqueue_x1, next, edge);
	lisp_output_process(NULL, NULL, &obj, 1);
}

static void assert_udp_lisp(
	const struct rte_udp_hdr *udp,
	const struct lisp_hdr *lisp,
	const void *inner,
	const void *orig_inner,
	uint16_t inner_len
) {
	const struct lisp_hdr expected = {
		.flags = LISP_F_I,
		.iid_lsb = lisp_encode_iid(TEST_IID),
	};

	assert_int_equal(udp->src_port, lisp_src_port(TEST_HASH));
	assert_in_range(rte_be_to_cpu_16(udp->src_port), EPHEMERAL_PORT_START, UINT16_MAX);
	assert_int_equal(udp->dst_port, RTE_BE16(GR_LISP_DATA_PORT));
	assert_int_equal(rte_be_to_cpu_16(udp->dgram_len), inner_len + LISP_ENCAP_LEN);
	assert_int_equal(udp->dgram_cksum, 0);

	assert_memory_equal(lisp, &expected, sizeof(expected));

	assert_ptr_equal(inner, orig_inner);
}

static void assert_outer4(struct fake_mbuf *fm, uint16_t inner_len) {
	const struct lisp_template_ipv4 *h = rte_pktmbuf_mtod(&fm->mbuf, void *);

	assert_int_equal(fm->mbuf.pkt_len, inner_len + sizeof(*h));
	assert_int_equal(fm->mbuf.data_len, inner_len + sizeof(*h));

	assert_int_equal(h->ip.version_ihl, IPV4_VERSION_IHL);
	assert_int_equal(h->ip.type_of_service, TEST_TOS);
	assert_int_equal(h->ip.time_to_live, TEST_TTL);
	assert_int_equal(rte_be_to_cpu_16(h->ip.total_length), inner_len + sizeof(*h));
	assert_int_equal(h->ip.fragment_offset, RTE_BE16(RTE_IPV4_HDR_DF_FLAG));
	assert_int_equal(h->ip.next_proto_id, IPPROTO_UDP);
	assert_int_equal(h->ip.src_addr, RTE_BE32(TEST_LOCAL));
	assert_int_equal(h->ip.dst_addr, RTE_BE32(TEST_REMOTE));
	assert_int_equal(rte_ipv4_cksum(&h->ip), 0);

	assert_udp_lisp(&h->udp, &h->lisp, h + 1, &fm->ip4, inner_len);

	assert_ptr_equal(l3_mbuf_data(&fm->mbuf)->nh, &underlay_nh);
}

static void assert_outer6(struct fake_mbuf *fm, uint16_t inner_len) {
	const struct lisp_template_ipv6 *h = rte_pktmbuf_mtod(&fm->mbuf, void *);

	assert_int_equal(fm->mbuf.pkt_len, inner_len + sizeof(*h));
	assert_int_equal(fm->mbuf.data_len, inner_len + sizeof(*h));

	assert_int_equal(
		rte_be_to_cpu_32(h->ip.vtc_flow),
		(IP6_VERSION << IP6_VERSION_SHIFT) | (TEST_TOS << RTE_IPV6_HDR_TC_SHIFT)
			| (TEST_HASH & RTE_IPV6_HDR_FL_MASK)
	);
	assert_int_equal(rte_be_to_cpu_16(h->ip.payload_len), inner_len + LISP_ENCAP_LEN);
	assert_int_equal(h->ip.proto, IPPROTO_UDP);
	assert_int_equal(h->ip.hop_limits, TEST_TTL);
	assert_memory_equal(&h->ip.src_addr, &test_local6, sizeof(test_local6));
	assert_memory_equal(&h->ip.dst_addr, &test_remote6, sizeof(test_remote6));

	assert_udp_lisp(&h->udp, &h->lisp, h + 1, &fm->ip6, inner_len);

	assert_ptr_equal(l3_mbuf_data(&fm->mbuf)->nh, &underlay_nh);
}

static void assert_tx_stats(uint64_t packets, uint64_t bytes) {
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->tx_packets, packets);
	assert_int_equal(iface_get_stats(0, lisp_iface->id)->tx_bytes, bytes);
}

static void assert_nh_stats(uint64_t packets, uint64_t bytes) {
	assert_int_equal(test_nh_stats[TEST_STATS_ID].tx_packets, packets);
	assert_int_equal(test_nh_stats[TEST_STATS_ID].tx_bytes, bytes);
}

static void lisp_output_ip4_in_ip4(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	expect_fib4(&underlay_nh);
	expect_output(&fm, IP_OUTPUT);
	assert_outer4(&fm, TEST_IP4_LEN);
	assert_tx_stats(1, TEST_IP4_LEN);
	assert_nh_stats(1, TEST_IP4_LEN);
}

static void lisp_output_ip6_in_ip4(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm);
	expect_fib4(&underlay_nh);
	expect_output(&fm, IP_OUTPUT);
	assert_outer4(&fm, TEST_IP6_LEN);
	assert_tx_stats(1, TEST_IP6_LEN);
	assert_nh_stats(1, TEST_IP6_LEN);
}

static void lisp_output_ip4_in_ip6(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	l3_mbuf_data(&fm.mbuf)->nh = &rloc6_nh;
	expect_fib6(&underlay_nh);
	expect_output(&fm, IP6_OUTPUT);
	assert_outer6(&fm, TEST_IP4_LEN);
	assert_tx_stats(1, TEST_IP4_LEN);
	assert_nh_stats(0, 0);
}

static void lisp_output_ip6_in_ip6(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fake_mbuf_inner6(&fm);
	l3_mbuf_data(&fm.mbuf)->nh = &rloc6_nh;
	expect_fib6(&underlay_nh);
	expect_output(&fm, IP6_OUTPUT);
	assert_outer6(&fm, TEST_IP6_LEN);
	assert_tx_stats(1, TEST_IP6_LEN);
	assert_nh_stats(0, 0);
}

static void lisp_output_iid_zero(void **) {
	const struct lisp_template_ipv4 *h4;
	const struct lisp_template_ipv6 *h6;
	struct fake_mbuf fm;

	iface_info_lisp(lisp_iface)->iid = 0;
	lisp_templates_init(iface_info_lisp(lisp_iface));

	fake_mbuf_init(&fm);
	expect_fib4(&underlay_nh);
	expect_output(&fm, IP_OUTPUT);
	h4 = rte_pktmbuf_mtod(&fm.mbuf, void *);
	assert_int_equal(h4->lisp.flags, 0);
	assert_int_equal(h4->lisp.iid_lsb, 0);

	fake_mbuf_init(&fm);
	l3_mbuf_data(&fm.mbuf)->nh = &rloc6_nh;
	expect_fib6(&underlay_nh);
	expect_output(&fm, IP6_OUTPUT);
	h6 = rte_pktmbuf_mtod(&fm.mbuf, void *);
	assert_int_equal(h6->lisp.flags, 0);
	assert_int_equal(h6->lisp.iid_lsb, 0);
}

static void lisp_output_src_port(void **) {
	const uint32_t hashes[] = {
		0,
		1,
		EPHEMERAL_PORT_MASK,
		EPHEMERAL_PORT_MASK + 1,
		TEST_HASH,
		UINT32_MAX,
	};
	bool differ = false;
	uint16_t port;

	for (unsigned i = 0; i < ARRAY_DIM(hashes); i++) {
		port = rte_be_to_cpu_16(lisp_src_port(hashes[i]));
		assert_in_range(port, EPHEMERAL_PORT_START, UINT16_MAX);
		assert_int_equal(port, rte_be_to_cpu_16(lisp_src_port(hashes[i])));
		if (port != rte_be_to_cpu_16(lisp_src_port(hashes[0])))
			differ = true;
	}
	assert_true(differ);
	assert_int_equal(rte_be_to_cpu_16(lisp_src_port(0)), EPHEMERAL_PORT_START);
	assert_int_equal(rte_be_to_cpu_16(lisp_src_port(EPHEMERAL_PORT_MASK)), UINT16_MAX);
}

static void lisp_output_no_rloc(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	l3_mbuf_data(&fm.mbuf)->nh = &underlay_nh;
	expect_output(&fm, NO_RLOC);
	assert_int_equal(fm.mbuf.pkt_len, TEST_IP4_LEN);
	assert_tx_stats(0, 0);
	assert_nh_stats(0, 0);
}

static void lisp_output_no_local_rloc(void **) {
	struct iface_info_lisp *lisp = iface_info_lisp(lisp_iface);
	struct fake_mbuf fm;

	lisp->local = 0;
	fake_mbuf_init(&fm);
	expect_output(&fm, NO_LOCAL_RLOC);
	assert_int_equal(fm.mbuf.pkt_len, TEST_IP4_LEN);

	lisp->local = RTE_BE32(TEST_LOCAL);
	memset(&lisp->local6, 0, sizeof(lisp->local6));
	fake_mbuf_init(&fm);
	l3_mbuf_data(&fm.mbuf)->nh = &rloc6_nh;
	expect_output(&fm, NO_LOCAL_RLOC);
	assert_int_equal(fm.mbuf.pkt_len, TEST_IP4_LEN);
	assert_tx_stats(0, 0);
	assert_nh_stats(0, 0);
}

static void lisp_output_no_route(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	expect_fib4(NULL);
	expect_output(&fm, NO_ROUTE);
	assert_int_equal(fm.mbuf.pkt_len, TEST_IP4_LEN);

	fake_mbuf_init(&fm);
	l3_mbuf_data(&fm.mbuf)->nh = &rloc6_nh;
	expect_fib6(NULL);
	expect_output(&fm, NO_ROUTE);
	assert_int_equal(fm.mbuf.pkt_len, TEST_IP4_LEN);
	assert_tx_stats(0, 0);
	assert_nh_stats(0, 0);
}

static void lisp_output_no_headroom(void **) {
	struct fake_mbuf fm;

	fake_mbuf_init(&fm);
	fm.mbuf.buf_addr = &fm.ip4;
	fm.mbuf.data_off = 0;
	fm.mbuf.buf_len = TEST_IP4_LEN;
	expect_fib4(&underlay_nh);
	expect_output(&fm, NO_HEADROOM);
	assert_int_equal(fm.mbuf.pkt_len, TEST_IP4_LEN);
	assert_tx_stats(0, 0);
	assert_nh_stats(0, 0);
}

static void lisp_output_iface_down(void **) {
	struct fake_mbuf fm;

	lisp_iface->flags &= ~GR_IFACE_F_UP;
	fake_mbuf_init(&fm);
	expect_output(&fm, IFACE_DOWN);
	assert_int_equal(fm.mbuf.pkt_len, TEST_IP4_LEN);
	assert_tx_stats(0, 0);
	assert_nh_stats(0, 0);
}

static void lisp_output_burst(void **) {
	struct fake_mbuf fm[3];
	void *objs[3];

	for (unsigned i = 0; i < ARRAY_DIM(fm); i++) {
		fake_mbuf_init(&fm[i]);
		objs[i] = &fm[i].mbuf;
	}
	fake_mbuf_inner6(&fm[1]);
	l3_mbuf_data(&fm[2].mbuf)->nh = &rloc6_nh;

	expect_fib4(&underlay_nh);
	expect_fib4(&underlay_nh);
	expect_fib6(&underlay_nh);
	expect_uint_value(rte_node_enqueue_x1, next, IP_OUTPUT);
	expect_uint_value(rte_node_enqueue_x1, next, IP_OUTPUT);
	expect_uint_value(rte_node_enqueue_x1, next, IP6_OUTPUT);
	lisp_output_process(NULL, NULL, objs, ARRAY_DIM(objs));

	assert_outer4(&fm[0], TEST_IP4_LEN);
	assert_outer4(&fm[1], TEST_IP6_LEN);
	assert_outer6(&fm[2], TEST_IP4_LEN);
	assert_tx_stats(3, 2 * TEST_IP4_LEN + TEST_IP6_LEN);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(lisp_output_ip4_in_ip4, setup),
		cmocka_unit_test_setup(lisp_output_ip6_in_ip4, setup),
		cmocka_unit_test_setup(lisp_output_ip4_in_ip6, setup),
		cmocka_unit_test_setup(lisp_output_ip6_in_ip6, setup),
		cmocka_unit_test_setup(lisp_output_iid_zero, setup),
		cmocka_unit_test_setup(lisp_output_src_port, setup),
		cmocka_unit_test_setup(lisp_output_no_rloc, setup),
		cmocka_unit_test_setup(lisp_output_no_local_rloc, setup),
		cmocka_unit_test_setup(lisp_output_no_route, setup),
		cmocka_unit_test_setup(lisp_output_no_headroom, setup),
		cmocka_unit_test_setup(lisp_output_iface_down, setup),
		cmocka_unit_test_setup(lisp_output_burst, setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
