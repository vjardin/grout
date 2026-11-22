// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

#pragma once

#include "iface.h"
#include "ip4_datapath.h"
#include "nexthop.h"

#include <gr_bitops.h>
#include <gr_lisp.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_udp.h>

#include <stdint.h>

// LISP data header (RFC 9300 section 5.1).
struct lisp_hdr {
	uint8_t flags;
	uint8_t nonce[3];
	rte_be32_t iid_lsb;
} __attribute__((packed));

#define LISP_F_N GR_BIT8(7)
#define LISP_F_L GR_BIT8(6)
#define LISP_F_E GR_BIT8(5)
#define LISP_F_V GR_BIT8(4)
#define LISP_F_I GR_BIT8(3)
#define LISP_F_R GR_BIT8(2)
#define LISP_F_KK (GR_BIT8(1) | GR_BIT8(0))

#define LISP_IID_SHIFT 8

static inline rte_be32_t lisp_encode_iid(uint32_t iid) {
	return rte_cpu_to_be_32(iid << LISP_IID_SHIFT);
}

static inline uint32_t lisp_decode_iid(rte_be32_t iid_lsb) {
	return rte_be_to_cpu_32(iid_lsb) >> LISP_IID_SHIFT;
}

#define IP6_VERSION 6
#define IP6_VERSION_SHIFT 28

struct lisp_template_ipv4 {
	struct rte_ipv4_hdr ip;
	struct rte_udp_hdr udp;
	struct lisp_hdr lisp;
};

struct lisp_template_ipv6 {
	struct rte_ipv6_hdr ip;
	struct rte_udp_hdr udp;
	struct lisp_hdr lisp;
};

#define LISP_ENCAP_LEN (sizeof(struct rte_udp_hdr) + sizeof(struct lisp_hdr))

static_assert(sizeof(struct lisp_template_ipv4) == sizeof(struct rte_ipv4_hdr) + LISP_ENCAP_LEN);
static_assert(sizeof(struct lisp_template_ipv6) == sizeof(struct rte_ipv6_hdr) + LISP_ENCAP_LEN);

GR_IFACE_INFO(GR_IFACE_TYPE_LISP, iface_info_lisp, {
	BASE(gr_iface_info_lisp);

	uint32_t n_stats; // nexthops of the interface that have stats
	struct lisp_template_ipv4 template4;
	struct lisp_template_ipv6 template6;
});

static inline void lisp_templates_init(struct iface_info_lisp *lisp) {
	const struct lisp_hdr hdr = {
		.flags = lisp->iid != 0 ? LISP_F_I : 0,
		.iid_lsb = lisp_encode_iid(lisp->iid),
	};
	const struct rte_udp_hdr udp = {
		.dst_port = RTE_BE16(GR_LISP_DATA_PORT),
	};

	lisp->template4 = (struct lisp_template_ipv4) {
		.ip = {
			.version_ihl = IPV4_VERSION_IHL,
			.fragment_offset = RTE_BE16(RTE_IPV4_HDR_DF_FLAG),
			.next_proto_id = IPPROTO_UDP,
			.src_addr = lisp->local,
		},
		.udp = udp,
		.lisp = hdr,
	};
	lisp->template6 = (struct lisp_template_ipv6) {
		.ip = {
			.vtc_flow = RTE_BE32(IP6_VERSION << IP6_VERSION_SHIFT),
			.proto = IPPROTO_UDP,
			.src_addr = lisp->local6,
		},
		.udp = udp,
		.lisp = hdr,
	};
}

GR_NH_TYPE_INFO(GR_NH_T_LISP, nexthop_info_lisp, {
	BASE(gr_nexthop_info_lisp);

	uint16_t iface_id; // interface of the nexthop in the RLOC index
	bool stats; // counted in n_stats of that interface
});

struct iface *lisp_get_iface(uint32_t iid, uint16_t encap_vrf_id);

// Get the nexthop of a remote RLOC of an interface.
struct nexthop *lisp_rloc_lookup(uint16_t iface_id, const struct l3_addr *rloc);

struct trace_lisp_data {
	uint32_t iid;
	uint16_t iface_id;
	struct l3_addr rloc;
};

int trace_lisp_format(char *buf, size_t len, const void *data, size_t data_len);
