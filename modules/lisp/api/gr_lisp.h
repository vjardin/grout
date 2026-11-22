// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

#pragma once

#include <gr_bitops.h>
#include <gr_infra.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

// NB: LISP interfaces are managed using GR_IFACE_* messages from gr_infra.h
// and LISP nexthops using GR_NH_* messages from gr_nexthop.h.

#define GR_LISP_DATA_PORT 4341
#define GR_LISP_IID_MAX 0xffffff

// LISP interface reconfiguration attributes.
#define GR_LISP_SET_IID GR_BIT64(32)
#define GR_LISP_SET_ENCAP_VRF GR_BIT64(33)
#define GR_LISP_SET_LOCAL GR_BIT64(34)
#define GR_LISP_SET_LOCAL6 GR_BIT64(35)
#define GR_LISP_SET_RLOC_FILTER GR_BIT64(36)
#define GR_LISP_SET_EID_FILTER GR_BIT64(37)

// Info structure for GR_IFACE_TYPE_LISP interfaces.
struct gr_iface_info_lisp {
	uint32_t iid; // Instance ID, unique per encap_vrf_id.
	uint16_t encap_vrf_id; // L3 domain of the RLOCs.
	bool rloc_filter; // Drop the packets that do not come from the RLOC of a nexthop.
	bool eid_filter; // Drop the packets whose source EID is not mapped to their source RLOC.
	ip4_addr_t local; // Local IPv4 RLOC.
	struct rte_ipv6_addr local6; // Local IPv6 RLOC.
};

// Info structure for GR_NH_T_LISP nexthops.
struct gr_nexthop_info_lisp {
	struct l3_addr rloc; // Remote RLOC.
};
