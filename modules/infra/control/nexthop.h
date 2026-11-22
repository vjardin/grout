// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include "control_queue.h"
#include "vec.h"

#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <assert.h>
#include <stdatomic.h>

extern struct gr_nexthop_config nh_conf;

int nexthop_config_set(const struct gr_nexthop_config *);
unsigned nexthop_used_count(void);

struct __rte_cache_aligned nexthop {
	BASE(gr_nexthop_base);

	uint32_t ref_count;
	uint32_t route_count; // number of routes referencing this nexthop
	uint32_t nh_count; // number of references held by other nexthops
	uint32_t stats_id; // index in nexthop_stats, 0 when stats are disabled

	uint8_t info
		[RTE_CACHE_LINE_MIN_SIZE * 2
		 - RTE_ALIGN_CEIL(
			 sizeof(struct gr_nexthop_base) + 4 * sizeof(uint32_t),
			 alignof(void *)
		 )] __rte_aligned(alignof(void *));
};
static_assert(sizeof(struct nexthop) <= (RTE_CACHE_LINE_MIN_SIZE * 2));

#define GR_NH_TYPE_INFO(type_id, type_name, fields)                                                \
	struct type_name fields __attribute__((__may_alias__, aligned(alignof(void *))));          \
	static inline struct type_name *type_name(const struct nexthop *nh) {                      \
		assert(nh->type == type_id);                                                       \
		return (struct type_name *)&nh->info;                                              \
	}                                                                                          \
	static_assert(sizeof(struct type_name) <= MEMBER_SIZE(struct nexthop, info))

GR_NH_TYPE_INFO(GR_NH_T_L3, nexthop_info_l3, {
	BASE(gr_nexthop_info_l3);

	gr_clock_ns_t last_reply; //!< timestamp when last update was received
	gr_clock_ns_t last_request;
	gr_clock_ns_t failed_since;

	bool snoop_only;

	uint8_t ucast_probes;
	uint8_t bcast_probes;

	// packets waiting for address resolution
	_Atomic(uint16_t) held_pkts;
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;

	// Local addresses only: interfaces the address is exposed on, allowed to
	// answer ARP/NDP for it in addition to the owning interface (strong host
	// model bypass). Control plane only.
	vec uint16_t *exposed_iface_ids;
});

static inline bool nexthop_l3_hold_queue_full(const struct nexthop *nh) {
	if (nh->type != GR_NH_T_L3)
		return false;

	const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
	if (atomic_load_explicit(&l3->held_pkts, memory_order_relaxed) >= nh_conf.max_held_pkts)
		return true;

	return false;
}

// Append a packet to the hold queue. Returns -ENOBUFS if the queue is full.
int nexthop_l3_hold_queue_add(struct nexthop *, struct rte_mbuf *);

// Reset the hold queue without freeing the mbufs.
void nexthop_l3_hold_queue_reset(struct nexthop *);

// Empty the hold queue, freeing all mbufs.
void nexthop_l3_hold_queue_flush(struct nexthop *);

// Iterate over all held mbufs. It is safe to mutate/free the mbufs while iterating.
#define nexthop_l3_hold_queue_foreach(m, nh)                                                       \
	for (struct rte_mbuf *__next = NULL, *m = nexthop_info_l3(nh)->held_pkts_head;             \
	     m != NULL && (__next = queue_mbuf_data(m)->next, true);                               \
	     m = __next)

struct hoplist {
	vec struct nexthop **nh;
};

struct nh_group_member {
	struct nexthop *nh;
	uint32_t weight;
};

#define MAX_NH_GROUP_RETA_SIZE 4096
GR_NH_TYPE_INFO(GR_NH_T_GROUP, nexthop_info_group, {
	uint16_t n_members;
	uint16_t reta_size; // MUST BE A POWER OF TWO
	struct nexthop *nh; // shortcut when there is a single nexthop in the group
	struct nh_group_member *members; // terminated by a NULL nexthop
	struct nexthop **reta;
});

// Iterate over the nexthops of the members of a group, from the datapath as
// well. Each one is read once: the control plane may replace it meanwhile.
#define nexthop_group_foreach(var, nhg)                                                            \
	for (const struct nh_group_member *var##_member = (nhg)->members;                          \
	     var##_member != NULL && (var = var##_member->nh) != NULL;                             \
	     var##_member++)

static inline struct nexthop *
nexthop_group_get_nh(struct nexthop_info_group *nhg, uint32_t flow_id) {
	if (likely(nhg->n_members == 1))
		return nhg->nh;
	if (unlikely(nhg->n_members == 0))
		return NULL;
	return nhg->reta[flow_id & (nhg->reta_size - 1)];
}

// Lookup an L3 nexthop that matches the specified criteria.
struct nexthop *
nexthop_lookup_l3(addr_family_t af, uint16_t vrf_id, uint16_t iface_id, const void *addr);

// Lookup a nexthop from its user provided ID.
struct nexthop *nexthop_lookup_id(uint32_t nh_id);

// Generic lookup based on base and type specific info.
struct nexthop *nexthop_lookup(const struct gr_nexthop_base *, const void *info);

// Compare two nexthops, return True if the same, else False
bool nexthop_equal(const struct nexthop *, const struct nexthop *);

// Check if a nexthop type value is valid.
bool nexthop_type_valid(gr_nh_type_t);

// Check if an origin value is valid.
bool nexthop_origin_valid(gr_nh_origin_t);

// Allocate a new nexthop from the global pool with the provided initial values.
struct nexthop *nexthop_new(const struct gr_nexthop_base *, const void *info);

// Update a nexthop with values from the API.
int nexthop_update(struct nexthop *, const struct gr_nexthop_base *, const void *info);

// Convert a nexthop to its public representation in the API.
// The returned value must be deallocated with free().
struct gr_nexthop *nexthop_to_api(const struct nexthop *, size_t *len);

// Uses nexthop_export to serve as callback for event_serializer.
int nexthop_serialize(const void *obj, void **buf);

// Clean all routes that reference a given nexthop.
void nexthop_routes_cleanup(struct nexthop *, bool notify);

// Clean all routes that reference the nexthops of an interface.
void nexthop_routes_cleanup_iface(uint16_t iface_id, bool notify);

// Increment the reference counter of a nexthop.
void nexthop_incref(struct nexthop *);

// Decrement the reference counter of a nexthop.
// When the counter drops to 0, the nexthop is destroyed and returned to the global pool.
void nexthop_decref(struct nexthop *);

// Take the reference that a route holds on its nexthop.
static inline void nexthop_route_incref(struct nexthop *nh) {
	nh->route_count++;
	nexthop_incref(nh);
}

// Drop the reference that a route holds on its nexthop.
static inline void nexthop_route_decref(struct nexthop *nh) {
	assert(nh->route_count > 0);
	nh->route_count--;
	nexthop_decref(nh);
}

// Take the reference that a nexthop holds on another one.
static inline void nexthop_nh_incref(struct nexthop *nh) {
	nh->nh_count++;
	nexthop_incref(nh);
}

// Drop the reference that a nexthop holds on another one.
static inline void nexthop_nh_decref(struct nexthop *nh) {
	assert(nh->nh_count > 0);
	nh->nh_count--;
	nexthop_decref(nh);
}

// Return the nexthop to the global pool regardless of its refcount.
void nexthop_destroy(struct nexthop *);

struct nexthop_stats {
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_packets;
	uint64_t rx_bytes;
};

// One table per lcore, indexed by nexthop->stats_id.
extern struct nexthop_stats *nexthop_stats[RTE_MAX_LCORE];

// Count a packet sent to a nexthop.
static inline void nexthop_stats_tx(const struct nexthop *nh, const struct rte_mbuf *m) {
	struct nexthop_stats *stats;

	if (nh->stats_id != 0) {
		stats = &nexthop_stats[rte_lcore_id()][nh->stats_id];
		stats->tx_packets++;
		stats->tx_bytes += rte_pktmbuf_pkt_len(m);
	}
}

// Count a packet received from a nexthop.
static inline void nexthop_stats_rx(const struct nexthop *nh, const struct rte_mbuf *m) {
	struct nexthop_stats *stats;

	if (nh->stats_id != 0) {
		stats = &nexthop_stats[rte_lcore_id()][nh->stats_id];
		stats->rx_packets++;
		stats->rx_bytes += rte_pktmbuf_pkt_len(m);
	}
}

// Get the counters of a nexthop, summed over all lcores.
void nexthop_stats_get(const struct nexthop *, struct nexthop_stats *);

// Reset the counters of all nexthops.
void nexthop_stats_reset(void);

// Callback for nh_iter().
typedef void (*nh_iter_cb_t)(struct nexthop *nh, void *priv);

// Iterate over all nexthops and invoke a callback for each active nexthop.
void nexthop_iter(nh_iter_cb_t nh_cb, void *priv);

// Cursor-based iteration over active nexthops.
// Pass NULL as prev to start, returns NULL when done.
struct nexthop *nexthop_next(struct nexthop *prev);

struct nexthop_af_ops {
	// Control queue callback invoked when packets reach ip*_hold.
	control_queue_cb_t resolve;
	// Callback that will be invoked when a nexthop needs to be refreshed by sending a probe.
	int (*solicit)(struct nexthop *);
	// Callback that will be invoked to delete all routes which reference a given nexthop.
	void (*cleanup_routes)(struct nexthop *, bool notify);
	// Same for all the nexthops of an interface, except those of its addresses.
	void (*cleanup_routes_iface)(uint16_t iface_id, bool notify);
	// Delete only automatically learned host routes for this nexthop.
	void (*cleanup_learned)(struct nexthop *);
	// Callback invoked by resolve() to flush held packets when the nexthop becomes
	// reachable.
	int (*resubmit)(struct rte_mbuf *, struct nexthop *);
};

void nexthop_af_ops_register(addr_family_t af, const struct nexthop_af_ops *);
const struct nexthop_af_ops *nexthop_af_ops_from_nh(const struct nexthop *);
const struct nexthop_af_ops *nexthop_af_ops_from_mbuf(const struct rte_mbuf *);

struct nexthop_type_ops {
	// The packets sent to nexthops of this type can be counted.
	bool stats;
	int (*reconfig)(const struct gr_nexthop_config *);
	struct nexthop *(*lookup)(const struct gr_nexthop_base *, const void *info);
	// Callback that will be invoked the nexthop refcount reaches zero.
	void (*remove_references)(struct nexthop *);
	void (*free)(struct nexthop *);
	bool (*equal)(const struct nexthop *, const struct nexthop *);
	// Copy public info structure to internal info structure.
	int (*import_info)(struct nexthop *, const void *public_info);
	// Convert a nexthop to its public representation in the API (including the base fields).
	struct gr_nexthop *(*to_api)(const struct nexthop *, size_t *len);
};

void nexthop_type_ops_register(gr_nh_type_t type, const struct nexthop_type_ops *);

// Local IP address nexthops will have these flags set.
#define NH_LOCAL_ADDR_FLAGS (GR_NH_F_LOCAL | GR_NH_F_LINK)
