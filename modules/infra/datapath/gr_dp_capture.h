// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#pragma once

#include <gr_capture.h>
#include <gr_capture_ring.h>
#include <gr_iface.h>

#ifdef RTE_LIB_BPF
#include <rte_bpf.h>
#endif
#include <rte_cycles.h>
#include <rte_mbuf.h>

#include <stdatomic.h>
#include <string.h>

static inline void capture_enqueue(
	uint16_t port_id,
	uint16_t queue_id,
	struct rte_mbuf **mbufs,
	uint16_t count,
	uint8_t direction,
	const struct iface *iface
) {
	struct capture_session *s = atomic_load_explicit(
		&iface_capture[iface->id], memory_order_relaxed
	);
	if (s == NULL)
		return;

	struct gr_capture_ring *ring = s->ring;
	struct gr_capture_slot *slots = gr_capture_ring_slots(ring);
	uint32_t mask = ring->slot_count - 1;
	uint32_t snap = ring->snap_len;
	uint64_t tsc = rte_rdtsc();

	// If a BPF filter is installed, run it on each mbuf first.
	// Only matching packets enter the ring, saving the atomic +
	// memcpy cost for filtered-out packets.
	uint16_t matched = count;
	uint16_t match_idx[count];
	uint64_t (*bpf_func)(void *) = s->bpf_jit_func;

	if (bpf_func != NULL) {
		matched = 0;
		for (uint16_t i = 0; i < count; i++) {
			if (bpf_func(mbufs[i]))
				match_idx[matched++] = i;
		}
		atomic_fetch_add_explicit(&s->bpf_passed, matched, memory_order_relaxed);
		atomic_fetch_add_explicit(&s->bpf_filtered, count - matched, memory_order_relaxed);
		if (matched == 0)
			return;
#ifdef RTE_LIB_BPF
	} else if (s->bpf != NULL) {
		matched = 0;
		for (uint16_t i = 0; i < count; i++) {
			if (rte_bpf_exec(s->bpf, mbufs[i]))
				match_idx[matched++] = i;
		}
		atomic_fetch_add_explicit(&s->bpf_passed, matched, memory_order_relaxed);
		atomic_fetch_add_explicit(&s->bpf_filtered, count - matched, memory_order_relaxed);
		if (matched == 0)
			return;
#endif
	}

	// Batch-reserve: one atomic op for the matched burst.
	uint32_t base = atomic_fetch_add_explicit(
		&ring->prod_head, matched, memory_order_relaxed
	);

	// Fill each reserved slot and publish it.
	for (uint16_t j = 0; j < matched; j++) {
		uint16_t i = (bpf_func != NULL
#ifdef RTE_LIB_BPF
			      || s->bpf != NULL
#endif
			      ) ? match_idx[j] : j;
		struct rte_mbuf *m = mbufs[i];
		uint32_t pos = base + j;
		struct gr_capture_slot *slot = &slots[pos & mask];
		uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
		uint32_t cap_len = pkt_len < snap ? pkt_len : snap;

		slot->pkt_len = pkt_len;
		slot->cap_len = cap_len;
		slot->iface_id = iface->id;
		slot->port_id = port_id;
		slot->queue_id = queue_id;
		slot->direction = direction;
		slot->timestamp_tsc = tsc;

		if (rte_pktmbuf_is_contiguous(m))
			memcpy(slot->data, rte_pktmbuf_mtod(m, void *), cap_len);
		else
			rte_pktmbuf_read(m, 0, cap_len, slot->data);

		atomic_store_explicit(
			&slot->sequence, pos + 1, memory_order_release
		);
	}
}
