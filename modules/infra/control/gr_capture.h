// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#pragma once

#include <gr_capture_ring.h>
#include <gr_infra.h>

#include <stdatomic.h>
#include <stdint.h>

struct rte_bpf;
struct rte_bpf_jit;

struct capture_session {
	struct gr_capture_ring *ring; // mmap'd pointer
	int shm_fd; // memfd kept open for fd passing to clients
	size_t shm_size;
	uint16_t iface_id; // GR_IFACE_ID_UNDEF = all
	uint32_t snap_len;
	_Atomic uint64_t drops;
	_Atomic uint64_t bpf_passed; // packets that passed the BPF filter
	_Atomic uint64_t bpf_filtered; // packets rejected by BPF filter
	// BPF filter (JIT-compiled). NULL = capture all packets.
	struct rte_bpf *bpf;
	uint64_t (*bpf_jit_func)(void *); // cached JIT function pointer, NULL if no filter
	// HW timestamp support (RX only).
	bool hw_timestamp;   // use mbuf HW timestamp instead of rte_rdtsc()
	int ts_dynfield_off; // mbuf dynfield offset for RX timestamp
	uint64_t ts_dynflag; // mbuf ol_flags bit for RX timestamp
};

// Per-interface capture session pointer, read atomically by datapath.
extern _Atomic(struct capture_session *) iface_capture[GR_MAX_IFACES];

struct capture_session *capture_session_start(uint16_t iface_id, uint32_t snap_len, uint8_t ts_clock);
void capture_session_stop(struct capture_session *s);
struct capture_session *capture_session_get(void);
int capture_session_set_filter(struct capture_session *s, const void *bpf_insns, uint16_t bpf_len);
