// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#include <gr_capture.h>
#include <gr_capture_ring.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>

#include <rte_cycles.h>
#include <rte_mbuf_dyn.h>

#ifdef RTE_LIB_BPF
#include <rte_bpf.h>
#include <rte_malloc.h>
#include <pcap/bpf.h>
#endif

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CAPTURE_SNAP_MAX 4096

_Atomic(struct capture_session *) iface_capture[GR_MAX_IFACES];

static struct capture_session *active_capture;

static void capture_set_flags(struct capture_session *s) {
	if (s->iface_id != GR_IFACE_ID_UNDEF) {
		struct iface *iface = iface_from_id(s->iface_id);
		if (iface != NULL) {
			iface->flags |= GR_IFACE_F_CAPTURE;
			atomic_store_explicit(
				&iface_capture[iface->id], s, memory_order_release
			);
		}
	} else {
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			iface->flags |= GR_IFACE_F_CAPTURE;
			atomic_store_explicit(
				&iface_capture[iface->id], s, memory_order_release
			);
		}
	}
}

static void capture_clear_flags(struct capture_session *s) {
	if (s->iface_id != GR_IFACE_ID_UNDEF) {
		struct iface *iface = iface_from_id(s->iface_id);
		if (iface != NULL) {
			iface->flags &= ~GR_IFACE_F_CAPTURE;
			atomic_store_explicit(
				&iface_capture[iface->id], NULL, memory_order_release
			);
		}
	} else {
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			iface->flags &= ~GR_IFACE_F_CAPTURE;
			atomic_store_explicit(
				&iface_capture[iface->id], NULL, memory_order_release
			);
		}
	}
}

static void iface_add_callback(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	struct capture_session *s = active_capture;
	if (s == NULL || s->iface_id != GR_IFACE_ID_UNDEF)
		return;
	iface_from_id(iface->id)->flags |= GR_IFACE_F_CAPTURE;
	atomic_store_explicit(&iface_capture[iface->id], s, memory_order_release);
}

struct capture_session *capture_session_get(void) {
	return active_capture;
}

struct capture_session *capture_session_start(uint16_t iface_id, uint32_t snap_len, uint8_t ts_clock) {
	struct capture_session *s;

	if (active_capture != NULL) {
		errno = EBUSY;
		return NULL;
	}

	if (iface_id != GR_IFACE_ID_UNDEF) {
		struct iface *iface = iface_from_id(iface_id);
		if (iface == NULL) {
			errno = ENODEV;
			return NULL;
		}
	}

	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;

	s->iface_id = iface_id;
	s->snap_len = snap_len ? snap_len : CAPTURE_SNAP_MAX;
	if (s->snap_len > GR_CAPTURE_SLOT_DATA_MAX)
		s->snap_len = GR_CAPTURE_SLOT_DATA_MAX;

	// Count port interfaces for the interface table.
	uint16_t n_ifaces = 0;
	struct iface *iface = NULL;
	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL)
		n_ifaces++;

	uint32_t slot_count = GR_CAPTURE_SLOT_COUNT_DEFAULT;
	s->shm_size = gr_capture_ring_memsize(slot_count, n_ifaces);

	s->shm_fd = memfd_create("grout-capture", MFD_CLOEXEC);
	if (s->shm_fd < 0) {
		LOG(ERR, "memfd_create: %s", strerror(errno));
		goto err_free;
	}
	if (ftruncate(s->shm_fd, s->shm_size) < 0) {
		LOG(ERR, "ftruncate: %s", strerror(errno));
		goto err_close;
	}
	s->ring = mmap(NULL, s->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, s->shm_fd, 0);
	if (s->ring == MAP_FAILED) {
		LOG(ERR, "mmap: %s", strerror(errno));
		s->ring = NULL;
		goto err_close;
	}

	// Initialize ring header.
	memset(s->ring, 0, s->shm_size);
	s->ring->magic = GR_CAPTURE_RING_MAGIC;
	s->ring->version = GR_CAPTURE_RING_VERSION;
	s->ring->slot_count = slot_count;
	s->ring->slot_size = GR_CAPTURE_SLOT_SIZE;
	s->ring->snap_len = s->snap_len;
	s->ring->n_ifaces = n_ifaces;
	s->ring->tsc_hz = rte_get_tsc_hz();
	s->ring->tsc_ref = rte_rdtsc();
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	s->ring->realtime_ref_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	LOG(INFO, "TSC calibration: tsc_hz=%lu tsc_ref=%lu realtime_ref=%lu ns",
	    s->ring->tsc_hz, s->ring->tsc_ref, s->ring->realtime_ref_ns);

	// Fill interface table.
	struct gr_capture_iface *itbl = gr_capture_ring_ifaces(s->ring);
	uint16_t idx = 0;
	iface = NULL;
	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
		const struct iface_info_port *port = iface_info_port(iface);
		itbl[idx].iface_id = iface->id;
		itbl[idx].port_id = port->port_id;
		memccpy(itbl[idx].name, iface->name, 0, IFNAMSIZ);
		itbl[idx].name[IFNAMSIZ - 1] = '\0';
		idx++;
	}

	// Set up HW timestamps if requested by the consumer.
	//
	// The ts_clock value comes from the capture start API request,
	// which the pcap-grout.so plugin sets based on tcpdump's -j flag:
	//   tcpdump -j adapter          → GR_CAPTURE_TS_NS      (no calibration)
	//   tcpdump -j adapter_unsynced → GR_CAPTURE_TS_RAW_NIC (100ms calibration)
	//   tcpdump (default)           → GR_CAPTURE_TS_TSC      (skips this block)
	//
	// GR_CAPTURE_TS_NS: the mlx5 driver already converts the NIC clock
	// to real-time nanoseconds (via tx_pp or wait_on_time). No extra
	// calibration needed — capture starts instantly.
	//
	// GR_CAPTURE_TS_RAW_NIC: raw NIC clock ticks are stored. The consumer
	// needs nic_hz to convert, so we measure it here with a 100ms delay.
	// This only runs when the user explicitly requests -j adapter_unsynced.
	if (ts_clock == GR_CAPTURE_TS_NS || ts_clock == GR_CAPTURE_TS_RAW_NIC) {
		int off = rte_mbuf_dynfield_lookup("rte_dynfield_timestamp", NULL);
		int bit = rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp", NULL);
		if (off >= 0 && bit >= 0) {
			s->hw_timestamp = true;
			s->ts_dynfield_off = off;
			s->ts_dynflag = 1ULL << bit;
			s->ring->ts_clock = ts_clock;
			if (ts_clock == GR_CAPTURE_TS_RAW_NIC) {
				// Calibrate NIC clock: two paired reads with a
				// 100ms delay for a stable frequency estimate.
				uint16_t port_id = UINT16_MAX;
				struct iface *i = NULL;
				uint64_t tmp;
				while ((i = iface_next(GR_IFACE_TYPE_PORT, i)) != NULL) {
					const struct iface_info_port *port = iface_info_port(i);
					if (rte_eth_read_clock(port->port_id, &tmp) == 0) {
						port_id = port->port_id;
						break;
					}
				}
				if (port_id != UINT16_MAX) {
					uint64_t nic_start, nic_end;
					struct timespec t_start, t_end;
					rte_eth_read_clock(port_id, &nic_start);
					clock_gettime(CLOCK_REALTIME, &t_start);
					usleep(100000); // 100ms
					rte_eth_read_clock(port_id, &nic_end);
					clock_gettime(CLOCK_REALTIME, &t_end);
					uint64_t wall_ns =
						(uint64_t)(t_end.tv_sec - t_start.tv_sec) * 1000000000ULL
						+ t_end.tv_nsec - t_start.tv_nsec;
					if (wall_ns > 0 && nic_end > nic_start)
						s->ring->nic_hz = (nic_end - nic_start)
							* 1000000000ULL / wall_ns;
					s->ring->nic_ref = nic_end;
					s->ring->realtime_ref_ns =
						(uint64_t)t_end.tv_sec * 1000000000ULL
						+ t_end.tv_nsec;
				} else {
					LOG(WARNING, "no port supports rte_eth_read_clock, "
					    "raw NIC timestamps unavailable");
				}
				LOG(INFO, "NIC clock calibration: %s (%s) nic_hz=%lu "
				    "nic_ref=%lu wall_ref=%lu ns (100ms sample)",
				    i ? i->name : "?",
				    i ? iface_info_port(i)->devargs : "?",
				    s->ring->nic_hz,
				    s->ring->nic_ref, s->ring->realtime_ref_ns);
			} else {
				LOG(INFO, "capture using NIC hardware timestamps (nanoseconds)");
			}
		} else {
			LOG(NOTICE, "HW timestamps requested but not available, using TSC");
		}
	}

	active_capture = s;
	capture_set_flags(s);

	LOG(INFO, "capture started iface_id=%u snap_len=%u ts_clock=%s",
	    iface_id, s->snap_len,
	    s->hw_timestamp ? "adapter" : "host");
	return s;

err_close:
	close(s->shm_fd);
err_free:
	free(s);
	return NULL;
}

int capture_session_set_filter(
	struct capture_session *s,
	const void *bpf_insns,
	uint16_t bpf_len
) {
#ifdef RTE_LIB_BPF
	struct rte_bpf *old = s->bpf;

	if (bpf_len == 0) {
		s->bpf_jit_func = NULL;
		s->bpf = NULL;
		if (old != NULL)
			rte_bpf_destroy(old);
		LOG(INFO, "capture filter cleared");
		return 0;
	}

	// Build a struct bpf_program from the raw bytecode.
	struct bpf_program prog = {
		.bf_len = bpf_len,
		.bf_insns = (struct bpf_insn *)(uintptr_t)bpf_insns,
	};

	// Convert classic BPF (libpcap format) to eBPF.
	struct rte_bpf_prm *prm = rte_bpf_convert(&prog);
	if (prm == NULL) {
		LOG(ERR, "rte_bpf_convert: %s", rte_strerror(rte_errno));
		return errno_set(EINVAL);
	}

	// JIT compile to native code.
	struct rte_bpf *bpf = rte_bpf_load(prm);
	rte_free(prm);
	if (bpf == NULL) {
		LOG(ERR, "rte_bpf_load: %s", rte_strerror(rte_errno));
		return errno_set(EINVAL);
	}

	struct rte_bpf_jit jit;
	if (rte_bpf_get_jit(bpf, &jit) < 0 || jit.func == NULL) {
		LOG(NOTICE, "BPF JIT not available, using interpreter");
		jit.func = NULL;
	}

	s->bpf_jit_func = jit.func;
	s->bpf = bpf;

	if (old != NULL)
		rte_bpf_destroy(old);

	LOG(INFO, "capture filter installed (%u instructions, JIT %s)",
	    bpf_len, jit.func ? "enabled" : "disabled");
	return 0;
#else
	(void)s;
	(void)bpf_insns;
	if (bpf_len > 0) {
		LOG(ERR, "BPF filter not supported (DPDK built without rte_bpf)");
		return errno_set(ENOTSUP);
	}
	return 0;
#endif
}

void capture_session_stop(struct capture_session *s) {
	if (s == NULL || active_capture != s)
		return;

	capture_clear_flags(s);
	active_capture = NULL;

#ifdef RTE_LIB_BPF
	if (s->bpf != NULL)
		rte_bpf_destroy(s->bpf);
#endif
	uint64_t bpf_passed = atomic_load(&s->bpf_passed);
	uint64_t bpf_filtered = atomic_load(&s->bpf_filtered);

	if (s->ring != NULL) {
		// Signal consumers that the session is gone. Consumers
		// check ring->magic in their poll loop and exit when
		// it changes. The mmap survives close so this write
		// is visible to any process still mapped.
		s->ring->magic = 0;
		munmap(s->ring, s->shm_size);
	}
	if (s->shm_fd >= 0)
		close(s->shm_fd);
	free(s);

	LOG(INFO, "capture stopped (bpf_passed=%lu bpf_filtered=%lu)",
	    bpf_passed, bpf_filtered);
}

static void capture_init(struct event_base *) {
}

static void capture_fini(struct event_base *) {
	if (active_capture != NULL)
		capture_session_stop(active_capture);
}

static struct gr_module capture_module = {
	.name = "capture",
	.depends_on = "iface*,trace",
	.init = capture_init,
	.fini = capture_fini,
};

RTE_INIT(capture_constructor) {
	gr_register_module(&capture_module);
	gr_event_subscribe(GR_EVENT_IFACE_POST_ADD, iface_add_callback);
}
