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

#if defined(RTE_LIB_BPF) && defined(RTE_HAS_LIBPCAP)
#include <rte_bpf.h>
#include <rte_malloc.h>
#include <pcap/bpf.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CAPTURE_SNAP_MAX 4096

_Atomic(struct capture_session *) iface_capture[GR_MAX_IFACES];

static struct capture_session *active_capture;
static unsigned capture_seq;

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

struct capture_session *capture_session_start(uint16_t iface_id, uint32_t snap_len) {
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

	snprintf(s->shm_path, sizeof(s->shm_path), "/grout-capture-%u", capture_seq++);

	int fd = shm_open(s->shm_path, O_CREAT | O_RDWR | O_EXCL, 0644);
	if (fd < 0) {
		LOG(ERR, "shm_open(%s): %s", s->shm_path, strerror(errno));
		goto err_free;
	}
	if (ftruncate(fd, s->shm_size) < 0) {
		LOG(ERR, "ftruncate(%s): %s", s->shm_path, strerror(errno));
		close(fd);
		shm_unlink(s->shm_path);
		goto err_free;
	}
	s->ring = mmap(NULL, s->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (s->ring == MAP_FAILED) {
		LOG(ERR, "mmap(%s): %s", s->shm_path, strerror(errno));
		shm_unlink(s->shm_path);
		s->ring = NULL;
		goto err_free;
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

	active_capture = s;
	capture_set_flags(s);

	LOG(INFO, "capture started iface_id=%u snap_len=%u shm=%s",
	    iface_id, s->snap_len, s->shm_path);
	return s;

err_free:
	free(s);
	return NULL;
}

int capture_session_set_filter(
	struct capture_session *s,
	const void *bpf_insns,
	uint16_t bpf_len
) {
#if defined(RTE_LIB_BPF) && defined(RTE_HAS_LIBPCAP)
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

#if defined(RTE_LIB_BPF) && defined(RTE_HAS_LIBPCAP)
	if (s->bpf != NULL)
		rte_bpf_destroy(s->bpf);
#endif
	uint64_t bpf_passed = atomic_load(&s->bpf_passed);
	uint64_t bpf_filtered = atomic_load(&s->bpf_filtered);

	if (s->ring != NULL) {
		// Signal consumers that the session is gone. Consumers
		// check ring->magic in their poll loop and exit when
		// it changes. The mmap survives shm_unlink so this
		// write is visible to any process still mapped.
		s->ring->magic = 0;
		munmap(s->ring, s->shm_size);
		shm_unlink(s->shm_path);
	}
	free(s);

	LOG(INFO, "capture stopped (bpf_passed=%lu bpf_filtered=%lu)",
	    bpf_passed, bpf_filtered);
}

static void capture_cleanup_stale(void) {
	glob_t g;
	if (glob("/dev/shm/grout-capture-*", GLOB_NOSORT, NULL, &g) == 0) {
		for (size_t i = 0; i < g.gl_pathc; i++) {
			const char *path = g.gl_pathv[i];
			const char *name = path + strlen("/dev/shm");
			LOG(NOTICE, "cleaning up stale capture shm %s", name);
			shm_unlink(name);
		}
		globfree(&g);
	}
}

static void capture_init(struct event_base *) {
	capture_cleanup_stale();
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
