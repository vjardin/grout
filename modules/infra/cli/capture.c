// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#include <gr_api.h>
#include <gr_capture_ring.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>

#include <ecoli.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// pcapng constants — no standard C header exists for the format.
// See https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html
#define PCAPNG_BT_SHB 0x0A0D0D0A
#define PCAPNG_BT_IDB 0x00000001
#define PCAPNG_BT_EPB 0x00000006

// pcapng option types
#define PCAPNG_OPT_END       0
#define PCAPNG_OPT_IF_NAME   2
#define PCAPNG_OPT_IF_TSRESOL 9
#define PCAPNG_EPB_FLAGS     2

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D

#define DLT_EN10MB 1

static inline uint32_t pcapng_pad4(uint32_t len) {
	return (len + 3) & ~3u;
}

static int pcapng_write_shb(FILE *f) {
	struct {
		uint32_t type, length;
		uint32_t bom;
		uint16_t major, minor;
		int64_t section_len;
		uint32_t length2;
	} __attribute__((packed)) shb = {
		.type = PCAPNG_BT_SHB,
		.bom = PCAPNG_BYTE_ORDER_MAGIC,
		.major = 1,
		.minor = 0,
		.section_len = -1, // unspecified
	};
	shb.length = sizeof(shb);
	shb.length2 = sizeof(shb);
	return fwrite(&shb, sizeof(shb), 1, f) == 1 ? 0 : -1;
}

static int pcapng_write_idb(FILE *f, const char *name, uint32_t snap_len) {
	uint16_t name_len = strlen(name);
	uint16_t name_padded = pcapng_pad4(name_len);
	// option: if_name
	uint32_t opt_name_size = 4 + name_padded; // type(2) + len(2) + padded data
	// option: if_tsresol = 9 (nanoseconds)
	uint32_t opt_tsresol_size = 4 + 4; // type(2) + len(2) + 1 byte padded to 4
	// option: end
	uint32_t opt_end_size = 4;
	uint32_t opts_size = opt_name_size + opt_tsresol_size + opt_end_size;

	struct {
		uint32_t type, length;
		uint16_t link_type, reserved;
		uint32_t snap_len;
	} __attribute__((packed)) idb = {
		.type = PCAPNG_BT_IDB,
		.link_type = DLT_EN10MB,
		.snap_len = snap_len,
	};
	idb.length = sizeof(idb) + opts_size + 4; // +4 for trailing length

	if (fwrite(&idb, sizeof(idb), 1, f) != 1)
		return -1;

	// if_name option
	uint16_t opt_hdr[2] = {PCAPNG_OPT_IF_NAME, name_len};
	fwrite(opt_hdr, 4, 1, f);
	fwrite(name, 1, name_len, f);
	char pad[4] = {0};
	if (name_padded > name_len)
		fwrite(pad, 1, name_padded - name_len, f);

	// if_tsresol option (1 byte = 9 for nanoseconds)
	uint16_t tsresol_hdr[2] = {PCAPNG_OPT_IF_TSRESOL, 1};
	fwrite(tsresol_hdr, 4, 1, f);
	uint8_t tsresol = 9;
	fwrite(&tsresol, 1, 1, f);
	fwrite(pad, 1, 3, f); // pad to 4

	// opt_endofopt
	uint32_t opt_end = 0;
	fwrite(&opt_end, 4, 1, f);

	fwrite(&idb.length, 4, 1, f);
	return 0;
}

static int pcapng_write_epb(
	FILE *f,
	uint32_t iface_idx,
	uint64_t timestamp_ns,
	uint32_t cap_len,
	uint32_t pkt_len,
	const uint8_t *data,
	uint8_t direction
) {
	uint32_t data_padded = pcapng_pad4(cap_len);
	// pcapng EPB flags: bits 0-1 = direction (GR_CAPTURE_DIR_IN/OUT
	// match the pcapng inbound/outbound values).
	uint32_t flags_val = direction & 0x3;
	uint32_t opts_size = 4 + 4 + 4; // flags opt (type+len+value) + opt_end
	uint32_t block_len = 28 + data_padded + opts_size + 4; // 28 = EPB header

	struct {
		uint32_t type, length;
		uint32_t iface_id;
		uint32_t ts_hi, ts_lo;
		uint32_t cap_len, orig_len;
	} __attribute__((packed)) epb = {
		.type = PCAPNG_BT_EPB,
		.length = block_len,
		.iface_id = iface_idx,
		.ts_hi = (uint32_t)(timestamp_ns >> 32),
		.ts_lo = (uint32_t)timestamp_ns,
		.cap_len = cap_len,
		.orig_len = pkt_len,
	};

	if (fwrite(&epb, sizeof(epb), 1, f) != 1)
		return -1;
	fwrite(data, 1, cap_len, f);
	char pad[4] = {0};
	if (data_padded > cap_len)
		fwrite(pad, 1, data_padded - cap_len, f);

	// epb_flags option
	uint16_t flags_hdr[2] = {PCAPNG_EPB_FLAGS, 4};
	fwrite(flags_hdr, 4, 1, f);
	fwrite(&flags_val, 4, 1, f);
	// opt_endofopt
	uint32_t opt_end = 0;
	fwrite(&opt_end, 4, 1, f);

	fwrite(&block_len, 4, 1, f);
	return 0;
}

static volatile sig_atomic_t capture_running;

static void capture_sigint(int /*sig*/) {
	capture_running = 0;
}

// Map port_id to pcapng interface index (IDB order).
static int find_iface_idx(const struct gr_capture_ring *ring, uint16_t port_id) {
	const struct gr_capture_iface *ifaces = gr_capture_ring_ifaces_const(ring);
	for (uint16_t i = 0; i < ring->n_ifaces; i++) {
		if (ifaces[i].port_id == port_id)
			return i;
	}
	return 0;
}

static cmd_status_t capture_dump(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_capture_start_req req = {0};
	struct gr_iface *iface = NULL;

	if (arg_str(p, "all") != NULL) {
		req.iface_id = GR_IFACE_ID_UNDEF;
	} else {
		iface = iface_from_name(c, arg_str(p, "NAME"));
		if (iface == NULL)
			return CMD_ERROR;
		req.iface_id = iface->id;
		free(iface);
	}

	if (arg_u32(p, "SNAPLEN", &req.snap_len) < 0 && errno != ENOENT)
		return CMD_ERROR;

	// Send capture start and get shm path.
	void *resp_ptr = NULL;
	if (gr_api_client_send_recv(
		    c, GR_CAPTURE_START, sizeof(req), &req, &resp_ptr
	    ) < 0)
		return CMD_ERROR;

	struct gr_capture_start_resp *resp = resp_ptr;
	char shm_path[GR_CAPTURE_SHM_PATH_SIZE];
	memccpy(shm_path, resp->shm_path, 0, sizeof(shm_path));
	shm_path[sizeof(shm_path) - 1] = '\0';
	free(resp_ptr);

	// Open and map the shared ring.
	int shm_fd = shm_open(shm_path, O_RDWR, 0);
	if (shm_fd < 0) {
		errorf("shm_open(%s): %s", shm_path, strerror(errno));
		goto stop;
	}
	struct stat st;
	if (fstat(shm_fd, &st) < 0) {
		errorf("fstat: %s", strerror(errno));
		close(shm_fd);
		goto stop;
	}
	struct gr_capture_ring *ring = mmap(
		NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0
	);
	close(shm_fd);
	if (ring == MAP_FAILED) {
		errorf("mmap: %s", strerror(errno));
		goto stop;
	}
	if (ring->magic != GR_CAPTURE_RING_MAGIC) {
		errorf("invalid capture ring magic");
		munmap(ring, st.st_size);
		goto stop;
	}

	// Write pcapng file header (SHB + IDBs).
	if (pcapng_write_shb(stdout) < 0) {
		munmap(ring, st.st_size);
		goto stop;
	}
	const struct gr_capture_iface *ifaces = gr_capture_ring_ifaces_const(ring);
	for (uint16_t i = 0; i < ring->n_ifaces; i++) {
		if (pcapng_write_idb(stdout, ifaces[i].name, ring->snap_len) < 0) {
			munmap(ring, st.st_size);
			goto stop;
		}
	}
	fflush(stdout);

	// Set up signal handlers to stop capture cleanly.
	struct sigaction sa = {.sa_handler = capture_sigint};
	struct sigaction old_int, old_term;
	sigaction(SIGINT, &sa, &old_int);
	sigaction(SIGTERM, &sa, &old_term);
	capture_running = 1;

	// Read loop: poll ring, format pcapng EPBs, write stdout.
	struct gr_capture_slot slot;
	while (capture_running && ring->magic == GR_CAPTURE_RING_MAGIC) {
		if (!gr_capture_ring_dequeue(ring, &slot)) {
			fflush(stdout);
			usleep(100);
			continue;
		}

		uint64_t ts_ns = gr_capture_slot_timestamp_ns(ring, &slot);
		int iface_idx = find_iface_idx(ring, slot.port_id);

		if (pcapng_write_epb(
			    stdout, iface_idx, ts_ns,
			    slot.cap_len, slot.pkt_len,
			    slot.data, slot.direction
		    ) < 0)
			break;
	}

	sigaction(SIGINT, &old_int, NULL);
	sigaction(SIGTERM, &old_term, NULL);
	munmap(ring, st.st_size);

stop:
	gr_api_client_send_recv(c, GR_CAPTURE_STOP, 0, NULL, NULL);
	return CMD_SUCCESS;
}

static cmd_status_t capture_stop(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_CAPTURE_STOP, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t capture_list(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_capture_info *info;
	int ret;

	gr_api_client_stream_foreach (
		info, ret, c, GR_CAPTURE_LIST, 0, NULL
	) {
		if (info->iface_id == GR_IFACE_ID_UNDEF)
			printf("iface=all");
		else
			printf("iface_id=%u", info->iface_id);
		printf(" snap_len=%u pkts=%lu drops=%lu\n",
		       info->snap_len, info->pkt_count, info->drops);
	}

	if (ret < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define CAPTURE_CTX(root) CLI_CONTEXT(root, CTX_ARG("capture", "Packet capture."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CAPTURE_CTX(root),
		"dump (all|(iface NAME)) [snaplen SNAPLEN]",
		capture_dump,
		"Capture packets and write pcapng to stdout.",
		with_help("All interfaces.", ec_node_str("all", "all")),
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help(
			"Snap length in bytes (0 = full packet).",
			ec_node_uint("SNAPLEN", 0, UINT32_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CAPTURE_CTX(root),
		"stop",
		capture_stop,
		"Stop the active packet capture."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CAPTURE_CTX(root),
		"list",
		capture_list,
		"List active captures."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "capture",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
