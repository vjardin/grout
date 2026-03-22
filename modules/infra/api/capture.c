// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#include <gr_api.h>
#include <gr_capture.h>
#include <gr_infra.h>
#include <gr_module.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct api_out capture_start(const void *request, struct api_ctx *) {
	const struct gr_capture_start_req *req = request;

	struct capture_session *s = capture_session_start(req->iface_id, req->snap_len, req->ts_clock);
	if (s == NULL)
		return api_out(errno, 0, NULL);

	// dup the fd so the session keeps its own copy; the server
	// closes the returned fd after sending it via SCM_RIGHTS.
	int fd = dup(s->shm_fd);
	if (fd < 0) {
		capture_session_stop(s);
		return api_out(errno, 0, NULL);
	}

	struct gr_capture_start_resp *resp = calloc(1, sizeof(*resp));
	if (resp == NULL) {
		close(fd);
		capture_session_stop(s);
		return api_out(ENOMEM, 0, NULL);
	}
	resp->shm_size = s->shm_size;

	return api_out_fd(0, sizeof(*resp), resp, fd);
}

static struct api_out capture_stop(const void * /*request*/, struct api_ctx *) {
	capture_session_stop(capture_session_get());
	return api_out(0, 0, NULL);
}

static struct api_out capture_list(const void * /*request*/, struct api_ctx *ctx) {
	struct capture_session *s = capture_session_get();
	if (s != NULL) {
		struct gr_capture_info info = {
			.iface_id = s->iface_id,
			.snap_len = s->snap_len,
			.pkt_count = atomic_load(&s->ring->prod_head),
			.drops = atomic_load(&s->drops),
		};
		api_send(ctx, sizeof(info), &info);
	}

	return api_out(0, 0, NULL);
}

static struct api_out capture_set_filter(const void *request, struct api_ctx *) {
	const struct gr_capture_set_filter_req *req = request;
	struct capture_session *s = capture_session_get();

	if (s == NULL)
		return api_out(ENOENT, 0, NULL);

	int ret = capture_session_set_filter(s, req->bpf_insns, req->bpf_len);
	if (ret < 0)
		return api_out(-ret, 0, NULL);

	return api_out(0, 0, NULL);
}

RTE_INIT(capture_api_init) {
	gr_api_handler(GR_CAPTURE_START, capture_start);
	gr_api_handler(GR_CAPTURE_STOP, capture_stop);
	gr_api_handler(GR_CAPTURE_LIST, capture_list);
	gr_api_handler(GR_CAPTURE_SET_FILTER, capture_set_filter);
}
