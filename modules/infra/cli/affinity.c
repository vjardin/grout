// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_display.h>
#include <gr_infra.h>
#include <gr_string.h>

#include <ecoli.h>

#include <string.h>

static cmd_status_t affinity_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_affinity_cpu_set_req req = {0};
	const char *arg;

	if ((arg = arg_str(p, "CONTROL")) != NULL) {
		if (cpuset_parse(&req.control_cpus, arg) < 0)
			return CMD_ERROR;
	}
	if ((arg = arg_str(p, "DATAPATH")) != NULL) {
		if (cpuset_parse(&req.datapath_cpus, arg) < 0)
			return CMD_ERROR;
	}

	if (gr_api_client_send_recv(c, GR_AFFINITY_CPU_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t affinity_show(struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_affinity_cpu_get_resp resp;
	void *resp_ptr = NULL;
	char buf[BUFSIZ];

	if (gr_api_client_send_recv(c, GR_AFFINITY_CPU_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	memcpy(&resp, resp_ptr, sizeof(resp));
	free(resp_ptr);

	struct gr_object *o = gr_object_new(NULL);

	if (cpuset_format(buf, sizeof(buf), &resp.control_cpus) == 0)
		gr_object_field(o, "control_cpus", 0, "%s", buf);

	if (cpuset_format(buf, sizeof(buf), &resp.datapath_cpus) == 0)
		gr_object_field(o, "datapath_cpus", 0, "%s", buf);

	gr_object_free(o);

	return CMD_SUCCESS;
}

static cmd_status_t rxq_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_affinity_rxq_set_req req;

	if (arg_iface(c, p, "NAME", GR_IFACE_TYPE_PORT, &req.iface_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "RXQ", &req.rxq_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "CPU", &req.cpu_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_AFFINITY_RXQ_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t rxq_list(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_port_rxq_map *q;
	int ret;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "CPU_ID", GR_DISP_RIGHT | GR_DISP_INT); // 0
	gr_table_column(table, "IFACE", GR_DISP_LEFT); // 1
	gr_table_column(table, "RXQ_ID", GR_DISP_RIGHT | GR_DISP_INT); // 2
	gr_table_column(table, "ENABLED", GR_DISP_BOOL); // 3

	gr_api_client_stream_foreach (q, ret, c, GR_AFFINITY_RXQ_LIST, 0, NULL) {
		gr_table_cell(table, 0, "%u", q->cpu_id);
		gr_table_cell(table, 1, "%s", iface_name_from_id(c, q->iface_id));
		gr_table_cell(table, 2, "%u", q->rxq_id);
		gr_table_cell(table, 3, "%s", q->enabled ? "true" : "false");

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t txq_rate_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_txq_rate_set_req req;
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "NAME"));

	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (arg_u16(p, "TXQ", &req.txq_id) < 0)
		return CMD_ERROR;
	if (arg_u32(p, "RATE", &req.rate_mbps) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_TXQ_RATE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static const char *queue_state_name(uint8_t state) {
	switch (state) {
	case 0:
		return "stopped";
	case 1:
		return "started";
	default:
		return "?";
	}
}

static cmd_status_t queue_list_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_queue_list_req req = {.iface_id = GR_IFACE_ID_UNDEF};
	const struct gr_port_queue_info *q;
	struct libscols_table *table;
	int ret;

	const char *name = arg_str(p, "NAME");
	if (name != NULL) {
		struct gr_iface *iface = iface_from_name(c, name);
		if (iface == NULL)
			return CMD_ERROR;
		req.iface_id = iface->id;
		free(iface);
	}

	table = scols_new_table();
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "DIR", 0, 0);
	scols_table_new_column(table, "QUEUE", 0, 0);
	scols_table_new_column(table, "NB_DESC", 0, 0);
	scols_table_new_column(table, "STATE", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (q, ret, c, GR_INFRA_QUEUE_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);

		struct gr_iface *iface = iface_from_id(c, q->iface_id);
		if (iface != NULL)
			scols_line_sprintf(line, 0, "%s", iface->name);
		else
			scols_line_sprintf(line, 0, "%u", q->iface_id);
		free(iface);
		scols_line_sprintf(line, 1, "%s", q->is_tx ? "tx" : "rx");
		scols_line_sprintf(line, 2, "%u", q->queue_id);
		scols_line_sprintf(line, 3, "%u", q->nb_desc);
		scols_line_sprintf(line, 4, "%s", queue_state_name(q->queue_state));
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define CPU_LIST_RE "^[0-9,-]+$"
#define AFFINITY_ARG CTX_ARG("affinity", "CPU and physical queue affinity.")
#define CPU_CTX(root) CLI_CONTEXT(root, AFFINITY_ARG, CTX_ARG("cpus", "CPU masks."))
#define QMAP_CTX(root) CLI_CONTEXT(root, AFFINITY_ARG, CTX_ARG("qmap", "Physical RXQ mappings."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CPU_CTX(root),
		"set (control CONTROL),(datapath DATAPATH)",
		affinity_set,
		"Change the CPU affinity lists.",
		with_help(
			"CPUs reserved for control plane threads.",
			ec_node_re("CONTROL", CPU_LIST_RE)
		),
		with_help(
			"CPUs reserved for datapath worker threads.",
			ec_node_re("DATAPATH", CPU_LIST_RE)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(CPU_CTX(root), "[show]", affinity_show, "Display CPU affinity lists.");
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		QMAP_CTX(root),
		"set NAME rxq RXQ cpu CPU",
		rxq_set,
		"Set DPDK port queue affinity.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("RX queue ID.", ec_node_uint("RXQ", 0, UINT16_MAX - 1, 10)),
		with_help("Worker CPU ID.", ec_node_uint("CPU", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		QMAP_CTX(root),
		"rate NAME txq TXQ limit RATE",
		txq_rate_set,
		"Set TX queue rate limit in Mbps (0 to disable).",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("TX queue ID.", ec_node_uint("TXQ", 0, UINT16_MAX - 1, 10)),
		with_help(
			"Rate limit in Mbps (0 to disable).",
			ec_node_uint("RATE", 0, UINT32_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		QMAP_CTX(root),
		"info NAME",
		queue_list_show,
		"Display per-queue details for a port.",
		with_help(
			"Port interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		QMAP_CTX(root),
		"info",
		queue_list_show,
		"Display per-queue details for all ports."
	);
	if (ret < 0)
		return ret;
	// [show] must be last: the OR node returns the first match,
	// and [show] matches 0 tokens (optional), shadowing later alternatives.
	ret = CLI_COMMAND(QMAP_CTX(root), "[show]", rxq_list, "Display DPDK port RXQ affinity.");
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "infra affinity",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
