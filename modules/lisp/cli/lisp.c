// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

#include "cli.h"
#include "cli_iface.h"
#include "cli_nexthop.h"
#include "display.h"

#include <gr_api.h>
#include <gr_lisp.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>

static void lisp_show(struct gr_api_client *c, const struct gr_iface *iface, struct gr_object *o) {
	const struct gr_iface_info_lisp *lisp = (const struct gr_iface_info_lisp *)iface->info;

	gr_object_field(o, "iid", GR_DISP_INT, "%u", lisp->iid);
	if (lisp->local != 0)
		gr_object_field(o, "local", 0, IP4_F, &lisp->local);
	if (!rte_ipv6_addr_is_unspec(&lisp->local6))
		gr_object_field(o, "local6", 0, IP6_F, &lisp->local6);
	gr_object_field(o, "encap_vrf", 0, "%s", iface_name_from_id(c, lisp->encap_vrf_id));
	gr_object_field(o, "rloc_filter", GR_DISP_BOOL, "%s", lisp->rloc_filter ? "true" : "false");
	gr_object_field(o, "eid_filter", GR_DISP_BOOL, "%s", lisp->eid_filter ? "true" : "false");
}

static void
lisp_list_info(struct gr_api_client *c, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_lisp *lisp = (const struct gr_iface_info_lisp *)iface->info;
	size_t n = 0;

	SAFE_BUF(snprintf, len, "iid=%u", lisp->iid);
	if (lisp->local != 0)
		SAFE_BUF(snprintf, len, " local=" IP4_F, &lisp->local);
	if (!rte_ipv6_addr_is_unspec(&lisp->local6))
		SAFE_BUF(snprintf, len, " local6=" IP6_F, &lisp->local6);
	SAFE_BUF(snprintf, len, " encap_vrf=%s", iface_name_from_id(c, lisp->encap_vrf_id));
	if (lisp->rloc_filter)
		SAFE_BUF(snprintf, len, " rloc_filter");
	if (lisp->eid_filter)
		SAFE_BUF(snprintf, len, " eid_filter");
err:
	return;
}

static struct cli_iface_type lisp_type = {
	.type_id = GR_IFACE_TYPE_LISP,
	.show = lisp_show,
	.list_info = lisp_list_info,
};

static uint64_t parse_lisp_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	const char *rloc_filter, *eid_filter;
	struct gr_iface_info_lisp *lisp;
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*lisp), update);

	lisp = (struct gr_iface_info_lisp *)iface->info;

	if (arg_u32(p, "IID", &lisp->iid) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_LISP_SET_IID;
	}

	if (arg_ip4(p, "LOCAL", &lisp->local) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_LISP_SET_LOCAL;
	}

	if (arg_ip6(p, "LOCAL6", &lisp->local6) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_LISP_SET_LOCAL6;
	}

	if (arg_str(p, "ENCAP_VRF") != NULL) {
		if (arg_vrf(c, p, "ENCAP_VRF", &lisp->encap_vrf_id) < 0)
			return 0;
		set_attrs |= GR_LISP_SET_ENCAP_VRF;
	}

	rloc_filter = arg_str(p, "RLOC_FILTER");
	if (rloc_filter != NULL) {
		lisp->rloc_filter = strcmp(rloc_filter, "on") == 0;
		set_attrs |= GR_LISP_SET_RLOC_FILTER;
	}

	eid_filter = arg_str(p, "EID_FILTER");
	if (eid_filter != NULL) {
		lisp->eid_filter = strcmp(eid_filter, "on") == 0;
		set_attrs |= GR_LISP_SET_EID_FILTER;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
}

static cmd_status_t lisp_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_iface_add_resp *resp;
	struct gr_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_lisp);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_LISP;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_lisp_args(c, p, &req->iface, false) == 0)
		goto err;

	if (gr_api_client_send_recv(c, GR_IFACE_ADD, len, req, &resp_ptr) < 0)
		goto err;

	free(req);
	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
err:
	free(req);
	return CMD_ERROR;
}

static cmd_status_t lisp_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_lisp);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_lisp_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static cmd_status_t lisp_nh_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_nexthop_info_lisp *lisp;
	struct gr_nh_add_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(*lisp);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	req->exist_ok = true;
	req->nh.type = GR_NH_T_LISP;
	req->nh.origin = GR_NH_ORIGIN_STATIC;

	if (arg_u32(p, "ID", &req->nh.nh_id) < 0 && errno != ENOENT)
		goto out;
	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_LISP, &req->nh.iface_id) < 0)
		goto out;

	lisp = (struct gr_nexthop_info_lisp *)req->nh.info;
	if (arg_ip_guess(p, "RLOC", &lisp->rloc.af, &lisp->rloc.addr) < 0)
		goto out;
	req->nh.stats = arg_str(p, "stats") != NULL;

	if (gr_api_client_send_recv(c, GR_NH_ADD, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

static void add_columns_lisp(struct gr_table *table) {
	gr_table_column(table, "RLOC", GR_DISP_LEFT);
}

static void fill_table_lisp(struct gr_table *table, unsigned start_col, const void *info) {
	const struct gr_nexthop_info_lisp *lisp = info;

	gr_table_cell(table, start_col, ADDR_F, ADDR_W(lisp->rloc.af), &lisp->rloc.addr);
}

static void fill_object_lisp(struct gr_object *o, const void *info) {
	const struct gr_nexthop_info_lisp *lisp = info;

	gr_object_field(o, "rloc", 0, ADDR_F, ADDR_W(lisp->rloc.af), &lisp->rloc.addr);
}

static struct cli_nexthop_formatter lisp_formatter = {
	.name = "lisp",
	.type = GR_NH_T_LISP,
	.add_columns = add_columns_lisp,
	.fill_table = fill_table_lisp,
	.fill_object = fill_object_lisp,
};

#define LISP_ATTRS_CMD                                                                             \
	"(local LOCAL),(local6 LOCAL6),(encap_vrf ENCAP_VRF),(rloc_filter RLOC_FILTER),"           \
	"(eid_filter EID_FILTER)"

#define LISP_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS,                                                                          \
		with_help(                                                                         \
			"Instance ID bound to the VRF of the interface (0-16777215).",             \
			ec_node_uint("IID", 0, GR_LISP_IID_MAX, 10)                                \
		),                                                                                 \
		with_help("Local IPv4 RLOC.", ec_node_re("LOCAL", IPV4_RE)),                       \
		with_help("Local IPv6 RLOC.", ec_node_re("LOCAL6", IPV6_RE)),                      \
		with_help(                                                                         \
			"L3 routing domain name of the RLOCs.",                                    \
			ec_node_dyn("ENCAP_VRF", complete_vrf_names, NULL)                         \
		),                                                                                 \
		with_help(                                                                         \
			"Drop the packets that do not come from the RLOC of a nexthop.",           \
			EC_NODE_OR("RLOC_FILTER", ec_node_str("", "on"), ec_node_str("", "off"))   \
		),                                                                                 \
		with_help(                                                                         \
			"Drop the packets whose source EID is not mapped to their source RLOC.",   \
			EC_NODE_OR("EID_FILTER", ec_node_str("", "on"), ec_node_str("", "off"))    \
		)

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"lisp NAME iid IID [" LISP_ATTRS_CMD "," IFACE_ATTRS_CMD "]",
		lisp_add,
		"Create a new LISP tunnel interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		LISP_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"lisp NAME (name NEW_NAME),(iid IID)," LISP_ATTRS_CMD "," IFACE_ATTRS_CMD,
		lisp_set,
		"Modify LISP parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_LISP))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		LISP_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		NEXTHOP_ADD_CTX(root),
		"lisp iface IFACE rloc RLOC [(id ID),(stats)]",
		lisp_nh_add,
		"Add a new LISP nexthop.",
		with_help(
			"LISP interface.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_LISP))
		),
		with_help("Remote RLOC.", ec_node_re("RLOC", IP_ANY_RE)),
		with_help("Nexthop ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help(
			"Count the packets sent to and received from this RLOC.",
			ec_node_str("stats", "stats")
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "lisp",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&lisp_type);
	cli_nexthop_formatter_register(&lisp_formatter);
}
