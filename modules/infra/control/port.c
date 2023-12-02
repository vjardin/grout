// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_api.h>
#include <br_control.h>
#include <br_infra_msg.h>

#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

struct port_entry {
	uint16_t port_id;
	char name[64];
	TAILQ_ENTRY(port_entry) entries;
};
static TAILQ_HEAD(, port_entry) port_entries;

static int fill_port_info(struct port_entry *e, struct br_infra_port *port) {
	struct rte_eth_dev_info info;
	int ret;

	memset(port, 0, sizeof(*port));
	port->index = e->port_id;
	memccpy(port->name, e->name, 0, sizeof(port->name));

	if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
		return ret;
	if ((ret = rte_eth_dev_get_mtu(e->port_id, &port->mtu)) < 0)
		return ret;
	if ((ret = rte_eth_macaddr_get(e->port_id, (void *)&port->mac)) < 0)
		return ret;

	memccpy(port->device, rte_dev_name(info.device), 0, sizeof(port->device));

	return 0;
}

static struct api_out port_add(const void *request, void *response) {
	const struct br_infra_port_add_req *req = request;
	struct br_infra_port_add_resp *resp = response;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	struct rte_eth_dev_info info;
	struct port_entry *entry;
	int ret;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		return api_out(EEXIST, 0);
	}
	TAILQ_FOREACH(entry, &port_entries, entries) {
		if (strcmp(entry->name, req->name) != 0)
			continue;
		return api_out(EEXIST, 0);
	}

	if ((ret = rte_dev_probe(req->devargs)) < 0)
		return api_out(-ret, 0);

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id))
		return api_out(ENOENT, 0);

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL) {
		rte_eth_dev_info_get(port_id, &info);
		rte_eth_dev_close(port_id);
		rte_dev_remove(info.device);
		return api_out(ENOMEM, 0);
	}

	entry->port_id = port_id;
	memccpy(entry->name, req->name, 0, sizeof(entry->name));

	TAILQ_INSERT_TAIL(&port_entries, entry, entries);

	if ((ret = fill_port_info(entry, &resp->port)) < 0)
		return api_out(-ret, 0);

	return api_out(0, sizeof(*resp));
}

static struct port_entry *find_port(const char *name) {
	struct port_entry *entry;
	TAILQ_FOREACH(entry, &port_entries, entries) {
		if (strcmp(entry->name, name) == 0)
			return entry;
	}
	return NULL;
}

static struct api_out port_del(const void *request, void *response) {
	const struct br_infra_port_del_req *req = request;
	struct rte_eth_dev_info info;
	struct port_entry *entry;
	int ret;

	(void)response;

	TAILQ_FOREACH(entry, &port_entries, entries) {
		if (strcmp(entry->name, req->name) != 0)
			continue;
		break;
	}

	entry = find_port(req->name);
	if (entry == NULL)
		return api_out(ENODEV, 0);

	if ((ret = rte_eth_dev_info_get(entry->port_id, &info)) < 0)
		return api_out(-ret, 0);
	if ((ret = rte_eth_dev_close(entry->port_id)) < 0)
		return api_out(-ret, 0);
	if ((ret = rte_dev_remove(info.device)) < 0)
		return api_out(-ret, 0);

	TAILQ_REMOVE(&port_entries, entry, entries);
	free(entry);

	return api_out(0, 0);
}

static struct api_out port_get(const void *request, void *response) {
	const struct br_infra_port_get_req *req = request;
	struct br_infra_port_get_resp *resp = response;
	struct port_entry *entry;
	int ret;

	entry = find_port(req->name);
	if (entry == NULL)
		return api_out(ENODEV, 0);

	if ((ret = fill_port_info(entry, &resp->port)) < 0)
		return api_out(-ret, 0);

	return api_out(0, sizeof(*resp));
}

static struct api_out port_list(const void *request, void *response) {
	struct br_infra_port_list_resp *resp = response;
	struct port_entry *entry;
	int ret;

	(void)request;

	resp->n_ports = 0;

	TAILQ_FOREACH(entry, &port_entries, entries) {
		struct br_infra_port *port = &resp->ports[resp->n_ports];
		if ((ret = fill_port_info(entry, port)) < 0)
			return api_out(-ret, 0);
		resp->n_ports++;
	}

	return api_out(0, sizeof(*resp));
}

static struct br_api_handler port_add_handler = {
	.name = "port add",
	.request_type = BR_INFRA_PORT_ADD,
	.callback = port_add,
};
static struct br_api_handler port_del_handler = {
	.name = "port del",
	.request_type = BR_INFRA_PORT_DEL,
	.callback = port_del,
};
static struct br_api_handler port_get_handler = {
	.name = "port get",
	.request_type = BR_INFRA_PORT_GET,
	.callback = port_get,
};
static struct br_api_handler port_list_handler = {
	.name = "port list",
	.request_type = BR_INFRA_PORT_LIST,
	.callback = port_list,
};

RTE_INIT(control_infra_init) {
	TAILQ_INIT(&port_entries);
	br_register_api_handler(&port_add_handler);
	br_register_api_handler(&port_del_handler);
	br_register_api_handler(&port_get_handler);
	br_register_api_handler(&port_list_handler);
}
