// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "worker_priv.h"

#include <br_iface.h>
#include <br_infra.h>
#include <br_log.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_stb_ds.h>
#include <br_worker.h>

#include <numa.h>
#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define ETHER_FRAME_GAP 20

uint32_t port_get_rxq_buffer_us(uint16_t port_id, uint16_t rxq_id) {
	uint32_t frame_size, pkts_per_us;
	struct rte_eth_rxq_info qinfo;
	struct rte_eth_link link;
	int ret;

	if ((ret = rte_eth_link_get_nowait(port_id, &link)) < 0)
		return 0;
	switch (link.link_speed) {
	case RTE_ETH_SPEED_NUM_NONE:
	case RTE_ETH_SPEED_NUM_UNKNOWN:
		return 0;
	}

	if (rte_eth_rx_queue_info_get(port_id, rxq_id, &qinfo) < 0)
		return 0;

	// minimum ethernet frame size on the wire
	frame_size = (RTE_ETHER_MIN_LEN + ETHER_FRAME_GAP) * 8;

	// reported speed by driver is in megabit/s and we need a result in micro seconds.
	// we can use link_speed without any conversion: megabit/s is equivalent to bit/us
	pkts_per_us = link.link_speed / frame_size;
	if (pkts_per_us == 0)
		return 0;

	return qinfo.nb_desc / pkts_per_us;
}

static uint16_t get_rxq_size(struct iface_info_port *p, const struct rte_eth_dev_info *info) {
	if (p->rxq_size == 0)
		p->rxq_size = info->default_rxportconf.ring_size;
	if (p->rxq_size == 0)
		p->rxq_size = RTE_ETH_DEV_FALLBACK_RX_RINGSIZE;
	return p->rxq_size;
}

static uint16_t get_txq_size(struct iface_info_port *p, const struct rte_eth_dev_info *info) {
	if (p->txq_size == 0)
		p->txq_size = info->default_txportconf.ring_size;
	if (p->txq_size == 0)
		p->txq_size = RTE_ETH_DEV_FALLBACK_TX_RINGSIZE;
	return p->txq_size;
}

static struct rte_eth_conf default_port_config = {
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL, // use default key
			.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
		},
	},
	.rxmode = {
		.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
	},
};

static void port_queue_assign(struct iface_info_port *p) {
	int socket_id = rte_eth_dev_socket_id(p->port_id);
	struct worker *worker, *default_worker = NULL;
	// XXX: can we assume there will never be more than 64 rxqs per port?
	uint64_t rxq_ids = 0;
	uint16_t txq = 0;

	STAILQ_FOREACH (worker, &workers, next) {
		struct queue_map tx_qmap = {
			.port_id = p->port_id,
			.queue_id = txq,
			.enabled = false,
		};
		for (int i = 0; i < arrlen(worker->txqs); i++) {
			if (worker->txqs[i].port_id == p->port_id) {
				// ensure no duplicates
				arrdelswap(worker->txqs, i);
				i--;
			}
		}
		// assign one txq to every worker
		arrpush(worker->txqs, tx_qmap);
		txq++;

		for (int i = 0; i < arrlen(worker->rxqs); i++) {
			struct queue_map *qmap = &worker->rxqs[i];
			if (qmap->port_id == p->port_id) {
				if (qmap->queue_id < p->n_rxq) {
					// rxq already assigned to a worker
					rxq_ids |= 1 << qmap->queue_id;
				} else {
					// remove extraneous rxq
					arrdelswap(worker->rxqs, i);
					i--;
				}
			}
		}
		if (socket_id == SOCKET_ID_ANY || socket_id == numa_node_of_cpu(worker->cpu_id)) {
			default_worker = worker;
		}
	}
	assert(default_worker != NULL);
	for (uint16_t rxq = 0; rxq < p->n_rxq; rxq++) {
		if (rxq_ids & (1 << rxq))
			continue;
		struct queue_map rx_qmap = {
			.port_id = p->port_id,
			.queue_id = rxq,
			.enabled = false,
		};
		arrpush(default_worker->rxqs, rx_qmap);
	}
}

static int port_configure(struct iface_info_port *p) {
	int socket_id = rte_eth_dev_socket_id(p->port_id);
	struct rte_eth_conf conf = default_port_config;
	uint16_t rxq_size, txq_size;
	struct rte_eth_dev_info info;
	uint32_t mbuf_count;
	char pool_name[128];
	int ret;

	// ensure there is a datapath worker running on the socket where the port is
	if ((ret = worker_ensure_default(socket_id)) < 0)
		return ret;

	// FIXME: deal with drivers that do not support more than 1 (or N) tx queues
	p->n_txq = worker_count();
	if (p->n_rxq == 0)
		p->n_rxq = 1;

	if ((ret = rte_eth_dev_info_get(p->port_id, &info)) < 0)
		return errno_log(-ret, "rte_eth_dev_info_get");

	rxq_size = get_rxq_size(p, &info);
	txq_size = get_txq_size(p, &info);

	rte_mempool_free(p->pool);
	p->pool = NULL;

	// Limit configured rss hash functions to only those supported by hardware
	conf.rx_adv_conf.rss_conf.rss_hf &= info.flow_type_rss_offloads;
	if (conf.rx_adv_conf.rss_conf.rss_hf == 0)
		conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
	else
		conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	conf.rxmode.offloads &= info.rx_offload_capa;

	if ((ret = rte_eth_dev_configure(p->port_id, p->n_rxq, p->n_txq, &conf)) < 0)
		return errno_log(-ret, "rte_eth_dev_configure");

	mbuf_count = rxq_size * p->n_rxq;
	mbuf_count += txq_size * p->n_txq;
	mbuf_count += RTE_GRAPH_BURST_SIZE;
	mbuf_count = rte_align32pow2(mbuf_count) - 1;
	snprintf(pool_name, sizeof(pool_name), "mbuf_%s", rte_dev_name(info.device));
	p->pool = rte_pktmbuf_pool_create(
		pool_name,
		mbuf_count,
		256, // cache_size
		0, // priv_size
		RTE_MBUF_DEFAULT_BUF_SIZE,
		socket_id
	);
	if (p->pool == NULL)
		return errno_log(rte_errno, "rte_pktmbuf_pool_create");

	// initialize rx/tx queues
	for (size_t q = 0; q < p->n_rxq; q++) {
		ret = rte_eth_rx_queue_setup(p->port_id, q, rxq_size, socket_id, NULL, p->pool);
		if (ret < 0)
			return errno_log(-ret, "rte_eth_rx_queue_setup");
	}
	for (size_t q = 0; q < p->n_txq; q++) {
		ret = rte_eth_tx_queue_setup(p->port_id, q, txq_size, socket_id, NULL);
		if (ret < 0)
			return errno_log(-ret, "rte_eth_tx_queue_setup");
	}

	port_queue_assign(p);

	p->configured = true;

	return 0;
}

int iface_port_reconfig(struct iface *iface, uint64_t set_attrs, const void *api_info) {
	struct iface_info_port *p = (struct iface_info_port *)iface->info;
	const struct br_iface_info_port *api = api_info;
	bool stopped = false;
	int ret;

	if ((ret = port_unplug(p->port_id)) < 0)
		return ret;

	if (set_attrs & (BR_PORT_SET_N_RXQS | BR_PORT_SET_N_TXQS | BR_PORT_SET_Q_SIZE)) {
		if (set_attrs & BR_PORT_SET_N_RXQS)
			p->n_rxq = api->n_rxq;
		if (set_attrs & BR_PORT_SET_N_TXQS)
			p->n_txq = api->n_txq;
		if (set_attrs & BR_PORT_SET_Q_SIZE) {
			p->rxq_size = api->rxq_size;
			p->txq_size = api->rxq_size;
		}
		p->configured = false;
	}

	if (!p->configured
	    || (set_attrs & (BR_IFACE_SET_FLAGS | BR_IFACE_SET_MTU | BR_PORT_SET_MAC))) {
		if ((ret = rte_eth_dev_stop(p->port_id)) < 0)
			return errno_log(-ret, "rte_eth_dev_stop");
		stopped = true;
	}
	if (!p->configured && (ret = port_configure(p)) < 0)
		return ret;

	if (set_attrs & BR_IFACE_SET_FLAGS) {
		if (iface->flags & BR_IFACE_F_PROMISC)
			ret = rte_eth_promiscuous_enable(p->port_id);
		else
			ret = rte_eth_promiscuous_disable(p->port_id);
		if (ret < 0) {
			errno_log(-ret, "rte_eth_promiscuous_{en,dis}able");
			if (rte_eth_promiscuous_get(p->port_id) == 1)
				iface->flags |= BR_IFACE_F_PROMISC;
			else
				iface->flags &= ~BR_IFACE_F_PROMISC;
		}

		if (iface->flags & BR_IFACE_F_ALLMULTI)
			ret = rte_eth_allmulticast_enable(p->port_id);
		else
			ret = rte_eth_allmulticast_disable(p->port_id);
		if (ret < 0) {
			errno_log(-ret, "rte_eth_allmulticast_{en,dis}able");
			if (rte_eth_allmulticast_get(p->port_id) == 1)
				iface->flags |= BR_IFACE_F_ALLMULTI;
			else
				iface->flags &= ~BR_IFACE_F_ALLMULTI;
		}

		if (iface->flags & BR_IFACE_F_UP)
			ret = rte_eth_dev_set_link_up(p->port_id);
		else
			ret = rte_eth_dev_set_link_down(p->port_id);
		if (ret < 0)
			errno_log(-ret, "rte_eth_dev_set_link_{up,down}");

		struct rte_eth_link link;
		if (rte_eth_link_get(p->port_id, &link) == 0) {
			if (link.link_status == RTE_ETH_LINK_UP)
				iface->state |= BR_IFACE_S_RUNNING;
			else
				iface->state &= ~BR_IFACE_S_RUNNING;
		}
	}

	if ((set_attrs & BR_IFACE_SET_MTU) && iface->mtu != 0) {
		if ((ret = rte_eth_dev_set_mtu(p->port_id, iface->mtu)) < 0)
			return errno_log(-ret, "rte_eth_dev_set_mtu");
	} else {
		if ((ret = rte_eth_dev_get_mtu(p->port_id, &iface->mtu)) < 0)
			return errno_log(-ret, "rte_eth_dev_get_mtu");
	}

	if ((set_attrs & BR_PORT_SET_MAC) && !br_eth_addr_is_zero(&api->mac)) {
		struct rte_ether_addr mac;
		memcpy(&mac, &api->mac, sizeof(mac));
		if ((ret = rte_eth_dev_default_mac_addr_set(p->port_id, &mac)) < 0)
			return errno_log(-ret, "rte_eth_dev_default_mac_addr_set");
		rte_ether_addr_copy(&mac, &p->mac);
	} else {
		if ((ret = rte_eth_macaddr_get(p->port_id, &p->mac)) < 0)
			return errno_log(-ret, "rte_eth_macaddr_get");
	}

	if (stopped && (ret = rte_eth_dev_start(p->port_id)) < 0)
		return errno_log(-ret, "rte_eth_dev_start");

	return port_plug(p->port_id);
}

static const struct iface *port_ifaces[RTE_MAX_ETHPORTS];

static int iface_port_fini(struct iface *iface) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;
	struct rte_eth_dev_info info;
	struct worker *worker, *tmp;
	size_t n_workers;
	int ret;

	port_unplug(port->port_id);

	port_ifaces[port->port_id] = NULL;

	ret = rte_eth_dev_info_get(port->port_id, &info);
	if (ret == 0)
		ret = rte_eth_dev_stop(port->port_id);
	if (ret == 0)
		ret = rte_eth_dev_close(port->port_id);
	if (ret == 0)
		ret = rte_dev_remove(info.device);
	if (port->pool != NULL) {
		rte_mempool_free(port->pool);
		port->pool = NULL;
	}
	if (ret != 0)
		return errno_log(-ret, "rte_dev_remove");

	LOG(INFO, "port %u destroyed", port->port_id);

	n_workers = worker_count();
	STAILQ_FOREACH_SAFE (worker, &workers, next, tmp) {
		for (int i = 0; i < arrlen(worker->rxqs); i++) {
			if (worker->rxqs[i].port_id == port->port_id) {
				arrdelswap(worker->rxqs, i);
				i--;
			}
		}
		if (arrlen(worker->rxqs) == 0)
			worker_destroy(worker->cpu_id);
	}
	if (worker_count() != n_workers) {
		// update the number of tx queues for all ports
		struct iface *iface = NULL;
		while ((iface = iface_next(BR_IFACE_TYPE_PORT, iface)) != NULL) {
			struct iface_info_port p = {.n_txq = 0};
			if ((ret = iface_port_reconfig(iface, BR_PORT_SET_N_TXQS, &p)) < 0)
				goto out;
		}
	}
out:
	return ret;
}

static int iface_port_init(struct iface *iface, const void *api_info) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;
	const struct br_iface_info_port *api = api_info;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	int ret;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, api->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		return errno_set(EEXIST);
	}

	if ((ret = rte_dev_probe(api->devargs)) < 0)
		return errno_set(-ret);

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, api->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id))
		return errno_set(EIDRM);

	port->port_id = port_id;
	port_ifaces[port_id] = iface;

	if ((ret = iface_port_reconfig(iface, IFACE_SET_ALL, api_info)) < 0) {
		iface_port_fini(iface);
		return ret;
	}

	return 0;
}

const struct iface *port_get_iface(uint16_t port_id) {
	return port_ifaces[port_id];
}

static int iface_port_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	const struct iface_info_port *port = (const struct iface_info_port *)iface->info;
	rte_ether_addr_copy(&port->mac, mac);
	return 0;
}

static void port_to_api(void *info, const struct iface *iface) {
	const struct iface_info_port *port = (const struct iface_info_port *)iface->info;
	struct br_iface_info_port *api = info;

	memccpy(api->devargs, port->devargs, 0, sizeof(api->devargs));
	memcpy(&api->mac, &port->mac, sizeof(api->mac));
	api->n_rxq = port->n_rxq;
	api->n_txq = port->n_txq;
	api->rxq_size = port->rxq_size;
	api->txq_size = port->txq_size;
}

static struct iface_type iface_type_port = {
	.id = BR_IFACE_TYPE_PORT,
	.name = "port",
	.info_size = sizeof(struct iface_info_port),
	.init = iface_port_init,
	.reconfig = iface_port_reconfig,
	.fini = iface_port_fini,
	.get_eth_addr = iface_port_get_eth_addr,
	.to_api = port_to_api,
};

RTE_INIT(port_constructor) {
	iface_type_register(&iface_type_port);
}
