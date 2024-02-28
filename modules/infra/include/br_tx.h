// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_TX
#define _BR_INFRA_TX

#include <rte_build_config.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include <stdint.h>

struct tx_mbuf_priv {
	uint16_t port_id;
};

extern int tx_mbuf_priv_offset;

struct tx_node_queues {
	uint16_t txq_ids[RTE_MAX_ETHPORTS];
};

static inline struct tx_mbuf_priv *tx_mbuf_priv(struct rte_mbuf *m) {
	return RTE_MBUF_DYNFIELD(m, tx_mbuf_priv_offset, struct tx_mbuf_priv *);
}

#endif