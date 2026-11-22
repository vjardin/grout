// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin

#include "config.h"
#include "iface.h"
#include "lisp.h"
#include "log.h"
#include "module.h"
#include "nexthop.h"
#include "rcu.h"
#include "vrf.h"

#include <gr_infra.h>
#include <gr_lisp.h>

#include <event2/event.h>
#include <rte_ethdev.h>
#include <rte_hash.h>

#include <string.h>

LOG_TYPE("lisp");

#define LISP_MTU_IPV4 (RTE_ETHER_MTU - sizeof(struct lisp_template_ipv4))
#define LISP_MTU_IPV6 (RTE_ETHER_MTU - sizeof(struct lisp_template_ipv6))

struct lisp_key {
	uint32_t iid;
	// Use uint32_t to avoid padding issues. See ipip_key in ipip/control.c.
	uint32_t vrf_id;
};

struct rloc_key {
	// Use uint32_t to avoid padding issues.
	uint32_t iface_id;
	uint32_t af;
	struct rte_ipv6_addr addr;
};

static struct rte_hash *lisp_hash;
static struct rte_hash *rloc_hash;

struct iface *lisp_get_iface(uint32_t iid, uint16_t encap_vrf_id) {
	const struct lisp_key key = {iid, encap_vrf_id};
	struct iface *iface;

	if (rte_hash_lookup_data(lisp_hash, &key, (void **)&iface) < 0)
		return NULL;

	return iface;
}

static void rloc_key_init(struct rloc_key *key, uint16_t iface_id, const struct l3_addr *rloc) {
	memset(key, 0, sizeof(*key));
	key->iface_id = iface_id;
	key->af = rloc->af;
	if (rloc->af == GR_AF_IP4)
		memcpy(&key->addr, &rloc->ipv4, sizeof(rloc->ipv4));
	else
		key->addr = rloc->ipv6;
}

struct nexthop *lisp_rloc_lookup(uint16_t iface_id, const struct l3_addr *rloc) {
	struct rte_hash *hash = rloc_hash;
	struct rloc_key key;
	struct nexthop *nh;

	if (hash == NULL)
		return NULL;

	rloc_key_init(&key, iface_id, rloc);
	if (rte_hash_lookup_data(hash, &key, (void **)&nh) < 0)
		return NULL;

	return nh;
}

static struct rte_hash *lisp_hash_create(const char *name, uint32_t entries, uint32_t key_len) {
	struct rte_hash_parameters params = {
		.name = name,
		.entries = entries,
		.key_len = key_len,
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	struct rte_hash_rcu_config rcu_config = {
		.v = gr_datapath_rcu(), .mode = RTE_HASH_QSBR_MODE_SYNC
	};
	struct rte_hash *hash;

	hash = rte_hash_create(&params);
	if (hash == NULL)
		return errno_log_null(rte_errno, "rte_hash_create");

	if (rte_hash_rcu_qsbr_add(hash, &rcu_config) < 0) {
		rte_hash_free(hash);
		return errno_log_null(rte_errno, "rte_hash_rcu_qsbr_add");
	}

	return hash;
}

static int lisp_check_local(addr_family_t af, uint16_t vrf_id, const void *addr) {
	const struct nexthop_info_l3 *l3;
	const struct nexthop *nh;

	nh = nexthop_lookup_l3(af, vrf_id, GR_IFACE_ID_UNDEF, addr);
	if (nh == NULL)
		return errno_set(EADDRNOTAVAIL);

	l3 = nexthop_info_l3(nh);
	if ((l3->flags & NH_LOCAL_ADDR_FLAGS) != NH_LOCAL_ADDR_FLAGS)
		return errno_set(EADDRNOTAVAIL);

	return 0;
}

// The MTU that leaves room for the headers of the largest encapsulation in use.
static uint16_t lisp_default_mtu(const struct gr_iface_info_lisp *conf) {
	return rte_ipv6_addr_is_unspec(&conf->local6) ? LISP_MTU_IPV4 : LISP_MTU_IPV6;
}

static int iface_lisp_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
) {
	struct iface_info_lisp *cur = iface_info_lisp(iface);
	const struct gr_iface_info_lisp *next = api_info;
	struct gr_iface_info_lisp conf = cur->base;
	struct lisp_key cur_key, next_key;
	bool registered, rewrite;
	uint16_t default_mtu;
	int ret;

	if (set_attrs & GR_LISP_SET_IID)
		conf.iid = next->iid;
	if (set_attrs & GR_LISP_SET_ENCAP_VRF)
		conf.encap_vrf_id = next->encap_vrf_id;
	if (set_attrs & GR_LISP_SET_LOCAL)
		conf.local = next->local;
	if (set_attrs & GR_LISP_SET_LOCAL6)
		conf.local6 = next->local6;
	if (set_attrs & GR_LISP_SET_RLOC_FILTER)
		conf.rloc_filter = next->rloc_filter;
	if (set_attrs & GR_LISP_SET_EID_FILTER)
		conf.eid_filter = next->eid_filter;

	if (conf.iid > GR_LISP_IID_MAX)
		return errno_set(ERANGE);

	if (conf.encap_vrf_id == GR_VRF_ID_UNDEF) {
		conf.encap_vrf_id = vrf_default_get_or_create();
		if (conf.encap_vrf_id == GR_VRF_ID_UNDEF)
			return -errno;
	}

	if (conf.local == 0 && rte_ipv6_addr_is_unspec(&conf.local6))
		return errno_set(EDESTADDRREQ);
	// The local RLOCs are only checked when they are configured.
	if ((set_attrs & (GR_LISP_SET_LOCAL | GR_LISP_SET_ENCAP_VRF)) && conf.local != 0
	    && lisp_check_local(GR_AF_IP4, conf.encap_vrf_id, &conf.local) < 0)
		return -errno;
	if ((set_attrs & (GR_LISP_SET_LOCAL6 | GR_LISP_SET_ENCAP_VRF))
	    && !rte_ipv6_addr_is_unspec(&conf.local6)
	    && lisp_check_local(GR_AF_IP6, conf.encap_vrf_id, &conf.local6) < 0)
		return -errno;

	registered = cur->encap_vrf_id != GR_VRF_ID_UNDEF;
	cur_key = (struct lisp_key) {cur->iid, cur->encap_vrf_id};
	next_key = (struct lisp_key) {conf.iid, conf.encap_vrf_id};

	if (!registered || memcmp(&cur_key, &next_key, sizeof(cur_key)) != 0) {
		if (rte_hash_lookup(lisp_hash, &next_key) >= 0)
			return errno_set(EADDRINUSE);

		if (conf.encap_vrf_id != cur->encap_vrf_id && vrf_incref(conf.encap_vrf_id) < 0)
			return -errno;

		ret = rte_hash_add_key_data(lisp_hash, &next_key, iface);
		if (ret < 0) {
			if (conf.encap_vrf_id != cur->encap_vrf_id)
				vrf_decref(conf.encap_vrf_id);
			return errno_log(-ret, "rte_hash_add_key_data");
		}

		if (registered) {
			rte_hash_del_key(lisp_hash, &cur_key);
			if (conf.encap_vrf_id != cur->encap_vrf_id)
				vrf_decref(cur->encap_vrf_id);
		}
	}

	// The workers copy the templates: do not rewrite them for nothing.
	rewrite = !registered || conf.iid != cur->iid || conf.local != cur->local
		|| !rte_ipv6_addr_eq(&conf.local6, &cur->local6);
	default_mtu = lisp_default_mtu(&cur->base);

	cur->base = conf;
	if (rewrite)
		lisp_templates_init(cur);

	// An MTU that was not chosen follows the local RLOCs.
	if (registered && !(set_attrs & GR_IFACE_SET_MTU) && iface->mtu == default_mtu)
		iface->mtu = lisp_default_mtu(&cur->base);

	return 0;
}

static int iface_lisp_fini(struct iface *iface) {
	struct iface_info_lisp *lisp = iface_info_lisp(iface);
	const struct lisp_key key = {lisp->iid, lisp->encap_vrf_id};

	if (lisp->encap_vrf_id != GR_VRF_ID_UNDEF) {
		rte_hash_del_key(lisp_hash, &key);
		vrf_decref(lisp->encap_vrf_id);
	}

	return 0;
}

static int iface_lisp_init(struct iface *iface, const void *api_info) {
	const struct iface_info_lisp *lisp = iface_info_lisp(iface);
	struct gr_iface conf;
	int ret;

	iface->speed = RTE_ETH_SPEED_NUM_10G;

	conf.base = iface->base;

	ret = iface_lisp_reconfig(iface, IFACE_SET_ALL, &conf, api_info);
	if (ret < 0) {
		iface_lisp_fini(iface);
		errno = -ret;
		return ret;
	}

	if (iface->mtu == 0)
		iface->mtu = lisp_default_mtu(&lisp->base);

	return 0;
}

static void lisp_to_api(void *info, const struct iface *iface) {
	const struct iface_info_lisp *lisp = iface_info_lisp(iface);
	struct gr_iface_info_lisp *api = info;

	*api = lisp->base;
}

static const struct iface_type iface_type_lisp = {
	.id = GR_IFACE_TYPE_LISP,
	.pub_size = sizeof(struct gr_iface_info_lisp),
	.priv_size = sizeof(struct iface_info_lisp),
	.init = iface_lisp_init,
	.reconfig = iface_lisp_reconfig,
	.fini = iface_lisp_fini,
	.to_api = lisp_to_api,
};

static bool lisp_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	return l3_addr_eq(&nexthop_info_lisp(a)->rloc, &nexthop_info_lisp(b)->rloc);
}

static struct nexthop *lisp_nh_lookup(const struct gr_nexthop_base *base, const void *info) {
	const struct gr_nexthop_info_lisp *pub = info;

	return lisp_rloc_lookup(base->iface_id, &pub->rloc);
}

static int lisp_nh_reconfig(const struct gr_nexthop_config *) {
	struct rte_hash *hash = rloc_hash;

	if (hash == NULL)
		return 0;

	// No nexthop is in use: the index is created again for the next one.
	rloc_hash = NULL;
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	rte_hash_free(hash);

	return 0;
}

// Account a nexthop that has stats in its interface.
static void lisp_nh_count(uint16_t iface_id, int count) {
	struct iface *iface = iface_from_id(iface_id);

	if (iface != NULL)
		iface_info_lisp(iface)->n_stats += count;
}

static void lisp_nh_remove_references(struct nexthop *nh) {
	struct nexthop_info_lisp *priv;
	struct rloc_key key;

	if (nh->type != GR_NH_T_LISP)
		return;

	priv = nexthop_info_lisp(nh);
	if (priv->iface_id == GR_IFACE_ID_UNDEF)
		return;

	rloc_key_init(&key, priv->iface_id, &priv->rloc);
	rte_hash_del_key(rloc_hash, &key);
	if (priv->stats)
		lisp_nh_count(priv->iface_id, -1);
	priv->iface_id = GR_IFACE_ID_UNDEF;
	priv->stats = false;
}

static int lisp_nh_import_info(struct nexthop *nh, const void *info) {
	const struct iface *iface = iface_from_id(nh->iface_id);
	struct nexthop_info_lisp *priv = nexthop_info_lisp(nh);
	const struct gr_nexthop_info_lisp *pub = info;
	struct rloc_key key;
	void *existing;
	char name[64];
	int ret;

	if (iface == NULL || iface->type != GR_IFACE_TYPE_LISP)
		return errno_set(EMEDIUMTYPE);

	switch (pub->rloc.af) {
	case GR_AF_IP4:
		if (pub->rloc.ipv4 == 0)
			return errno_set(EDESTADDRREQ);
		break;
	case GR_AF_IP6:
		if (rte_ipv6_addr_is_unspec(&pub->rloc.ipv6))
			return errno_set(EDESTADDRREQ);
		break;
	default:
		return errno_set(EAFNOSUPPORT);
	}

	if (rloc_hash == NULL) {
		snprintf(name, sizeof(name), "lisp-rloc-%u", nh_conf.max_count);
		rloc_hash = lisp_hash_create(name, nh_conf.max_count, sizeof(key));
		if (rloc_hash == NULL)
			return -errno;
	}

	// An interface has one nexthop per remote RLOC.
	rloc_key_init(&key, nh->iface_id, &pub->rloc);
	if (rte_hash_lookup_data(rloc_hash, &key, &existing) < 0) {
		if ((ret = rte_hash_add_key_data(rloc_hash, &key, nh)) < 0)
			return errno_set(-ret);
		if (priv->iface_id != GR_IFACE_ID_UNDEF) {
			rloc_key_init(&key, priv->iface_id, &priv->rloc);
			rte_hash_del_key(rloc_hash, &key);
		}
	} else if (existing != nh) {
		return errno_set(EADDRINUSE);
	}

	if (priv->stats)
		lisp_nh_count(priv->iface_id, -1);
	if (nh->stats)
		lisp_nh_count(nh->iface_id, 1);

	priv->rloc = pub->rloc;
	priv->iface_id = nh->iface_id;
	priv->stats = nh->stats;

	return 0;
}

static struct gr_nexthop *lisp_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_lisp *priv = nexthop_info_lisp(nh);
	struct gr_nexthop_info_lisp *lisp;
	struct gr_nexthop *pub;

	pub = malloc(sizeof(*pub) + sizeof(*lisp));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	lisp = (struct gr_nexthop_info_lisp *)pub->info;
	*lisp = priv->base;

	*len = sizeof(*pub) + sizeof(*lisp);

	return pub;
}

static struct nexthop_type_ops nh_ops = {
	.stats = true,
	.reconfig = lisp_nh_reconfig,
	.lookup = lisp_nh_lookup,
	.remove_references = lisp_nh_remove_references,
	.equal = lisp_nh_equal,
	.import_info = lisp_nh_import_info,
	.to_api = lisp_nh_to_api,
};

static void lisp_init(struct event_base *) {
	lisp_hash = lisp_hash_create("lisp", gr_config.max_ifaces, sizeof(struct lisp_key));
	if (lisp_hash == NULL)
		ABORT("rte_hash_create(lisp)");
}

static void lisp_fini(struct event_base *) {
	rte_hash_free(lisp_hash);
	lisp_hash = NULL;
	rte_hash_free(rloc_hash);
	rloc_hash = NULL;
}

static struct module lisp_module = {
	.name = "lisp",
	.depends_on = "rcu",
	.init = lisp_init,
	.fini = lisp_fini,
};

RTE_INIT(lisp_constructor) {
	module_register(&lisp_module);
	iface_type_register(&iface_type_lisp);
	nexthop_type_ops_register(GR_NH_T_LISP, &nh_ops);
}
