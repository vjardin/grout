// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin

// Install or withdraw the static mappings of LISP sites through the API.
// Site N has the RLOC RLOC_BASE + N, the nexthop ID NH_ID_BASE + N and the
// EID subnets EID_BASE/EID_PREFIXLEN + N * subnets + i.

// clang-format off
#include <gr_api_client_impl.h>
// clang-format on

#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IP4_BITS (sizeof(ip4_addr_t) * CHAR_BIT)
#define RLOC_BASE RTE_IPV4(198, 18, 0, 0)
#define RLOC_PREFIXLEN 15
#define RLOC_MAX (1 << (IP4_BITS - RLOC_PREFIXLEN))
#define EID_BASE RTE_IPV4(10, 0, 0, 0)
#define EID_PREFIXLEN 24
#define NH_ID_BASE 100000

static ip4_addr_t site_rloc(uint32_t site) {
	return htonl(RLOC_BASE + site);
}

static ip4_addr_t site_subnet(uint32_t site, uint32_t subnets, uint32_t i) {
	return htonl(EID_BASE + ((site * subnets + i) << (IP4_BITS - EID_PREFIXLEN)));
}

static int add_sites(
	struct gr_api_client *c,
	const struct gr_iface *lisp,
	uint32_t first,
	uint32_t count,
	uint32_t subnets
) {
	struct gr_ip4_route_add_req route = {
		.vrf_id = lisp->vrf_id,
		.dest.prefixlen = EID_PREFIXLEN,
		.origin = GR_NH_ORIGIN_STATIC,
		.exist_ok = false,
	};
	struct gr_nexthop_info_lisp *info;
	struct gr_nh_add_req *nh;
	size_t len;

	len = sizeof(*nh) + sizeof(*info);
	if ((nh = calloc(1, len)) == NULL)
		return -1;

	nh->exist_ok = false;
	nh->nh.type = GR_NH_T_LISP;
	nh->nh.origin = GR_NH_ORIGIN_STATIC;
	nh->nh.iface_id = lisp->id;
	nh->nh.stats = true;
	info = (struct gr_nexthop_info_lisp *)nh->nh.info;
	info->rloc.af = GR_AF_IP4;

	for (uint32_t site = first; site < first + count; site++) {
		nh->nh.nh_id = NH_ID_BASE + site;
		info->rloc.ipv4 = site_rloc(site);
		if (gr_api_client_send_recv(c, GR_NH_ADD, len, nh, NULL) < 0) {
			perror("GR_NH_ADD");
			goto err;
		}
		route.nh_id = nh->nh.nh_id;
		for (uint32_t i = 0; i < subnets; i++) {
			route.dest.ip = site_subnet(site, subnets, i);
			if (gr_api_client_send_recv(
				    c, GR_IP4_ROUTE_ADD, sizeof(route), &route, NULL
			    )
			    < 0) {
				perror("GR_IP4_ROUTE_ADD");
				goto err;
			}
		}
	}

	free(nh);
	return 0;
err:
	free(nh);
	return -1;
}

static int del_sites(
	struct gr_api_client *c,
	const struct gr_iface *lisp,
	uint32_t first,
	uint32_t count,
	uint32_t subnets,
	bool nexthops_only
) {
	struct gr_ip4_route_del_req route = {
		.vrf_id = lisp->vrf_id,
		.dest.prefixlen = EID_PREFIXLEN,
		.missing_ok = false,
	};
	// By ID only: a lookup by type would need the RLOC.
	struct gr_nh_del_req nh = {.missing_ok = false};

	for (uint32_t site = first; site < first + count; site++) {
		for (uint32_t i = 0; i < subnets && !nexthops_only; i++) {
			route.dest.ip = site_subnet(site, subnets, i);
			if (gr_api_client_send_recv(
				    c, GR_IP4_ROUTE_DEL, sizeof(route), &route, NULL
			    )
			    < 0) {
				perror("GR_IP4_ROUTE_DEL");
				return -1;
			}
		}
		nh.nh.nh_id = NH_ID_BASE + site;
		if (gr_api_client_send_recv(c, GR_NH_DEL, sizeof(nh), &nh, NULL) < 0) {
			perror("GR_NH_DEL");
			return -1;
		}
	}

	return 0;
}

static void usage(const char *prog) {
	fprintf(stderr,
		"Usage: %s [-d|-D] [-s SOCK] [-f FIRST] [-n SITES] [-m SUBNETS] IFACE\n",
		prog);
	fprintf(stderr, "  -d         Withdraw the sites: their routes, then their nexthop\n");
	fprintf(stderr, "  -D         Withdraw the sites by deleting their nexthop only\n");
	fprintf(stderr, "  -s SOCK    API socket path (default: $GROUT_SOCK_PATH)\n");
	fprintf(stderr, "  -f FIRST   Index of the first site (default: 0)\n");
	fprintf(stderr, "  -n SITES   Number of sites (default: 1000)\n");
	fprintf(stderr, "  -m SUBNETS Number of EID subnets per site (default: 4)\n");
	fprintf(stderr, "  IFACE      Name of the LISP interface\n");
}

int main(int argc, char **argv) {
	struct gr_iface_get_req get = {.iface_id = GR_IFACE_ID_UNDEF};
	bool del = false, nexthops_only = false;
	const struct gr_iface_get_resp *resp;
	uint32_t first = 0, count = 1000;
	const char *sock_path = NULL;
	struct gr_api_client *c;
	void *resp_ptr = NULL;
	uint32_t subnets = 4;
	gr_clock_ns_t time;
	float duration;
	uint32_t ops;
	int ret;
	int o;

	while ((o = getopt(argc, argv, "dDs:f:n:m:h")) != -1) {
		switch (o) {
		case 'D':
			nexthops_only = true;
			// fallthrough
		case 'd':
			del = true;
			break;
		case 's':
			sock_path = optarg;
			break;
		case 'f':
			first = strtoul(optarg, NULL, 10);
			break;
		case 'n':
			count = strtoul(optarg, NULL, 10);
			break;
		case 'm':
			subnets = strtoul(optarg, NULL, 10);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return o == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}
	if (optind != argc - 1 || strlen(argv[optind]) >= sizeof(get.name)) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	if (count == 0 || subnets == 0 || first + count > RLOC_MAX) {
		fprintf(stderr, "error: at most %u sites\n", RLOC_MAX);
		return EXIT_FAILURE;
	}

	c = gr_api_client_connect(sock_path);
	if (c == NULL) {
		perror("gr_api_client_connect");
		return EXIT_FAILURE;
	}

	memccpy(get.name, argv[optind], 0, sizeof(get.name));
	if (gr_api_client_send_recv(c, GR_IFACE_GET, sizeof(get), &get, &resp_ptr) < 0) {
		perror("GR_IFACE_GET");
		return EXIT_FAILURE;
	}
	resp = resp_ptr;
	if (resp->iface.type != GR_IFACE_TYPE_LISP) {
		fprintf(stderr, "error: %s is not a LISP interface\n", argv[optind]);
		return EXIT_FAILURE;
	}

	time = gr_clock_ns();

	if (del)
		ret = del_sites(c, &resp->iface, first, count, subnets, nexthops_only);
	else
		ret = add_sites(c, &resp->iface, first, count, subnets);

	duration = (float)(gr_clock_ns() - time) / (float)GR_NS_PER_S;
	ops = nexthops_only ? count : count * (subnets + 1);

	printf("%s %u sites with %u subnets: %.2fs (%.0f requests/s)\n",
	       del ? "withdrew" : "installed",
	       count,
	       subnets,
	       duration,
	       (float)ops / duration);

	free(resp_ptr);
	gr_api_client_disconnect(c);

	return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
