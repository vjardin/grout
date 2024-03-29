// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP
#define _BR_IP

#include <br_client.h>
#include <br_ip4_types.h>
#include <br_net_types.h>

#include <stdbool.h>
#include <stddef.h>

int br_ip4_nh_add(const struct br_client *, const struct br_ip4_nh *, bool exist_ok);
int br_ip4_nh_del(const struct br_client *, ip4_addr_t, bool missing_ok);
int br_ip4_nh_list(const struct br_client *, size_t *n_nhs, struct br_ip4_nh **);

int br_ip4_route_add(const struct br_client *, const struct ip4_net *, ip4_addr_t, bool exist_ok);
int br_ip4_route_del(const struct br_client *, const struct ip4_net *, bool missing_ok);
int br_ip4_route_get(const struct br_client *, ip4_addr_t, struct br_ip4_nh *);
int br_ip4_route_list(const struct br_client *, size_t *n_routes, struct br_ip4_route **);

#endif