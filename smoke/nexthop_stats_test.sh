#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

. $(dirname $0)/_init.sh

count=5
payload=100
ip4_len=$((20 + 8 + payload))
ip6_len=$((40 + 8 + payload))

# One worker for p0, another one for p2.
grcli affinity cpus set control 0 datapath 1,2

port_add p0
port_add p1
port_add p2
grcli affinity qmap set p0 rxq 0 cpu 1
grcli affinity qmap set p2 rxq 0 cpu 2
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1
grcli address add 172.16.2.1/24 iface p2
grcli address add fd00:0::1/64 iface p0
grcli address add fd00:1::1/64 iface p1
grcli interface add ipip tun1 local 172.16.1.1 remote 172.16.1.4
grcli address add 10.98.0.1/24 iface tun1

for n in 0 2; do
	netns_add n$n
	move_to_netns x-p$n n$n
	ip -n n$n addr add 172.16.$n.2/24 dev x-p$n
	ip -n n$n route add default via 172.16.$n.1
done
ip -n n0 addr add fd00:0::2/64 dev x-p0
ip -n n0 route add default via fd00:0::1

# n1 is the gateway of 16.1.0.0/16 and fd00:f1::/64, and of 16.2.0.0/16
# through the tunnel.
netns_add n1
move_to_netns x-p1 n1
ip -n n1 addr add 172.16.1.2/24 dev x-p1
ip -n n1 addr add 172.16.1.4/24 dev x-p1
ip -n n1 addr add fd00:1::2/64 dev x-p1
ip -n n1 addr add 16.1.0.1/16 dev lo
ip -n n1 addr add 16.2.0.1/16 dev lo
ip -n n1 addr add fd00:f1::1/64 dev lo
ip -n n1 route add default via 172.16.1.1
ip -n n1 route add default via fd00:1::1
ip -n n1 tunnel add tun1 mode ipip local 172.16.1.4 remote 172.16.1.1
ip -n n1 link set tun1 up
ip -n n1 addr add 10.98.0.2/24 dev tun1
ip netns exec n1 sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec n1 sysctl -qw net.ipv4.conf.tun1.rp_filter=0

# 100 is resolved with ARP. 101 is an address that n1 does not own, so that
# no neighbor discovery packet is ever sent to it. 103 is not counted.
grcli nexthop add l3 iface p1 address 172.16.1.2 id 100 stats
grcli nexthop add l3 iface p1 address fd00:1::99 mac $(stable_mac p1) id 101 stats
grcli nexthop add l3 iface tun1 address 10.98.0.2 id 102 stats
grcli nexthop add l3 iface p1 address 172.16.1.3 id 103
grcli route add 16.1.0.0/16 via id 100
grcli route add fd00:f1::/64 via id 101
grcli route add 16.2.0.0/16 via id 102

check_stats() {
	local id=$1 packets=$2 bytes=$3

	grcli nexthop stats
	grcli -j nexthop stats | jq -e --argjson id $id --argjson packets $packets \
		--argjson bytes $bytes \
		'any(.[]; .id == $id and .tx_packets == $packets and .tx_bytes == $bytes)' \
		|| fail "nexthop $id: expected $packets packets and $bytes bytes"
}

counted_ids() {
	grcli -j nexthop stats | jq -c '[.[].id] | sort'
}

[ "$(counted_ids)" = "[100,101,102]" ] || fail "unexpected counted nexthops"
check_stats 100 0 0

# The first packet waits for the ARP resolution. It must be counted once.
ip netns exec n0 ping -i0.01 -c$count -s$payload -n 16.1.0.1
check_stats 100 $count $((count * ip4_len))
ip netns exec n0 ping -i0.01 -c$count -s$payload -n fd00:f1::1
check_stats 101 $count $((count * ip6_len))
ip netns exec n0 ping -i0.01 -c$count -s$payload -n 16.2.0.1
check_stats 102 $count $((count * ip4_len))
check_stats 100 $count $((count * ip4_len))

# Packets of another worker add up.
ip netns exec n2 ping -i0.01 -c$count -s$payload -n 16.1.0.1
check_stats 100 $((2 * count)) $((2 * count * ip4_len))

grcli stats reset
check_stats 100 0 0
check_stats 101 0 0
check_stats 102 0 0
# They count again from there.
ip netns exec n0 ping -i0.01 -c$count -s$payload -n 16.1.0.1
check_stats 100 $count $((count * ip4_len))
grcli stats reset
check_stats 100 0 0

# Disabled then enabled again: the nexthop keeps forwarding and restarts
# from zero.
ip netns exec n0 ping -i0.01 -c$count -s$payload -n 16.1.0.1
grcli nexthop add l3 iface p1 address 172.16.1.2 id 100
[ "$(counted_ids)" = "[101,102]" ] || fail "nexthop 100 is still counted"
ip netns exec n0 ping -i0.01 -c$count -s$payload -n 16.1.0.1
grcli nexthop add l3 iface p1 address 172.16.1.2 id 100 stats
check_stats 100 0 0
ip netns exec n0 ping -i0.01 -c$count -s$payload -n 16.1.0.1
check_stats 100 $count $((count * ip4_len))

# The counters of a deleted nexthop are not inherited by the next one.
grcli nexthop del 100
[ "$(counted_ids)" = "[101,102]" ] || fail "deleted nexthop is still counted"
grcli nexthop add l3 iface p1 address 172.16.1.3 id 103 stats
check_stats 103 0 0

# The counters survive the removal of the worker that updated them.
ip netns exec n2 ping -i0.01 -c$count -s$payload -n 16.2.0.1
check_stats 102 $count $((count * ip4_len))
grcli affinity cpus set datapath 1
check_stats 102 $count $((count * ip4_len))
