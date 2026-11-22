#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin

# Two tenants with the same EID prefixes share the RLOCs of two sites.
#
#  blue-a 10.1.0.2 -- p0  VRF blue-a  lisp-blue-a (iid 101) \
#                                                            VRF wan-a  p2 192.0.2.1 -- core
#  red-a  10.1.0.2 -- p1  VRF red-a   lisp-red-a  (iid 202) /                            |
#                                                                                        |
#  blue-b 10.2.0.2 -- p4  VRF blue-b  lisp-blue-b (iid 101) \                            |
#                                                            VRF wan-b  p3 192.0.2.5 -- core
#  red-b  10.2.0.2 -- p5  VRF red-b   lisp-red-b  (iid 202) /

. $(dirname $0)/_init.sh

for vrf in wan-a wan-b blue-a red-a blue-b red-b; do
	grcli interface add vrf $vrf
done
port_add p0 vrf blue-a
port_add p1 vrf red-a
port_add p2 vrf wan-a
port_add p3 vrf wan-b
port_add p4 vrf blue-b
port_add p5 vrf red-b

grcli address add 192.0.2.1/30 iface p2
grcli address add 192.0.2.5/30 iface p3

netns_add core
move_to_netns x-p2 core
move_to_netns x-p3 core
ip -n core addr add 192.0.2.2/30 dev x-p2
ip -n core addr add 192.0.2.6/30 dev x-p3
ip netns exec core sysctl -wq net.ipv4.ip_forward=1
grcli route add 192.0.2.4/30 via 192.0.2.2 vrf wan-a
grcli route add 192.0.2.0/30 via 192.0.2.6 vrf wan-b

# site_tenant PORT TENANT SITE IID LOCAL_RLOC REMOTE_RLOC REMOTE_SITE NHID
site_tenant() {
	local port="$1" tenant="$2" site="$3" iid="$4" local="$5" remote="$6" rsite="$7" nh="$8"
	local n=$((site == 1 ? 1 : 2)) r=$((rsite == 1 ? 1 : 2)) s
	[ "$site" = 1 ] && s=a || s=b

	grcli address add 10.$n.0.1/24 iface $port
	grcli address add fd00:$n::1/64 iface $port
	netns_add $tenant-$s
	move_to_netns x-$port $tenant-$s
	ip -n $tenant-$s addr add 10.$n.0.2/24 dev x-$port
	ip -n $tenant-$s addr add fd00:$n::2/64 dev x-$port
	ip -n $tenant-$s route add default via 10.$n.0.1
	ip -n $tenant-$s route add default via fd00:$n::1

	grcli interface add lisp lisp-$tenant-$s iid $iid local $local \
		encap_vrf wan-$s vrf $tenant-$s
	grcli nexthop add lisp iface lisp-$tenant-$s rloc $remote id $nh stats
	grcli route add 10.$r.0.0/24 via id $nh vrf $tenant-$s
	grcli route add fd00:$r::/64 via id $nh vrf $tenant-$s

	ip netns exec $tenant-$s socat TCP6-LISTEN:7777,fork,reuseaddr,ipv6only=0 \
		SYSTEM:"echo $tenant-$s" &
}

site_tenant p0 blue 1 101 192.0.2.1 192.0.2.5 2 11
site_tenant p1 red 1 202 192.0.2.1 192.0.2.5 2 12
site_tenant p4 blue 2 101 192.0.2.5 192.0.2.1 1 21
site_tenant p5 red 2 202 192.0.2.5 192.0.2.1 1 22

grcli interface show type lisp
grcli nexthop show type lisp

ask() {
	local ns="$1" dst="$2"
	ip netns exec $ns socat -T2 - "TCP:$dst:7777,connect-timeout=2" < /dev/null
}

wait_ready() {
	local i
	for i in $(seq 50); do
		[ -e $tmp/ready ] && return
		sleep 0.1
	done
	fail "helper not ready"
}

# check_tenant TENANT IID
check_tenant() {
	local tenant="$1" iid="$2" pid answer
	rm -f $tmp/ready
	ip netns exec core lisp_xtr capture x-p2 --count 6 --ready $tmp/ready > $tmp/capture &
	pid=$!
	wait_ready
	ip netns exec $tenant-a ping -i0.01 -c3 -n 10.2.0.2
	ip netns exec $tenant-a ping -i0.01 -c3 -n fd00:2::2
	wait $pid || fail "LISP packets not seen in the core"
	cat $tmp/capture
	[ "$(grep -cw -e "iid=$iid" $tmp/capture)" -eq 6 ] || fail "$tenant: instance ID $iid expected"

	answer=$(ask $tenant-a 10.2.0.2)
	[ "$answer" = "$tenant-b" ] || fail "$tenant-a reached '$answer' with IPv4"
	answer=$(ask $tenant-a "[fd00:2::2]")
	[ "$answer" = "$tenant-b" ] || fail "$tenant-a reached '$answer' with IPv6"
	answer=$(ask $tenant-b 10.1.0.2)
	[ "$answer" = "$tenant-a" ] || fail "$tenant-b reached '$answer' with IPv4"
}

for tenant in blue red; do
	ip netns exec $tenant-a ping -i0.01 -c3 -n 10.2.0.2
	ip netns exec $tenant-a ping -i0.01 -c3 -n fd00:2::2
done
check_tenant blue 101
check_tenant red 202

# The tenants count separately what they send to the same RLOC and what
# they receive from it.
nh_stat() {
	grcli -j nexthop stats | jq --argjson id $1 ".[] | select(.id == \$id) | .$2"
}
grcli nexthop stats
blue=$(nh_stat 11 tx_packets)
red=$(nh_stat 12 tx_packets)
pings=3
ip netns exec blue-a ping -i0.01 -c$pings -n 10.2.0.2
[ "$(nh_stat 11 tx_packets)" -eq $((blue + pings)) ] || fail "blue: unexpected packets sent"
[ "$(nh_stat 12 tx_packets)" -eq "$red" ] || fail "red: unexpected packets sent"
for pair in "11 21" "21 11" "12 22" "22 12"; do
	read -r tx rx <<< "$pair"
	[ "$(nh_stat $tx tx_packets)" -eq "$(nh_stat $rx rx_packets)" ] \
		|| fail "packets sent to nexthop $tx and received from nexthop $rx differ"
done

# A tenant which is removed from a site does not leak to the other one.
grcli interface del lisp-red-b
ip netns exec red-a ping -i0.01 -c3 -W1 -n 10.2.0.2 && fail "red-a reached a host of site b"
check_tenant blue 101

grcli interface stats
