#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

# Two LISP sites in the same grout, connected through a Linux router.
#
#  host-a       EID VRF site-a      locator VRF wan-a      core
# 10.1.0.2 --- p0 10.1.0.1  lisp-a  192.0.2.1 p1 --------- 192.0.2.2
# fd00:1::2       fd00:1::1         2001:db8:a::1          2001:db8:a::2
#                                                             |
# 10.2.0.2 --- p3 10.2.0.1  lisp-b  192.0.2.5 p2 --------- 192.0.2.6
# fd00:2::2       fd00:2::1         2001:db8:b::1          2001:db8:b::2
#  host-b       EID VRF site-b      locator VRF wan-b

. $(dirname $0)/_init.sh

grcli interface add vrf site-a
grcli interface add vrf site-b
grcli interface add vrf wan-a
grcli interface add vrf wan-b
port_add p0 vrf site-a
port_add p1 vrf wan-a
port_add p2 vrf wan-b
port_add p3 vrf site-b

grcli address add 10.1.0.1/24 iface p0
grcli address add fd00:1::1/64 iface p0
grcli address add 192.0.2.1/30 iface p1
grcli address add 2001:db8:a::1/64 iface p1
grcli address add 192.0.2.5/30 iface p2
grcli address add 2001:db8:b::1/64 iface p2
grcli address add 10.2.0.1/24 iface p3
grcli address add fd00:2::1/64 iface p3

netns_add host-a
move_to_netns x-p0 host-a
ip -n host-a addr add 10.1.0.2/24 dev x-p0
ip -n host-a addr add fd00:1::2/64 dev x-p0
ip -n host-a route add default via 10.1.0.1
ip -n host-a route add default via fd00:1::1

netns_add host-b
move_to_netns x-p3 host-b
ip -n host-b addr add 10.2.0.2/24 dev x-p3
ip -n host-b addr add fd00:2::2/64 dev x-p3
ip -n host-b route add default via 10.2.0.1
ip -n host-b route add default via fd00:2::1

netns_add core
move_to_netns x-p1 core
move_to_netns x-p2 core
ip -n core addr add 192.0.2.2/30 dev x-p1
ip -n core addr add 2001:db8:a::2/64 dev x-p1
ip -n core addr add 192.0.2.6/30 dev x-p2
ip -n core addr add 2001:db8:b::2/64 dev x-p2
ip netns exec core sysctl -wq net.ipv4.ip_forward=1
ip netns exec core sysctl -wq net.ipv6.conf.all.forwarding=1

grcli route add 192.0.2.4/30 via 192.0.2.2 vrf wan-a
grcli route add 2001:db8:b::/64 via 2001:db8:a::2 vrf wan-a
grcli route add 192.0.2.0/30 via 192.0.2.6 vrf wan-b
grcli route add 2001:db8:a::/64 via 2001:db8:b::2 vrf wan-b

# The same instance ID on both sides: it is scoped by the locator VRF.
grcli interface add lisp lisp-a iid 101 local 192.0.2.1 local6 2001:db8:a::1 \
	encap_vrf wan-a vrf site-a pkt_too_big on
grcli interface add lisp lisp-b iid 101 local 192.0.2.5 local6 2001:db8:b::1 \
	encap_vrf wan-b vrf site-b pkt_too_big on
grcli interface show
grcli -j interface show name lisp-a | jq -e \
	'.iid == 101 and .local == "192.0.2.1" and .local6 == "2001:db8:a::1"
	and .encap_vrf == "wan-a" and .vrf == "site-a"' || fail "unexpected lisp-a attributes"

# An instance ID cannot be bound twice in the same locator VRF.
grcli interface add lisp lisp-dup iid 101 local 192.0.2.1 encap_vrf wan-a vrf site-b \
	&& fail "duplicate instance ID accepted"
# A local RLOC must be an address of the locator VRF.
grcli interface add lisp lisp-bad iid 102 local 192.0.2.5 encap_vrf wan-a vrf site-a \
	&& fail "foreign local RLOC accepted"
grcli interface add lisp lisp-bad iid 102 local6 2001:db8:b::1 encap_vrf wan-a vrf site-a \
	&& fail "foreign local IPv6 RLOC accepted"
# At least one local RLOC is required.
grcli interface add lisp lisp-bad iid 102 encap_vrf wan-a vrf site-a \
	&& fail "interface without local RLOC accepted"
# The instance ID is 24 bits wide.
grcli interface add lisp lisp-bad iid 16777216 local 192.0.2.1 encap_vrf wan-a vrf site-a \
	&& fail "out of range instance ID accepted"
grcli interface show name lisp-dup && fail "lisp-dup was created"
grcli interface show name lisp-bad && fail "lisp-bad was created"

# Remote RLOCs.
grcli nexthop add lisp iface lisp-a rloc 192.0.2.5 id 14 stats
grcli nexthop add lisp iface lisp-a rloc 2001:db8:b::1 id 16 stats
grcli nexthop add lisp iface lisp-b rloc 192.0.2.1 id 24 stats
grcli nexthop add lisp iface lisp-b rloc 2001:db8:a::1 id 26 stats
grcli nexthop show
grcli -j nexthop show type lisp | jq -e \
	'.[] | select(.id == 16 and .rloc == "2001:db8:b::1" and .iface == "lisp-a")' \
	|| fail "unexpected nexthop 16"
# A LISP nexthop needs a LISP interface and a remote RLOC.
grcli nexthop add lisp iface p0 rloc 192.0.2.5 id 99 && fail "nexthop on a port accepted"
grcli nexthop add lisp iface lisp-a rloc 0.0.0.0 id 99 && fail "nexthop without RLOC accepted"
grcli nexthop add lisp iface lisp-a rloc :: id 99 && fail "nexthop without RLOC accepted"
# An interface has one nexthop per remote RLOC.
grcli nexthop add lisp iface lisp-a rloc 2001:db8:b::1 id 14 \
	&& fail "second nexthop accepted for an RLOC"
grcli -j nexthop show type lisp | jq -e 'length == 4' || fail "unexpected nexthops"

wait_ready() {
	local i
	for i in $(seq 50); do
		[ -e $tmp/ready ] && return
		sleep 0.1
	done
	fail "helper not ready"
}

counter() {
	grcli -j stats show software | jq -r --arg n "$1" \
		'[.[] | select(.node == $n) | .packets] | add // 0'
}

# check_lisp RLOC_AF IID
check_lisp() {
	local af="$1" iid="$2" pid
	rm -f $tmp/ready
	ip netns exec core lisp_xtr capture x-p1 --count 6 --ready $tmp/ready > $tmp/capture &
	pid=$!
	wait_ready
	ip netns exec host-a ping -i0.01 -c3 -n 10.2.0.2
	ip netns exec host-a ping -i0.01 -c3 -n fd00:2::2
	wait $pid || fail "LISP packets not seen in the core"
	cat $tmp/capture
	[ "$(grep -cw -e "af=$af" $tmp/capture)" -eq 6 ] || fail "IPv$af RLOCs expected"
	[ "$(grep -cw -e "iid=$iid" $tmp/capture)" -eq 6 ] || fail "instance ID $iid expected"
	[ "$(grep -cw -e "idst=10.2.0.2" $tmp/capture)" -eq 3 ] || fail "IPv4 EIDs expected"
	[ "$(grep -cw -e "idst=fd00:2::2" $tmp/capture)" -eq 3 ] || fail "IPv6 EIDs expected"
}

set_mappings() {
	local a="$1" b="$2"
	grcli route add 10.2.0.0/24 via id "$a" vrf site-a
	grcli route add fd00:2::/64 via id "$a" vrf site-a
	grcli route add 10.1.0.0/24 via id "$b" vrf site-b
	grcli route add fd00:1::/64 via id "$b" vrf site-b
}

del_mappings() {
	grcli route del 10.2.0.0/24 vrf site-a
	grcli route del fd00:2::/64 vrf site-a
	grcli route del 10.1.0.0/24 vrf site-b
	grcli route del fd00:1::/64 vrf site-b
}

# Resolve the neighbors of the underlay.
ip netns exec core ping -i0.01 -c3 -n 192.0.2.1
ip netns exec core ping -i0.01 -c3 -n 192.0.2.5
ip netns exec core ping -i0.01 -c3 -n 2001:db8:a::1
ip netns exec core ping -i0.01 -c3 -n 2001:db8:b::1

# IPv4 and IPv6 EIDs over IPv4 RLOCs.
set_mappings 14 24
grcli route show vrf site-a
ip netns exec host-a ping -i0.01 -c3 -n 10.2.0.2
ip netns exec host-a ping -i0.01 -c3 -n fd00:2::2
check_lisp 4 101

# The addresses of the remote xTR in its EID VRF are reachable.
ip netns exec host-a ping -i0.01 -c3 -n 10.2.0.1
ip netns exec host-a ping -i0.01 -c3 -n fd00:2::1
# With an address, the xTR can send ICMP errors to the remote hosts.
grcli address add 10.2.0.254/32 iface lisp-b
grcli address add fd00:2::fe/128 iface lisp-b
ip netns exec host-a ping -i0.01 -c3 -n 10.2.0.254
ip netns exec host-a ping -i0.01 -c3 -n fd00:2::fe
ip netns exec host-a traceroute -N1 -q1 -w1 -n 10.2.0.2 | tee $tmp/traceroute
grep -qw -e 10.2.0.254 $tmp/traceroute || fail "no ICMP error from the remote xTR"
ip netns exec host-a traceroute -N1 -q1 -w1 -n fd00:2::2 | tee $tmp/traceroute
grep -qw -e fd00:2::fe $tmp/traceroute || fail "no ICMPv6 error from the remote xTR"

# IPv4 and IPv6 EIDs over IPv6 RLOCs.
del_mappings
ip netns exec host-a ping -i0.01 -c3 -W1 -n 10.2.0.2 && fail "reachable without mapping"
set_mappings 16 26
check_lisp 6 101

# What is left of 1500 bytes after the largest outer headers, and an ICMP
# payload which fits in the MTU of the ports but not in the one of the tunnel.
mtu=$((1500 - 40 - 8 - 8))
size=1450

# IPv4 packets larger than the MTU are fragmented before encapsulation.
ip netns exec host-a ping -i0.01 -c3 -s $size -M dont -n 10.2.0.2
[ "$(counter ip_fragment)" -ge 6 ] || fail "packets were not fragmented"
# Path MTU discovery.
out=$(ip netns exec host-a ping -c1 -W1 -s $size -M do -n 10.2.0.2 2>&1 || true)
echo "$out"
echo "$out" | grep -qF "mtu = $mtu" || fail "IPv4 path MTU not reported"
out=$(ip netns exec host-a ping -c1 -W1 -s $size -n fd00:2::2 2>&1 || true)
echo "$out"
echo "$out" | grep -qF "mtu=$mtu" || fail "IPv6 path MTU not reported"
out=$(ip netns exec host-b ping -c1 -W1 -s $size -n fd00:1::2 2>&1 || true)
echo "$out"
echo "$out" | grep -qF "mtu=$mtu" || fail "IPv6 path MTU not reported"
# The hosts now send packets that fit.
ip netns exec host-a ping -i0.01 -c3 -s $size -n 10.2.0.2
ip netns exec host-a ping -i0.01 -c3 -s $size -n fd00:2::2

# What a site has sent to an RLOC, the other site has received it from the
# RLOC of the same address family. The only packets lost in between are the
# two traceroute probes whose TTL expired in the core.
expired=2
nh_stat() {
	grcli -j nexthop stats | jq --argjson id $1 ".[] | select(.id == \$id) | .$2"
}
# check_pair TX_ID RX_ID LOST
check_pair() {
	local tx=$1 rx=$2 lost=$3
	[ "$(nh_stat $tx tx_packets)" -gt 0 ] || fail "nexthop $tx: nothing sent"
	[ "$(nh_stat $tx tx_packets)" -eq $(($(nh_stat $rx rx_packets) + lost)) ] \
		|| fail "packets sent to nexthop $tx and received from nexthop $rx differ"
	[ $lost -ne 0 ] || [ "$(nh_stat $tx tx_bytes)" -eq "$(nh_stat $rx rx_bytes)" ] \
		|| fail "bytes sent to nexthop $tx and received from nexthop $rx differ"
}
grcli nexthop stats
check_pair 14 24 $expired
check_pair 16 26 0
check_pair 24 14 0
check_pair 26 16 0

# The mappings of the two sites mirror each other: both pass the source EID
# filter. A host that sends from an address which is not an EID of its site
# does not.
grcli interface set lisp lisp-a eid_filter on
grcli interface set lisp lisp-b eid_filter on
ip netns exec host-a ping -i0.01 -c3 -n 10.2.0.2
ip netns exec host-a ping -i0.01 -c3 -n fd00:2::2
ip netns exec host-b ping -i0.01 -c3 -n 10.1.0.2
[ "$(counter lisp_input_unknown_eid)" -eq 0 ] || fail "unexpected lisp_input_unknown_eid drops"
ip -n host-a addr add 10.99.0.1/32 dev lo
ip netns exec host-a ping -i0.01 -c3 -W1 -n -I 10.99.0.1 10.2.0.2 \
	&& fail "reachable from a source that has no mapping"
[ "$(counter lisp_input_unknown_eid)" -eq 3 ] || fail "lisp_input_unknown_eid drops expected"
ip -n host-a addr del 10.99.0.1/32 dev lo
grcli interface set lisp lisp-a eid_filter off
grcli interface set lisp lisp-b eid_filter off

# The xTRs must agree on the instance ID.
grcli interface set lisp lisp-a iid 202
grcli -j interface show name lisp-a | jq -e '.iid == 202' || fail "instance ID not updated"
[ "$(counter lisp_input_no_tunnel)" -eq 0 ] || fail "unexpected lisp_input_no_tunnel drops"
ip netns exec host-a ping -i0.01 -c3 -W1 -n 10.2.0.2 && fail "reachable with another instance ID"
[ "$(counter lisp_input_no_tunnel)" -ge 3 ] || fail "lisp_input_no_tunnel drops expected"
grcli interface set lisp lisp-b iid 202
check_lisp 6 202

# Nothing is sent nor received through an interface that is down.
grcli interface set lisp lisp-b down
ip netns exec host-a ping -i0.01 -c3 -W1 -n 10.2.0.2 && fail "reachable with lisp-b down"
grcli interface set lisp lisp-b up
check_lisp 6 202

# Rename, then back to IPv4 RLOCs.
grcli interface set lisp lisp-a name lisp-a2
grcli -j interface show name lisp-a2 | jq -e '.iid == 202 and .encap_vrf == "wan-a"' \
	|| fail "attributes lost on rename"
grcli interface set lisp lisp-a2 name lisp-a
del_mappings
set_mappings 14 24
check_lisp 4 202

grcli interface stats
grcli stats show software

# The nexthops and the routes of an interface are deleted along with it.
grcli interface del lisp-a
grcli -j nexthop show type lisp | jq -e '[.[] | select(.iface == "lisp-a")] | length == 0' \
	|| fail "nexthops of lisp-a still present"
grcli -j nexthop show type lisp | jq -e '[.[] | select(.iface == "lisp-b")] | length == 2' \
	|| fail "nexthops of lisp-b deleted"
grcli route show vrf site-a | grep -F 10.2.0.0/24 && fail "route of lisp-a still present"
# Its instance ID can be bound again.
grcli interface add lisp lisp-a iid 202 local 192.0.2.1 encap_vrf wan-a vrf site-a
grcli nexthop add lisp iface lisp-a rloc 192.0.2.5 id 14
grcli route add 10.2.0.0/24 via id 14 vrf site-a
ip netns exec host-a ping -i0.01 -c3 -n 10.2.0.2
