#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin

# Site b is reachable through two RLOCs, an IPv4 one and an IPv6 one.
#
#  host-a       EID VRF site-a      locator VRF wan-a      core
# 10.1.0.2 --- p0 10.1.0.1  lisp-a  192.0.2.1 p1 --------- 192.0.2.2
#                                   2001:db8:a::1          2001:db8:a::2
#                                                             |
# 10.2.0.2 --- p3 10.2.0.1  lisp-b  192.0.2.5 p2 --------- 192.0.2.6
#                                   2001:db8:b::1          2001:db8:b::2
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
grcli address add 192.0.2.1/30 iface p1
grcli address add 2001:db8:a::1/64 iface p1
grcli address add 192.0.2.5/30 iface p2
grcli address add 2001:db8:b::1/64 iface p2
grcli address add 10.2.0.1/24 iface p3

netns_add host-a
move_to_netns x-p0 host-a
ip -n host-a addr add 10.1.0.2/24 dev x-p0
ip -n host-a route add default via 10.1.0.1

netns_add host-b
move_to_netns x-p3 host-b
ip -n host-b addr add 10.2.0.2/24 dev x-p3
ip -n host-b route add default via 10.2.0.1

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

grcli interface add lisp lisp-a iid 101 local 192.0.2.1 local6 2001:db8:a::1 \
	encap_vrf wan-a vrf site-a
grcli interface add lisp lisp-b iid 101 local 192.0.2.5 local6 2001:db8:b::1 \
	encap_vrf wan-b vrf site-b

# The locator set of site b.
grcli nexthop add lisp iface lisp-a rloc 192.0.2.5 id 14 stats
grcli nexthop add lisp iface lisp-a rloc 2001:db8:b::1 id 16 stats
grcli nexthop add group id 100 member 14 weight 1 member 16 weight 3
grcli route add 10.2.0.0/24 via id 100 vrf site-a
# Site a has a single RLOC. Its IPv6 one only sends packets.
grcli nexthop add lisp iface lisp-b rloc 192.0.2.1 id 24 stats
grcli nexthop add lisp iface lisp-b rloc 2001:db8:a::1 id 26 stats
grcli route add 10.1.0.0/24 via id 24 vrf site-b
grcli nexthop show
grcli route show vrf site-a

# Resolve the neighbors of the underlay.
ip netns exec core ping -i0.01 -c3 -n 192.0.2.1
ip netns exec core ping -i0.01 -c3 -n 192.0.2.5
ip netns exec core ping -i0.01 -c3 -n 2001:db8:a::1
ip netns exec core ping -i0.01 -c3 -n 2001:db8:b::1
ip netns exec host-a ping -i0.01 -c3 -n 10.2.0.2

wait_ready() {
	local i
	for i in $(seq 50); do
		[ -e $tmp/ready ] && return
		sleep 0.1
	done
	fail "helper not ready"
}

flows=64

# nh_stat ID COUNTER
nh_stat() {
	grcli -j nexthop stats | jq --argjson id $1 ".[] | select(.id == \$id) | .$2"
}

nh_packets() {
	nh_stat $1 tx_packets
}

# Send flows from host-a to host-b and count them per RLOC in the core.
send_flows() {
	local cap_pid recv_pid nh4 nh6 tx
	nh4=$(nh_packets 14)
	nh6=$(nh_packets 16)
	rm -f $tmp/ready
	ip netns exec core lisp_xtr capture x-p1 --count $flows \
		--ready $tmp/ready > $tmp/capture &
	cap_pid=$!
	wait_ready
	rm -f $tmp/ready
	ip netns exec host-b lisp_xtr recv --ready $tmp/ready > $tmp/recv &
	recv_pid=$!
	wait_ready
	ip netns exec host-a lisp_xtr udp 10.2.0.2 --count $flows --payload flow
	# The last packet may take the other RLOC: let the flows arrive first.
	sleep 0.2
	ip netns exec host-a lisp_xtr udp 10.2.0.2 --payload end
	wait $recv_pid || fail "flows were not delivered"
	wait $cap_pid || fail "flows did not cross the core"
	[ "$(grep -c -e ' payload=flow$' $tmp/recv)" -eq $flows ] || fail "flows were lost"
	rloc4=$(grep -cw -e "dst=192.0.2.5" $tmp/capture || true)
	rloc6=$(grep -cw -e "dst=2001:db8:b::1" $tmp/capture || true)
	echo "flows: $rloc4 to the IPv4 RLOC, $rloc6 to the IPv6 RLOC"
	[ $((rloc4 + rloc6)) -eq $flows ] || fail "unexpected RLOC"

	# Each RLOC counts its share of the flows. The last packet is not captured.
	nh4=$(($(nh_packets 14) - nh4))
	nh6=$(($(nh_packets 16) - nh6))
	[ $((nh4 + nh6)) -eq $((flows + 1)) ] || fail "$nh4 + $nh6 packets counted"
	[ $nh4 -ge $rloc4 ] && [ $nh6 -ge $rloc6 ] || fail "$nh4 and $nh6 packets counted"
	# All the packets of the interface go to one of these two RLOCs.
	tx=$(grcli -j interface stats | jq '.[] | select(.interface == "lisp-a") | .tx_packets')
	[ $(($(nh_packets 14) + $(nh_packets 16))) -eq "$tx" ] \
		|| fail "the RLOCs do not add up to the $tx packets of the interface"
	# Site b has received them from the RLOC of site a of the same family.
	[ "$(nh_stat 24 rx_packets)" -eq "$(nh_packets 14)" ] \
		|| fail "packets sent to and received from the IPv4 RLOCs differ"
	[ "$(nh_stat 26 rx_packets)" -eq "$(nh_packets 16)" ] \
		|| fail "packets sent to and received from the IPv6 RLOCs differ"
}

# Both RLOCs are used, according to their weights.
send_flows
[ "$rloc4" -gt 0 ] || fail "IPv4 RLOC not used"
[ "$rloc6" -gt "$rloc4" ] || fail "weights not honored"

# All the packets of a flow go to the same RLOC.
same_flow() {
	local i
	for i in $(seq 8); do
		ip netns exec host-a lisp_xtr udp 10.2.0.2 --sport 5555
	done
}
rm -f $tmp/ready
ip netns exec core lisp_xtr capture x-p1 --count 8 --ready $tmp/ready > $tmp/capture &
cap_pid=$!
wait_ready
same_flow
wait $cap_pid || fail "flow did not cross the core"
[ "$(grep -ow -e 'dst=[0-9a-f.:]*' $tmp/capture | sort -u | wc -l)" -eq 1 ] \
	|| fail "the packets of a flow were sent to several RLOCs"

# An RLOC which is not usable anymore is removed from the locator set.
grcli nexthop add group id 100 member 14
send_flows
[ "$rloc4" -eq $flows ] || fail "IPv6 RLOC still used"
grcli nexthop add group id 100 member 16
send_flows
[ "$rloc6" -eq $flows ] || fail "IPv4 RLOC still used"

# Equal weights.
grcli nexthop add group id 100 member 14 member 16
send_flows
[ "$rloc4" -gt 0 ] || fail "IPv4 RLOC not used"
[ "$rloc6" -gt 0 ] || fail "IPv6 RLOC not used"

# Source EID filter. Site b maps the EIDs of site a to its IPv4 RLOC only:
# what site a sends from its IPv6 RLOC is dropped.
counter() {
	grcli -j stats show software | jq -r --arg n "$1" \
		'[.[] | select(.node == $n) | .packets] | add // 0'
}
grcli interface set lisp lisp-b eid_filter on
rm -f $tmp/ready
ip netns exec core lisp_xtr capture x-p1 --count $flows --ready $tmp/ready > $tmp/capture &
cap_pid=$!
wait_ready
rm -f $tmp/ready
ip netns exec host-b lisp_xtr recv --ready $tmp/ready > $tmp/recv &
recv_pid=$!
wait_ready
ip netns exec host-a lisp_xtr udp 10.2.0.2 --count $flows --payload flow
wait $cap_pid || fail "flows did not cross the core"
sleep 0.2
grcli interface set lisp lisp-b eid_filter off
ip netns exec host-a lisp_xtr udp 10.2.0.2 --payload end
wait $recv_pid || fail "last packet not received"
rloc4=$(grep -cw -e "dst=192.0.2.5" $tmp/capture || true)
rloc6=$(grep -cw -e "dst=2001:db8:b::1" $tmp/capture || true)
echo "flows: $rloc4 to the IPv4 RLOC, $rloc6 to the IPv6 RLOC"
[ "$rloc4" -gt 0 ] && [ "$rloc6" -gt 0 ] || fail "both RLOCs must be used"
[ "$(grep -c -e ' payload=flow$' $tmp/recv)" -eq "$rloc4" ] \
	|| fail "only the flows of the IPv4 RLOC must be delivered"
[ "$(counter lisp_input_unknown_eid)" -eq "$rloc6" ] \
	|| fail "the flows of the IPv6 RLOC must be dropped"

# With the locator set of site a in the mapping, all the flows pass. The
# counters start again from zero: the dropped flows were sent, not received.
grcli nexthop add group id 200 member 24 member 26
grcli route del 10.1.0.0/24 vrf site-b
grcli route add 10.1.0.0/24 via id 200 vrf site-b
grcli stats reset
grcli interface set lisp lisp-b eid_filter on
send_flows
[ "$(counter lisp_input_unknown_eid)" -eq 0 ] || fail "unexpected lisp_input_unknown_eid drops"
