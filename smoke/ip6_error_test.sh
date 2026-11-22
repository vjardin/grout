#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

# ICMPv6 errors sent to the source of the packets that cannot be forwarded.

. $(dirname $0)/_init.sh

port_add p0
port_add p1 mtu 1400
grcli address add fd00:ba4:0::1/64 iface p0
grcli address add fd00:ba4:1::1/64 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	ip link set $p mtu 1500
	move_to_netns $p $ns
	ip -n $ns addr add fd00:ba4:$n::2/64 dev $p
	ip -n $ns route add default via fd00:ba4:$n::1
done

ip netns exec n0 ping -i0.01 -c3 -n fd00:ba4:1::2

# capture_error TYPE COMMAND...
capture_error() {
	local type="$1" pid
	shift
	mark_events
	timeout 10 grcli capture iface p0 direction out count 1 \
		filter "ip6[40]=$type" > $tmp/error.pcapng &
	pid=$!
	wait_event -t10 "capture start"
	"$@" && fail "unexpected success: $*"
	wait $pid || fail "no ICMPv6 error of type $type"
	tcpdump -r $tmp/error.pcapng -nv | tee $tmp/error.txt
}

# A large invoking packet is truncated: the error is 1280 bytes long.
capture_error 3 ip netns exec n0 ping -c1 -W1 -t1 -s 1400 -n fd00:ba4:1::2
grep -qF 'payload length: 1240' $tmp/error.txt || fail "error larger than the minimum MTU"
# A small one is copied as a whole.
capture_error 3 ip netns exec n0 ping -c1 -W1 -t1 -n fd00:ba4:1::2
grep -qF 'payload length: 112' $tmp/error.txt || fail "invoking packet not copied as a whole"

counter() {
	grcli -j stats show software | jq -r --arg n "$1" \
		'[.[] | select(.node == $n) | .packets] | add // 0'
}

# A packet which is larger than the MTU of the output interface is only
# counted, unless this interface is asked to send packet too big errors.
ip netns exec n0 ping -c1 -W1 -s 1400 -n fd00:ba4:1::2 && fail "unexpected reply"
[ "$(counter ip6_output_too_big)" -eq 1 ] || fail "large packet not counted"
[ "$(counter ip6_error_pkt_too_big)" -eq 0 ] || fail "unexpected packet too big error"
grcli interface set port p1 pkt_too_big on
grcli interface show | grep -w p1 | grep -qw pkt_too_big || fail "flag not shown"

# Packet too big.
capture_error 2 ip netns exec n0 ping -c1 -W1 -s 1400 -n fd00:ba4:1::2
[ "$(counter ip6_output_too_big)" -eq 1 ] || fail "large packet still counted as a drop"
grep -qF 'packet too big, mtu 1400' $tmp/error.txt || fail "MTU not reported"
grep -qF 'payload length: 1240' $tmp/error.txt || fail "error larger than the minimum MTU"
ip -n n0 route get fd00:ba4:1::2 | grep -qw 'mtu 1400' || fail "path MTU not learned"
# The source fragments its packets from now on.
ip netns exec n0 ping -i0.01 -c3 -s 1400 -n fd00:ba4:1::2
# Path MTU discovery.
ip netns exec n0 ip -6 route flush cache
ip netns exec n0 tracepath -n fd00:ba4:1::2 | tee $tmp/tracepath
grep -qw 'pmtu 1400' $tmp/tracepath || fail "tracepath did not discover the path MTU"

# Back to the default.
grcli interface set port p1 pkt_too_big off
ip netns exec n0 ip -6 route flush cache
ip netns exec n0 ping -c1 -W1 -s 1400 -n fd00:ba4:1::2 && fail "unexpected reply"
[ "$(counter ip6_output_too_big)" -eq 2 ] || fail "large packet not counted"
