#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin

# Many remote RLOCs and EID prefixes for several tenants. The packets that
# the peer sends are decapsulated and sent back to the RLOC of their EID.
#
#  peer xTR                     grout
# 192.0.2.2 ------ p0 192.0.2.1      locator VRF wan
# 2001:db8:a::2       2001:db8:a::1
#                     lisp1 (iid 1001)  EID VRF t1  \
#                     lisp2 (iid 1002)  EID VRF t2   } the same EID prefixes,
#                     lisp3 (iid 1003)  EID VRF t3  /  mapped to other RLOCs

tenants=3
# Remote RLOCs per tenant. Every other one is an IPv6 RLOC.
rlocs=1024
# For each RLOC, 4 IPv4 EID prefixes and 1 IPv6 EID prefix.
grout_max_nexthops=4096
grout_max_routes=8192
grout_verbose_level=1

. $(dirname $0)/_init.sh

grcli interface add vrf wan
port_add p0 vrf wan
grcli address add 192.0.2.1/30 iface p0
grcli address add 2001:db8:a::1/64 iface p0

netns_add peer
move_to_netns x-p0 peer
ip -n peer addr add 192.0.2.2/30 dev x-p0
ip -n peer addr add 2001:db8:a::2/64 dev x-p0

# All the remote RLOCs are behind the peer.
grcli route add 198.18.0.0/15 via 192.0.2.2 vrf wan
grcli route add 2001:db8:f::/48 via 2001:db8:a::2 vrf wan
ip netns exec peer ping -i0.01 -c3 -n 192.0.2.1
ip netns exec peer ping -i0.01 -c3 -n 2001:db8:a::1

# The helpers return their result in $REPLY: no subshell per mapping.

# rloc TENANT INDEX
rloc() {
	local t="$1" r="$2"
	if [ $((r % 2)) -eq 0 ]; then
		REPLY="198.18.$((t * 8 + r / 256)).$((r % 256))"
	else
		printf -v REPLY '2001:db8:f::%x:%x' "$t" "$r"
	fi
}

# eid4 RLOC_INDEX PREFIX_INDEX HOST
eid4() {
	local r="$1" e="$2" host="$3"
	REPLY="10.$((e * 4 + r / 256)).$((r % 256)).$host"
}

# eid6 RLOC_INDEX HOST
eid6() {
	local r="$1" host="$2"
	# always in canonical form
	printf -v REPLY 'fd00:0:0:%x::%s' "$((r + 4096))" "$host"
}

for t in $(seq $tenants); do
	grcli interface add vrf t$t
	grcli interface add lisp lisp$t iid $((1000 + t)) \
		local 192.0.2.1 local6 2001:db8:a::1 encap_vrf wan vrf t$t
done

set +x
for t in $(seq $tenants); do
	for r in $(seq 0 $((rlocs - 1))); do
		nh=$((t * 10000 + r + 1))
		rloc $t $r
		echo "nexthop add lisp iface lisp$t rloc $REPLY id $nh stats"
		for e in 0 1 2 3; do
			eid4 $r $e 0
			echo "route add $REPLY/24 via id $nh vrf t$t"
		done
		eid6 $r ""
		echo "route add $REPLY/64 via id $nh vrf t$t"
	done
done > $tmp/mappings
set -x

SECONDS=0
grcli -e -f $tmp/mappings > /dev/null
echo "$(wc -l < $tmp/mappings) commands in ${SECONDS}s"

count() {
	grcli -j "$@" max 0 | jq length
}
[ "$(count nexthop show type lisp)" -eq $((tenants * rlocs)) ] || fail "missing nexthops"
[ "$(count nexthop stats type lisp)" -eq $((tenants * rlocs)) ] || fail "missing counters"
for t in $(seq $tenants); do
	[ "$(count route show vrf t$t)" -ge $((rlocs * 5)) ] || fail "missing routes in t$t"
done

wait_ready() {
	local i
	for i in $(seq 50); do
		[ -e $tmp/ready ] && return
		sleep 0.1
	done
	fail "helper not ready"
}

# Mappings to check: the first and the last ones, and some in between.
samples="0 1 2 255 256 511 $((rlocs - 2)) $((rlocs - 1))"

# check_tenant TENANT IID
check_tenant() {
	local t="$1" iid="$2" dst4="" dst6="" expect=()
	local out_iid=$((1000 + t)) r e pid item eid to
	for r in $samples; do
		rloc $t $r
		to=$REPLY
		for e in 0 3; do
			eid4 $r $e 9
			dst4+=" --idst $REPLY"
			expect+=("$REPLY $to")
		done
		eid6 $r 9
		dst6+=" --idst $REPLY"
		expect+=("$REPLY $to")
	done
	rm -f $tmp/ready
	ip netns exec peer lisp_xtr capture x-p0 --count ${#expect[@]} \
		--ready $tmp/ready > $tmp/capture &
	pid=$!
	wait_ready
	ip netns exec peer lisp_xtr send 192.0.2.1 --iid $iid --isrc 10.255.255.1 $dst4
	ip netns exec peer lisp_xtr send 2001:db8:a::1 --iid $iid --isrc fd00:ffff::1 $dst6
	wait $pid || fail "tenant $t: packets were not sent back"
	for item in "${expect[@]}"; do
		read -r eid to <<< "$item"
		grep -wF -e "idst=$eid" $tmp/capture | grep -wF -e "dst=$to" |
			grep -qwF -e "iid=$out_iid" ||
			fail "tenant $t: $eid not sent to $to with instance ID $out_iid"
	done
}

for t in $(seq $tenants); do
	check_tenant $t $((1000 + t))
done

# The RLOCs add up to the packets of the interfaces.
tx_nexthops=$(grcli -j nexthop stats type lisp max 0 | jq '[.[].tx_packets] | add')
tx_ifaces=$(grcli -j interface stats \
	| jq '[.[] | select(.interface | startswith("lisp")) | .tx_packets] | add')
[ "$tx_nexthops" -gt 0 ] || fail "no packet counted"
[ "$tx_nexthops" -eq "$tx_ifaces" ] \
	|| fail "$tx_nexthops packets for the RLOCs, $tx_ifaces for the interfaces"

# Several instance IDs bound to the same VRF.
for i in $(seq 32); do
	grcli interface add lisp extra$i iid $((2000 + i)) local 192.0.2.1 \
		local6 2001:db8:a::1 encap_vrf wan vrf t3
done
check_tenant 3 2001
check_tenant 3 2032

# Deleting an interface flushes its nexthops and its routes.
SECONDS=0
grcli interface del lisp2
echo "lisp2 deleted in ${SECONDS}s"
[ "$(count nexthop show type lisp)" -eq $(((tenants - 1) * rlocs)) ] || fail "nexthops not flushed"
[ "$(count nexthop stats type lisp)" -eq $(((tenants - 1) * rlocs)) ] || fail "counters not flushed"
[ "$(count route show vrf t2)" -lt 5 ] || fail "routes not flushed"
check_tenant 1 1001
check_tenant 3 1003
eid4 0 0 9
ip netns exec peer lisp_xtr send 192.0.2.1 --iid 1002 --isrc 10.255.255.1 --idst $REPLY
sleep 0.2
dropped=$(grcli -j stats show software | jq -r \
	'[.[] | select(.node == "lisp_input_no_tunnel") | .packets] | add // 0')
[ "$dropped" -eq 1 ] || fail "packet of a deleted instance ID not dropped"
