#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

# 40000 remote sites with 4 EID subnets each, installed and withdrawn through
# the API by lisp_inject. Each step is timed.
#
#  peer xTR                     grout
# 192.0.2.2 ------ p0 192.0.2.1      locator VRF wan
#                     lisp1 (iid 1001)  EID VRF t1

: "${sites:=40000}"
subnets=4

grout_verbose_level=1
grout_max_nexthops=$((sites + 1024))
trace_enable=false
follow_events=hide
. $(dirname $0)/_init.sh

grcli interface add vrf wan
port_add p0 vrf wan
grcli address add 192.0.2.1/30 iface p0

netns_add peer
move_to_netns x-p0 peer
ip -n peer addr add 192.0.2.2/30 dev x-p0

# All the remote RLOCs are behind the peer, which can send from any of them.
grcli route add 198.18.0.0/15 via 192.0.2.2 vrf wan
ip -n peer addr add 198.18.0.0/15 dev lo
ip netns exec peer ping -i0.01 -c3 -n 192.0.2.1

# Only the EID VRF needs a large IPv4 table.
grcli interface add vrf t1 rib4-routes $((sites * subnets + 1024))
grcli interface add lisp lisp1 iid 1001 local 192.0.2.1 encap_vrf wan vrf t1

rss() {
	ps -o rss= -p $grout_pid | awk '{ printf "%d MB\n", $1 / 1024 }'
}

# timed LABEL MAX_MS COMMAND...
timed() {
	local label="$1" max="$2" start=$(date +%s%N) ms
	shift 2
	"$@"
	ms=$((($(date +%s%N) - start) / 1000000))
	echo "TIME $label: $ms ms"
	[ "$ms" -le "$max" ] || fail "$label took more than $max ms"
}

count() {
	grcli -j "$@" max 0 | jq length
}

read_stats() {
	grcli -j nexthop stats type lisp max 0 > $tmp/stats
}

wait_ready() {
	local i
	for i in $(seq 50); do
		[ -e $tmp/ready ] && return
		sleep 0.1
	done
	fail "helper not ready"
}

# check_sites SITE...
check_sites() {
	local s p eid rloc expect=() pid item
	for s in "$@"; do
		p=$((s * subnets + subnets - 1))
		eid="$((10 + p / 65536)).$((p / 256 % 256)).$((p % 256)).9"
		rloc="198.$((18 + s / 65536)).$((s / 256 % 256)).$((s % 256))"
		expect+=("$eid $rloc")
	done
	rm -f $tmp/ready
	ip netns exec peer lisp_xtr capture x-p0 --count ${#expect[@]} \
		--ready $tmp/ready > $tmp/capture &
	pid=$!
	wait_ready
	# Each site sends a packet to itself, from its own RLOC.
	for item in "${expect[@]}"; do
		read -r eid rloc <<< "$item"
		ip netns exec peer lisp_xtr send 192.0.2.1 --local $rloc --iid 1001 \
			--isrc 10.255.255.1 --idst $eid
	done
	wait $pid || fail "packets were not sent back"
	for item in "${expect[@]}"; do
		read -r eid rloc <<< "$item"
		grep -wF -e "idst=$eid" $tmp/capture | grep -qwF -e "dst=$rloc" ||
			fail "$eid not sent to $rloc"
	done
}

echo "MEMORY before: $(rss)"
timed "install $sites sites" 60000 lisp_inject -n $sites -m $subnets lisp1
echo "MEMORY after: $(rss)"
[ "$(count nexthop show type lisp)" -eq $sites ] || fail "missing nexthops"
[ "$(count route show vrf t1)" -ge $((sites * subnets)) ] || fail "missing routes"
sampled=(0 1 $((sites / 2)) $((sites - 2)) $((sites - 1)))
check_sites "${sampled[@]}"

# Each site has its counters. Only the sampled ones have sent a packet, and
# were sent one.
timed "read $sites counters" 5000 read_stats
[ "$(jq length $tmp/stats)" -eq $sites ] || fail "missing counters"
[ "$(jq '[.[] | select(.rx_packets == 1 and .tx_packets == 1)] | length' $tmp/stats)" \
	-eq ${#sampled[@]} ] || fail "unexpected counters"
[ "$(jq '[.[].rx_packets] | add' $tmp/stats)" -eq ${#sampled[@]} ] || fail "unexpected counters"
[ "$(jq '[.[].tx_packets] | add' $tmp/stats)" -eq ${#sampled[@]} ] || fail "unexpected counters"

# Withdraw some sites: their routes first, then their nexthop.
chunk=$((sites / 40))
timed "withdraw $chunk sites" 5000 lisp_inject -d -f $chunk -n $chunk -m $subnets lisp1
# Withdraw as many other sites by deleting their nexthop, routes included.
timed "delete $chunk nexthops" 120000 lisp_inject -D -f $((2 * chunk)) -n $chunk -m $subnets lisp1
[ "$(count nexthop show type lisp)" -eq $((sites - 2 * chunk)) ] || fail "nexthops not deleted"
[ "$(count route show vrf t1)" -lt $(((sites - 2 * chunk) * subnets + 16)) ] \
	|| fail "routes not deleted"
timed "install $((2 * chunk)) sites" 5000 lisp_inject -f $chunk -n $((2 * chunk)) -m $subnets lisp1
check_sites 0 $chunk $((2 * chunk - 1)) $((2 * chunk)) $((3 * chunk - 1)) $((sites - 1))

# Remove the tenant: all its nexthops and routes go with the interface.
timed "delete the interface" 30000 grcli interface del lisp1
[ "$(count nexthop show type lisp)" -eq 0 ] || fail "nexthops not flushed"
[ "$(count route show vrf t1)" -lt 16 ] || fail "routes not flushed"
echo "MEMORY end: $(rss)"
