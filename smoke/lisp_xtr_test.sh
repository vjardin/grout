#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin

# Wire format, against a remote xTR which is not grout (lisp_xtr).
#
#  host                   grout                                  peer xTR
# 10.1.0.2 --- p0 10.1.0.1  lisp0 (iid 101)  192.0.2.1 p1 --- 192.0.2.2
# fd00:1::2       fd00:1::1                  2001:db8:a::1    2001:db8:a::2
#              EID VRF site               locator VRF wan
#
# 10.2.0.0/24, fd00:2::/64 -> IPv4 RLOC, 10.3.0.0/24, fd00:3::/64 -> IPv6 RLOC

. $(dirname $0)/_init.sh

grcli interface add vrf site
grcli interface add vrf wan
port_add p0 vrf site
port_add p1 vrf wan
grcli address add 10.1.0.1/24 iface p0
grcli address add fd00:1::1/64 iface p0
grcli address add 192.0.2.1/30 iface p1
grcli address add 2001:db8:a::1/64 iface p1
# A local address of the locator VRF that is not an RLOC.
grcli address add 198.51.100.1/24 iface p1

netns_add lan
move_to_netns x-p0 lan
ip -n lan addr add 10.1.0.2/24 dev x-p0
ip -n lan addr add fd00:1::2/64 dev x-p0 nodad
ip -n lan route add default via 10.1.0.1
ip -n lan route add default via fd00:1::1

netns_add peer
move_to_netns x-p1 peer
ip -n peer addr add 192.0.2.2/30 dev x-p1
ip -n peer addr add 2001:db8:a::2/64 dev x-p1 nodad
ip -n peer addr add 198.51.100.2/24 dev x-p1

grcli interface add lisp lisp0 iid 101 local 192.0.2.1 local6 2001:db8:a::1 \
	encap_vrf wan vrf site
grcli nexthop add lisp iface lisp0 rloc 192.0.2.2 id 14 stats
grcli nexthop add lisp iface lisp0 rloc 2001:db8:a::2 id 16 stats
grcli route add 10.2.0.0/24 via id 14 vrf site
grcli route add fd00:2::/64 via id 14 vrf site
grcli route add 10.3.0.0/24 via id 16 vrf site
grcli route add fd00:3::/64 via id 16 vrf site

# Resolve the neighbors.
ip netns exec lan ping -i0.01 -c3 -n 10.1.0.1
ip netns exec lan ping -i0.01 -c3 -n fd00:1::1
ip netns exec peer ping -i0.01 -c3 -n 192.0.2.1
ip netns exec peer ping -i0.01 -c3 -n 2001:db8:a::1
ip netns exec peer ping -i0.01 -c3 -n 198.51.100.1

wait_ready() {
	local i
	for i in $(seq 50); do
		[ -e $tmp/ready ] && return
		sleep 0.1
	done
	fail "helper not ready"
}

host_udp() {
	ip netns exec lan lisp_xtr udp "$@"
}

peer_send() {
	ip netns exec peer lisp_xtr send "$@"
}

# capture COUNT COMMAND...
capture() {
	local count="$1" pid
	shift
	rm -f $tmp/ready
	ip netns exec peer lisp_xtr capture x-p1 --count "$count" \
		--ready $tmp/ready > $tmp/capture &
	pid=$!
	wait_ready
	"$@"
	wait $pid || fail "$count LISP packets expected from: $*"
	cat $tmp/capture
}

# Check that all the captured packets have the given fields.
check_fields() {
	local f
	for f in "$@"; do
		if grep -vqwF -- "$f" $tmp/capture; then
			fail "$f expected in: $(grep -vwF -- "$f" $tmp/capture | head -n1)"
		fi
	done
}

# check_encap OUTER_IP_HEADER_SIZE
check_encap() {
	awk -v ip="$1" '{
		for (i = 1; i <= NF; i++) {
			split($i, kv, "=")
			f[kv[1]] = kv[2]
		}
		if (f["len"] != f["ilen"] + ip + 16)
			exit 1
		if (f["udplen"] != f["ilen"] + 16)
			exit 1
		if (f["sport"] < 49152)
			exit 1
	}' $tmp/capture || fail "bad lengths or source port"
}

distinct() {
	grep -ow -- "$1=[0-9a-fx]*" $tmp/capture | sort -u | wc -l
}

counter() {
	grcli -j stats show software | jq -r --arg n "$1" \
		'[.[] | select(.node == $n) | .packets] | add // 0'
}

check_counter() {
	local n
	n=$(counter "$1")
	[ "$n" -eq "$2" ] || fail "$1: $n packets, expected $2"
}

# nh_stat ID COUNTER
nh_stat() {
	grcli -j nexthop stats | jq --argjson id $1 ".[] | select(.id == \$id) | .$2"
}

# check_nh_stats ID tx|rx PACKETS [BYTES]
check_nh_stats() {
	local id=$1 dir=$2 packets=$3 bytes=${4:-} n

	n=$(nh_stat $id ${dir}_packets)
	[ "$n" -eq $packets ] || fail "nexthop $id: $n $dir packets, expected $packets"
	[ -n "$bytes" ] || return 0
	n=$(nh_stat $id ${dir}_bytes)
	[ "$n" -eq $bytes ] || fail "nexthop $id: $n $dir bytes, expected $bytes"
}

# DSCP and ECN codepoints.
ef=0xb8
af11=0x28
not_ect=0x00
ect1=0x01
ect0=0x02
ce=0x03
# LISP flags: instance ID present, and all the ones that are ignored.
flag_i=0x08
flags_ignored=0xfc
# What is left of 1500 bytes after the largest outer headers.
eth_mtu=1500
mtu=$((eth_mtu - 40 - 8 - 8))
ip4_udp=$((20 + 8))
ip6_udp=$((40 + 8))
ttl=64
low_ttl=5
lower_ttl=3

# Encapsulation
tos=$(printf '0x%02x' $((ef | ect1)))
lisp_hdr="udpcksum=0x0000 flags=$flag_i nonce=0x000000 iid=101 lsb=0x00"

capture 1 host_udp 10.2.0.9 --tos $tos --ttl $ttl --payload v4-in-v4
check_fields af=4 src=192.0.2.1 dst=192.0.2.2 tos=$tos ttl=$((ttl - 1)) df=1 cksum=ok $lisp_hdr \
	iaf=4 isrc=10.1.0.2 idst=10.2.0.9 itos=$tos ittl=$((ttl - 1)) icksum=ok payload=v4-in-v4
check_encap 20

capture 1 host_udp fd00:2::9 --tos $tos --ttl $ttl --payload v6-in-v4
check_fields af=4 src=192.0.2.1 dst=192.0.2.2 tos=$tos ttl=$((ttl - 1)) df=1 cksum=ok $lisp_hdr \
	iaf=6 isrc=fd00:1::2 idst=fd00:2::9 itos=$tos ittl=$((ttl - 1)) payload=v6-in-v4
check_encap 20

capture 1 host_udp 10.3.0.9 --tos $tos --ttl $ttl --payload v4-in-v6
check_fields af=6 src=2001:db8:a::1 dst=2001:db8:a::2 tos=$tos ttl=$((ttl - 1)) $lisp_hdr \
	iaf=4 isrc=10.1.0.2 idst=10.3.0.9 itos=$tos ittl=$((ttl - 1)) icksum=ok payload=v4-in-v6
check_encap 40

capture 1 host_udp fd00:3::9 --tos $tos --ttl $ttl --payload v6-in-v6
check_fields af=6 src=2001:db8:a::1 dst=2001:db8:a::2 tos=$tos ttl=$((ttl - 1)) $lisp_hdr \
	iaf=6 isrc=fd00:1::2 idst=fd00:3::9 itos=$tos ittl=$((ttl - 1)) payload=v6-in-v6
check_encap 40

# Each RLOC has counted an IPv4 and an IPv6 inner packet, without the outer
# headers.
tag_len=8
check_nh_stats 14 tx 2 $((ip4_udp + tag_len + ip6_udp + tag_len))
check_nh_stats 16 tx 2 $((ip4_udp + tag_len + ip6_udp + tag_len))

# Source port and flow label entropy.
same_flow() {
	host_udp 10.2.0.9 --sport 5555
	host_udp 10.2.0.9 --sport 5555
}
capture 2 same_flow
[ "$(distinct sport)" -eq 1 ] || fail "source port changed for the same flow"
capture 32 host_udp 10.2.0.9 --count 32
[ "$(distinct sport)" -ge 8 ] || fail "no entropy in the source port"
check_encap 20
capture 32 host_udp fd00:3::9 --count 32
[ "$(distinct sport)" -ge 8 ] || fail "no entropy in the source port"
[ "$(distinct flow)" -ge 8 ] || fail "no entropy in the flow label"
check_encap 40

# MTU and fragmentation.
grcli -j interface show name lisp0 | jq -e --argjson mtu $mtu '.mtu == $mtu' \
	|| fail "unexpected MTU"
capture 1 host_udp 10.3.0.9 --df --size $((mtu - ip4_udp)) --payload fits
check_fields af=6 len=$eth_mtu ilen=$mtu payload=fits
capture 2 host_udp 10.2.0.9 --size $((mtu - ip4_udp + 1)) --payload fragmented
check_fields af=4 df=1 iaf=4
check_encap 20
check_counter ip_error_frag_needed 0
check_counter ip6_error_pkt_too_big 0
host_udp 10.2.0.9 --df --size $((mtu - ip4_udp + 1)) --payload too-big
host_udp fd00:2::9 --size $((mtu - ip6_udp + 1)) --payload too-big
sleep 0.2
check_counter ip_error_frag_needed 1
# The interface has to ask for the ICMPv6 errors.
check_counter ip6_output_too_big 1
check_counter ip6_error_pkt_too_big 0
grcli interface set lisp lisp0 pkt_too_big on
host_udp fd00:2::9 --size $((mtu - ip6_udp + 1)) --payload too-big
sleep 0.2
check_counter ip6_output_too_big 1
check_counter ip6_error_pkt_too_big 1
# So far: 2 packets, 2 of the same flow, 32 flows, then 2 fragments to the
# IPv4 RLOC and a packet that fits to the IPv6 one. The packets that are too
# big are not counted.
check_nh_stats 14 tx $((2 + 2 + 32 + 2))
check_nh_stats 16 tx $((2 + 32 + 1))

# No route to the remote RLOC in the locator VRF.
grcli nexthop add lisp iface lisp0 rloc 203.0.113.1 id 99 stats
grcli route add 10.9.0.0/24 via id 99 vrf site
host_udp 10.9.0.9 --payload no-route
sleep 0.2
check_counter lisp_output_no_route 1
# A packet that is not encapsulated is not counted.
check_nh_stats 99 tx 0 0

# Decapsulation
rm -f $tmp/ready
ip netns exec lan lisp_xtr recv --ready $tmp/ready > $tmp/recv &
recv_pid=$!
wait_ready

rloc4=192.0.2.1
rloc6=2001:db8:a::1
in4="--iid 101 --isrc 10.2.0.9 --idst 10.1.0.2"
in6="--iid 101 --isrc fd00:2::9 --idst fd00:1::2"

# Address families and UDP checksums.
peer_send $rloc4 $in4 --payload v4-in-v4
peer_send $rloc4 $in6 --payload v6-in-v4
peer_send $rloc6 $in4 --payload v4-in-v6
peer_send $rloc6 $in6 --payload v6-in-v6
peer_send $rloc4 $in4 --udp-cksum --payload cksum-v4
peer_send $rloc6 $in6 --udp-cksum --payload cksum-v6
# Ignored fields.
peer_send $rloc4 $in4 --flags $flags_ignored --nonce 0xffffff --lsb 0xff --payload flags
# TTL.
peer_send $rloc4 $in4 --ttl $low_ttl --ittl $ttl --payload ttl-outer-v4
peer_send $rloc6 $in6 --ttl $low_ttl --ittl $ttl --payload ttl-outer-v6
peer_send $rloc4 $in4 --ttl $ttl --ittl $lower_ttl --payload ttl-inner-v4
peer_send $rloc6 $in6 --ttl $ttl --ittl $lower_ttl --payload ttl-inner-v6
# DSCP and ECN.
peer_send $rloc4 $in4 --tos $ef --itos $af11 --payload dscp-v4
peer_send $rloc6 $in6 --tos $ef --itos $af11 --payload dscp-v6
peer_send $rloc4 $in4 --tos $ce --itos $ect0 --payload ecn-ce-v4
peer_send $rloc6 $in6 --tos $ce --itos $ect0 --payload ecn-ce-v6
peer_send $rloc4 $in4 --tos $ect1 --itos $ect0 --payload ecn-ect1
peer_send $rloc4 $in4 --tos $ect0 --itos $ect1 --payload ecn-inner
peer_send $rloc4 $in4 --tos $ce --itos $not_ect --payload ecn-drop-v4
peer_send $rloc6 $in6 --tos $ce --itos $not_ect --payload ecn-drop-v6
# Packets that must be dropped.
peer_send $rloc4 $in4 --iid 999 --payload iid-unknown
peer_send $rloc4 $in4 --flags 0 --payload iid-none
peer_send 198.51.100.1 $in4 --payload not-rloc
for key in 1 2 3; do
	peer_send $rloc4 $in4 --flags $((flag_i | key)) --payload key-$key
done
peer_send $rloc4 $in4 --truncate 8 --payload short-hdr
peer_send $rloc4 $in4 --truncate 27 --payload short-v4
peer_send $rloc4 $in6 --truncate 47 --payload short-v6
peer_send $rloc4 $in4 --inner-version 5 --payload version
peer_send $rloc4 $in4 --ttl $low_ttl --tos $ef --bad-inner-cksum --payload bad-cksum
grcli interface set lisp lisp0 down
peer_send $rloc4 $in4 --payload down
grcli interface set lisp lisp0 up
peer_send $rloc4 $in4 --payload end

wait $recv_pid || fail "last packet not received"
cat $tmp/recv

# delivered PAYLOAD FIELD...
delivered() {
	local name="$1" line f
	shift
	line=$(grep -- " payload=$name\$" $tmp/recv) || fail "$name: not delivered"
	for f in "$@"; do
		echo "$line" | grep -qwF -- "$f" || fail "$name: $f expected in: $line"
	done
}

delivered v4-in-v4 af=4 src=10.2.0.9 tos=$not_ect ttl=$((ttl - 1))
delivered v6-in-v4 af=6 src=fd00:2::9 tos=$not_ect ttl=$((ttl - 1))
delivered v4-in-v6 af=4 src=10.2.0.9 tos=$not_ect ttl=$((ttl - 1))
delivered v6-in-v6 af=6 src=fd00:2::9 tos=$not_ect ttl=$((ttl - 1))
delivered cksum-v4
delivered cksum-v6
delivered flags ttl=$((ttl - 1))
delivered ttl-outer-v4 ttl=$((low_ttl - 1))
delivered ttl-outer-v6 ttl=$((low_ttl - 1))
delivered ttl-inner-v4 ttl=$((lower_ttl - 1))
delivered ttl-inner-v6 ttl=$((lower_ttl - 1))
delivered dscp-v4 tos=$ef
delivered dscp-v6 tos=$ef
delivered ecn-ce-v4 tos=$ce
delivered ecn-ce-v6 tos=$ce
delivered ecn-ect1 tos=$ect1
delivered ecn-inner tos=$ect1
delivered end
[ "$(wc -l < $tmp/recv)" -eq 18 ] || fail "unexpected packets were delivered"

check_counter lisp_input_ecn_drop 2
check_counter lisp_input_no_tunnel 2
check_counter lisp_input_bad_rloc 1
check_counter lisp_input_bad_flags 3
check_counter lisp_input_bad_length 3
check_counter lisp_input_bad_version 1
check_counter ip_input_bad_checksum 1
check_counter iface_input_admin_down 1

# The packets that were decapsulated are counted on the nexthop of their
# source RLOC: the 18 delivered ones and the one with a bad inner checksum.
check_nh_stats 14 rx 12
check_nh_stats 16 rx 7
iface_stat() {
	grcli -j interface stats | jq ".[] | select(.interface == \"lisp0\") | .$1"
}
[ $(($(nh_stat 14 rx_packets) + $(nh_stat 16 rx_packets))) -eq "$(iface_stat rx_packets)" ] \
	|| fail "the RLOCs do not add up to the packets of the interface"
[ $(($(nh_stat 14 rx_bytes) + $(nh_stat 16 rx_bytes))) -eq "$(iface_stat rx_bytes)" ] \
	|| fail "the RLOCs do not add up to the bytes of the interface"

# Source RLOC filter. The peer has an address which is not the RLOC of a
# nexthop.
other=198.51.100.2
rm -f $tmp/ready
ip netns exec lan lisp_xtr recv --ready $tmp/ready > $tmp/recv &
recv_pid=$!
wait_ready
peer_send $rloc4 --local $other $in4 --payload any-source
grcli interface set lisp lisp0 rloc_filter on
grcli -j interface show name lisp0 | jq -e '.rloc_filter == true' || fail "filter not set"
peer_send $rloc4 --local $other $in4 --payload filtered
peer_send $rloc4 $in4 --payload known-source
# A nexthop without any route makes its RLOC a known source.
grcli nexthop add lisp iface lisp0 rloc $other id 98 stats
declared=declared-source
peer_send $rloc4 --local $other $in4 --payload $declared
grcli interface set lisp lisp0 rloc_filter off
peer_send $rloc4 $in4 --payload end
wait $recv_pid || fail "last packet not received"
cat $tmp/recv
delivered any-source
delivered known-source
delivered $declared
[ "$(wc -l < $tmp/recv)" -eq 4 ] || fail "unexpected packets were delivered"
check_counter lisp_input_unknown_rloc 1
check_nh_stats 98 rx 1 $((ip4_udp + ${#declared}))
check_nh_stats 14 rx $((12 + 2))
# The packet of the unknown source is the only one that no nexthop counted.
[ $(($(nh_stat 14 rx_packets) + $(nh_stat 16 rx_packets) + $(nh_stat 98 rx_packets) + 1)) \
	-eq "$(iface_stat rx_packets)" ] || fail "unexpected packets of unknown sources"

# Source EID filter: the source EID must be mapped to the source RLOC.
# 10.2.0.0/24 and fd00:2::/64 are mapped to the IPv4 RLOC of the peer,
# 10.3.0.0/24 to its IPv6 one.
rx14=$(nh_stat 14 rx_packets)
rx16=$(nh_stat 16 rx_packets)
rm -f $tmp/ready
ip netns exec lan lisp_xtr recv --ready $tmp/ready > $tmp/recv &
recv_pid=$!
wait_ready
grcli interface set lisp lisp0 eid_filter on
grcli -j interface show name lisp0 | jq -e '.eid_filter == true' || fail "filter not set"
peer_send $rloc4 $in4 --payload eid-v4
peer_send $rloc4 $in6 --payload eid-v6
peer_send $rloc6 --iid 101 --isrc 10.3.0.9 --idst 10.1.0.2 --payload eid-rloc6
# The other RLOC of the same xTR is not the one of the mapping.
peer_send $rloc6 $in4 --payload other-rloc-v4
peer_send $rloc4 --iid 101 --isrc 10.3.0.9 --idst 10.1.0.2 --payload other-rloc-v6
# A source without mapping, and one which is a local EID.
peer_send $rloc4 --iid 101 --isrc 10.77.0.1 --idst 10.1.0.2 --payload not-mapped
peer_send $rloc4 --iid 101 --isrc 10.1.0.99 --idst 10.1.0.2 --payload local-eid
# With both RLOCs in the mapping, the xTR can send from any of them.
grcli nexthop add group id 100 member 14 member 16
grcli route del 10.2.0.0/24 vrf site
grcli route add 10.2.0.0/24 via id 100 vrf site
peer_send $rloc6 $in4 --payload locator-set
grcli interface set lisp lisp0 eid_filter off
peer_send $rloc4 $in4 --payload end
wait $recv_pid || fail "last packet not received"
cat $tmp/recv
delivered eid-v4
delivered eid-v6
delivered eid-rloc6
delivered locator-set
[ "$(wc -l < $tmp/recv)" -eq 5 ] || fail "unexpected packets were delivered"
check_counter lisp_input_unknown_eid 4
# The accepted packets are counted on the nexthop of the mapping.
check_nh_stats 14 rx $((rx14 + 3))
check_nh_stats 16 rx $((rx16 + 2))

# A nexthop cannot become of another type: it stays the peer of its RLOC.
grcli nexthop add blackhole id 14 vrf site && fail "nexthop 14 became a blackhole"
[ "$(grcli -j nexthop show id 14 | jq -r .type)" = LISP ] || fail "nexthop 14 changed type"

# The default MTU follows the local RLOCs, unless another one was set.
lisp_mtu() {
	grcli -j interface show name "$1" | jq .mtu
}
grcli interface add lisp lisp1 iid 102 local 198.51.100.1 encap_vrf wan vrf site
[ "$(lisp_mtu lisp1)" -eq $((eth_mtu - 20 - 8 - 8)) ] || fail "unexpected MTU with an IPv4 RLOC"
grcli interface set lisp lisp1 local6 2001:db8:a::1
[ "$(lisp_mtu lisp1)" -eq $mtu ] || fail "no room for the IPv6 header in the MTU"
grcli interface set lisp lisp1 local6 ::
[ "$(lisp_mtu lisp1)" -eq $((eth_mtu - 20 - 8 - 8)) ] || fail "unexpected MTU with an IPv4 RLOC"
grcli interface set lisp lisp1 mtu 1400
grcli interface set lisp lisp1 local6 2001:db8:a::1
[ "$(lisp_mtu lisp1)" -eq 1400 ] || fail "the MTU that was set has changed"

# A local RLOC is checked when it is configured: the interface can still be
# changed once its address is gone.
grcli address del 198.51.100.1/24 iface p1
grcli interface set lisp lisp1 rloc_filter on
grcli interface set lisp lisp1 local 198.51.100.1 && fail "local RLOC without address accepted"
grcli interface del lisp1

grcli interface stats
