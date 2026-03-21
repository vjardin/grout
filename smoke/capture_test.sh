#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin, Free Mobile

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add 172.16.0.1/24 iface p0
grcli address add 172.16.1.1/24 iface p1

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
	ip -n $ns addr add 172.16.$n.2/24 dev $p
	ip -n $ns route add default via 172.16.$n.1
done

stop_capture() {
	kill "$1" 2>/dev/null || true
	wait "$1" 2>/dev/null || true
	grcli capture stop 2>/dev/null || true
	sleep 0.2
}

# per-interface capture produces valid pcapng with ICMP packets
cap=$tmp/capture-p0.pcapng
grcli capture dump iface p0 > "$cap" &
cap_pid=$!
sleep 0.5

ip netns exec n0 ping -i0.01 -c5 -n 172.16.1.2
sleep 1
stop_capture $cap_pid

[ -s "$cap" ] || fail "capture file is empty"
tcpdump -r "$cap" -n -c1 > /dev/null 2>&1 || fail "tcpdump cannot read pcapng"
tcpdump -r "$cap" -n 2>/dev/null | grep -q ICMP || fail "no ICMP packets in capture"

# all-interfaces capture sees traffic on both ports
cap_all=$tmp/capture-all.pcapng
grcli capture dump all > "$cap_all" &
cap_pid=$!
sleep 0.5

ip netns exec n0 ping -i0.01 -c3 -n 172.16.1.2
ip netns exec n1 ping -i0.01 -c3 -n 172.16.0.2
sleep 1
stop_capture $cap_pid

[ -s "$cap_all" ] || fail "all-interfaces capture file is empty"
tcpdump -r "$cap_all" -n 2>/dev/null | grep -q ICMP || fail "no ICMP in all-iface capture"

# capture list reports the active session
cap_list=$tmp/capture-list.pcapng
grcli capture dump iface p0 > "$cap_list" &
cap_pid=$!
sleep 1

grcli capture list | grep -q "iface_id=" || fail "capture list shows no active capture"

stop_capture $cap_pid

# explicit stop cleans up and allows a new capture
cap_stop=$tmp/capture-stop.pcapng
grcli capture dump iface p0 > "$cap_stop" &
cap_pid=$!
sleep 0.5

grcli capture stop
wait $cap_pid 2>/dev/null || true

grcli capture list | grep -q "iface_id=" && fail "capture still active after stop"

# a new capture can start after the previous one was stopped
cap_reuse=$tmp/capture-reuse.pcapng
grcli capture dump iface p0 > "$cap_reuse" &
cap_pid=$!
sleep 0.5

ip netns exec n0 ping -i0.01 -c2 -n 172.16.0.1
sleep 0.5
stop_capture $cap_pid

[ -s "$cap_reuse" ] || fail "restarted capture file is empty"

# only one capture at a time, second attempt must fail
cap_first=$tmp/capture-first.pcapng
cap_second=$tmp/capture-second.pcapng
grcli capture dump iface p0 > "$cap_first" &
cap_pid=$!
sleep 0.5

grcli capture dump iface p1 > "$cap_second" 2>&1 && fail "second capture should have failed"

stop_capture $cap_pid

# snaplen truncation produces valid pcapng
cap_snap=$tmp/capture-snap.pcapng
grcli capture dump iface p0 snaplen 64 > "$cap_snap" &
cap_pid=$!
sleep 0.5

ip netns exec n0 ping -i0.01 -c3 -s 500 -n 172.16.1.2
sleep 1
stop_capture $cap_pid

[ -s "$cap_snap" ] || fail "snaplen capture file is empty"
tcpdump -r "$cap_snap" -n -c1 > /dev/null 2>&1 || fail "tcpdump cannot read snaplen pcapng"

# --- native libpcap "tcpdump -i grout:p0" tests ---
# These require a libpcap built with plugin loader support (pcap-plugin.c)
# and the pcap-grout.so plugin. If either is unavailable, skip silently.
# Set GROUT_LIBPCAP_DIR to the directory containing libpcap.so with
# plugin support (e.g. /home/user/dev/libpcap/build).
# Set GROUT_PLUGIN_DIR to the directory containing pcap-grout.so
# (e.g. the grout build directory). If unset, auto-detect from builddir.

grout_plugin_src="${GROUT_PLUGIN_DIR:-${builddir:+$builddir/pcap}}"

# The plugin loader validates directory and file ownership/permissions
# (no group/world-writable, owned by root when running as root).
# Build directories fail these checks, so copy the plugin to a safe
# temporary location with correct permissions for the test.
grout_plugin_dir=""
if [ -n "$grout_plugin_src" ] && [ -f "$grout_plugin_src/pcap-grout.so" ]; then
	grout_plugin_dir="$tmp/pcap-plugins"
	mkdir -m 0755 "$grout_plugin_dir"
	cp "$grout_plugin_src/pcap-grout.so" "$grout_plugin_dir/"
	chmod 0755 "$grout_plugin_dir/pcap-grout.so"
fi

if [ -n "$GROUT_LIBPCAP_DIR" ] && [ -f "$GROUT_LIBPCAP_DIR/libpcap.so" ] &&
   [ -n "$grout_plugin_dir" ] &&
   LD_PRELOAD="$GROUT_LIBPCAP_DIR/libpcap.so" PCAP_PLUGIN_DIR="$grout_plugin_dir" \
   tcpdump --version > /dev/null 2>&1 &&
   LD_PRELOAD="$GROUT_LIBPCAP_DIR/libpcap.so" PCAP_PLUGIN_DIR="$grout_plugin_dir" \
   tcpdump -D 2>/dev/null | grep -q "grout:"; then

grout_preload="env LD_PRELOAD=$GROUT_LIBPCAP_DIR/libpcap.so PCAP_PLUGIN_DIR=$grout_plugin_dir GROUT_SOCK_PATH=$GROUT_SOCK_PATH"

# native tcpdump captures ICMP on a single interface
cap_native=$tmp/capture-native.pcapng
timeout 10 $grout_preload tcpdump -i grout:p0 -w "$cap_native" -c5 2>/dev/null &
td_pid=$!
sleep 1

ip netns exec n0 ping -i0.01 -c10 -n 172.16.1.2
wait $td_pid 2>/dev/null || true

[ -s "$cap_native" ] || fail "native tcpdump capture is empty"
tcpdump -r "$cap_native" -n 2>/dev/null | grep -q ICMP \
	|| fail "no ICMP in native tcpdump capture"

# native tcpdump -D lists grout interfaces
$grout_preload tcpdump -D 2>/dev/null | grep -q "grout:p0" \
	|| fail "grout:p0 not listed by tcpdump -D"

# native tcpdump on grout:all captures traffic
cap_native_all=$tmp/capture-native-all.pcapng
timeout 10 $grout_preload tcpdump -i grout:all -w "$cap_native_all" -c5 2>/dev/null &
td_pid=$!
sleep 1

ip netns exec n0 ping -i0.01 -c10 -n 172.16.1.2
wait $td_pid 2>/dev/null || true

[ -s "$cap_native_all" ] || fail "native tcpdump all-capture is empty"
tcpdump -r "$cap_native_all" -n 2>/dev/null | grep -q ICMP \
	|| fail "no ICMP in native all-capture"

# BPF datapath filter: verify the JIT filter runs in grout, not in libpcap.
# Send both ICMP and UDP traffic. Capture with "icmp" filter. If the
# datapath BPF JIT works, only ICMP packets enter the ring, so
# capture list pkt_count should be close to the ICMP count, not the
# total. If the filter only ran in libpcap, all packets would be in
# the ring.
cap_bpf=$tmp/capture-bpf.pcapng
timeout 10 $grout_preload tcpdump -i grout:p0 -w "$cap_bpf" 'icmp' -c5 2>/dev/null &
td_pid=$!
sleep 1

# Send ICMP (should pass filter)
ip netns exec n0 ping -i0.01 -c10 -n 172.16.1.2 &
ping_pid=$!
# Send UDP flood (should be filtered out by BPF JIT in grout)
ip netns exec n0 bash -c 'for i in $(seq 1 200); do echo x > /dev/udp/172.16.1.2/9999 2>/dev/null; done' &
udp_pid=$!
wait $ping_pid 2>/dev/null || true
wait $udp_pid 2>/dev/null || true
wait $td_pid 2>/dev/null || true

# Check grout logs confirm JIT filter was installed
grcli capture list > "$tmp/bpf_list.txt" 2>&1

[ -s "$cap_bpf" ] || fail "BPF filtered capture is empty"
tcpdump -r "$cap_bpf" -n 2>/dev/null | grep -q ICMP \
	|| fail "no ICMP in BPF filtered capture"
# No UDP should appear in the capture
tcpdump -r "$cap_bpf" -n 2>/dev/null | grep -q UDP \
	&& fail "UDP leaked through BPF filter"

# The pkt_count from capture list tells us how many packets entered
# the ring. With datapath BPF, this should be only ICMP packets
# (roughly 10-30 for 10 pings + ARP). Without datapath BPF, it
# would include the 200+ UDP packets too.
pkts=$(sed -n 's/.*pkts=\([0-9]*\).*/\1/p' "$tmp/bpf_list.txt")
if [ -n "$pkts" ] && [ "$pkts" -gt 100 ]; then
	fail "pkt_count=$pkts too high, BPF filter likely not running in datapath"
fi

stop_capture $td_pid

fi # native libpcap grout support
