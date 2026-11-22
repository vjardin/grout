# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin
#
# name: LISP xTR, IPv4 RLOCs
#
#   direction 0 (TRex port 0 -> grout p0): LISP packet, decapsulated and sent
#     plain out p1;
#   direction 1 (TRex port 1 -> grout p1): plain packet, encapsulated out p0.
#
# The plain frames are 64 bytes on the wire, the LISP ones carry 36 more bytes.
# The swept source UDP port is the outer one in direction 0 (its checksum is
# zero, there is nothing to fix) and the customer one in direction 1.

import struct

from trex_stl_lib.api import *

GROUT_P0_MAC = "02:00:00:00:00:00"
GROUT_P1_MAC = "02:00:00:00:00:01"
TREX_P0_MAC = "02:00:00:00:01:00"
TREX_P1_MAC = "02:00:00:00:01:01"

LOCAL_RLOC = "172.16.0.1"
REMOTE_RLOC = "172.16.0.2"
LISP_DATA_PORT = 4341
IID = 100

# Hosts of the remote EID prefix and of the local one.
REMOTE_EID = "16.0.0.1"
LOCAL_EID = "48.0.0.1"

FRAME_SIZE = 60
ETHER_SIZE = 14


def sport_vm():
    vm = STLVM()
    vm.var(name="sport", min_value=1024, max_value=65535, size=2, op="inc")
    vm.write(fv_name="sport", pkt_offset="UDP:0.sport")
    return vm


def lisp_header(iid):
    # flags (I), nonce, instance ID, locator status bits
    return Raw(struct.pack("!B3xI", 0x08, iid << 8))


def routed_packet(src_ip, dst_ip):
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=1024, dport=1024, chksum=0)
    pkt /= max(0, FRAME_SIZE - ETHER_SIZE - len(pkt)) * b"x"
    return pkt


class Profile:
    def get_streams(self, direction=0, tunables=(), **kwargs):
        if direction == 0:
            pkt = Ether(src=TREX_P0_MAC, dst=GROUT_P0_MAC)
            pkt /= IP(src=REMOTE_RLOC, dst=LOCAL_RLOC)
            pkt /= UDP(sport=1024, dport=LISP_DATA_PORT, chksum=0)
            pkt /= lisp_header(IID)
            pkt /= routed_packet(REMOTE_EID, LOCAL_EID)
        else:
            pkt = Ether(src=TREX_P1_MAC, dst=GROUT_P1_MAC)
            pkt /= routed_packet(LOCAL_EID, REMOTE_EID)

        return [
            STLStream(packet=STLPktBuilder(pkt=pkt, vm=sport_vm()), mode=STLTXCont())
        ]


def register():
    return Profile()
