#!/usr/bin/python3

from scapy.all import *
import os

def verify_checksum(packet, layer):
    old_checksum = packet[layer].chksum
    packet = packet.__class__(bytes(packet))
    new_checksum = packet[layer].chksum

    if old_checksum == new_checksum:
        print(f"checksum is correct for layer: {layer}")
    else:
        print(f"checksum is incorrect for layer: {layer}")
        exit(1)

def main(args):
    raw_bytes = list(map(lambda x: int(x.strip()), args[0].split(',')))
    packet = IP(bytes(raw_bytes))
    # del packet[UDP].chksum
    # del packet[IP].chksum
    # packet.show2()
    packet.show()

    wrpcap('/tmp/aero_netstack.pcap', pkt=packet)

if __name__ == '__main__':
    main(os.sys.argv[1:])
