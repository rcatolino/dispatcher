#!/usr/bin/python3

from scapy.all import IP, TCP, hexdump
import socket
import sys

lport = 8255
lhost = '127.0.0.1'
max_syn_size = 128

"""
def print_hex(data):
    for b in data:
        sys.stdout.write("{:02x}".format(b))
    sys.stdout.write("\n")
"""

s = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_TCP)
s.bind((lhost, 0))

while True:
    packet = IP(s.recv(max_syn_size))
    for p in packet:
        if p.dport == lport:
            packet.show()
