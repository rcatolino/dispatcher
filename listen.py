#!/usr/bin/python3

import random
from scapy.all import IP, TCP, hexdump
import socket
from subprocess import run
import sys

lport = 8255
lhost = ''
max_syn_size = 128

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

s = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_TCP)
s.bind((lhost, 0))

mappings = {}

def giveup(msg):
    print("{}".format(msg))
    exit(1)

def docker_start():
    run(['/usr/bin/docker', 'run', '--rm', 'ghchal1client', '/usr/sbin/sshd/'])

def iptables_route(p.src):
    run(['/usr/bin/iptables', ''])

def remove_mapping(client):
    print("Removing mapping for client {}".format(client))
    del mapping[client]

def add_mapping(p):
    print("Adding dynamic mapping from client {}".format(p.src))
    if mapping[p.src]:
        remove_mapping(p.src)
    container_id, container_addr = docker_start()
    iptables_route(p.src, container_addr)
    mapping[p.src] = (container_addr, container_id)

def filter_packet(p):
    return p.dport == lport and (lhost == '' or p.dst == lhost)

while True:
    packets = IP(s.recv(max_syn_size))
    for p in packets:
        if filter_packet(p) and (p[TCP].flags == SYN):
            p.show()
            add_mapping(p)

