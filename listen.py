#!/usr/bin/python3

import random
from scapy.all import IP, TCP, hexdump
import socket
from subprocess import run, PIPE
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
    run_process = run(['/usr/bin/docker', 'run', '-d', 'ghchal1client'], stdout=PIPE)
    container_id = run_process.stdout.decode('utf8').strip('\n')
    print("Created new container {}".format(container_id))
    inspect_process = run(['/usr/bin/docker',
        'inspect',
        '--format=\'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}\'',
        container_id], stdout=PIPE)
    ip = inspect_process.stdout.decode('utf8')
    print("New container address : {}".format(ip)).strip('\n')
    return container_id, ip

def docker_stop(container):
    run(['/usr/bin/docker', 'stop', container])
    run(['/usr/bin/docker', 'rm', container])

def iptables_route(client_addr, container_addr):
    run(['/usr/bin/iptables', ''])

def remove_mapping(client):
    print("Removing mapping for client {}".format(client))
    container = mappings[client][0]
    docker_stop(container)
    del mappings[client]

def add_mapping(p):
    print("Adding dynamic mapping for client {}".format(p.src))
    if p.src in mappings:
        remove_mapping(p.src)
    container_id, container_addr = docker_start()
    #iptables_route(p.src, container_addr)
    mappings[p.src] = (container_id, container_addr)
    print(mappings)

def filter_packet(p):
    return p.dport == lport and (lhost == '' or p.dst == lhost)

while True:
    packets = IP(s.recv(max_syn_size))
    for p in packets:
        if filter_packet(p) and (p[TCP].flags == SYN):
            p.show()
            add_mapping(p)

