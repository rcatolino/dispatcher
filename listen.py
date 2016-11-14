#!/usr/bin/python3

import random
from scapy.all import IP, TCP, hexdump
import signal
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

def sigint_handler(signal, frame):
    giveup("Received sigint")

def giveup(msg):
    print("{}".format(msg))
    print("Stop dropping RST")
    iptables_rst_rst()
    print("Cleaning up containers")
    for (client_addr, (container_id, container_addr, dst_addr)) in mappings.items():
        iptables_route('-D', client_addr, container_addr, dst_addr)
        docker_stop(container_id)
    exit(1)

def docker_start():
    run_process = run(['/usr/bin/docker', 'run', '-d', 'ghchal1client'], stdout=PIPE)
    container_id = run_process.stdout.decode('utf8').strip('\n')
    print("Created new container {}".format(container_id))
    inspect_process = run(['/usr/bin/docker',
        'inspect',
        '--format=\'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}\'',
        container_id], stdout=PIPE)
    ip = inspect_process.stdout.decode('utf8').strip('\n')
    print("New container address : {}".format(ip))
    return container_id, ip

def docker_stop(container):
    run(['/usr/bin/docker', 'stop', container])
    run(['/usr/bin/docker', 'rm', container])

def iptables_route(action, client_addr, container_addr, own_addr):
    run(['/usr/bin/iptables', '-t', 'nat', action, 'PREROUTING',
        '-s', client_addr, '-d', own_addr,
        '-p', 'tcp', '!', '--syn', '--dport', '8255',
        '-j', 'DNAT', '--to-destination', container_addr+':2222'])

def remove_mapping(client):
    print("Removing mapping for client {}".format(client))
    container_id, container_addr, dst_addr  = mappings[client]
    iptables_route('-D', client, container_addr, dst_addr)
    docker_stop(container_id)
    del mappings[client]

def add_mapping(p):
    print("Adding dynamic mapping for client {}".format(p.src))
    if p.src in mappings:
        #remove_mapping(p.src)
        print("Ignoring SYN because of preexisting mapping")
        return
    container_id, container_addr = docker_start()
    iptables_route('-A', p.src, container_addr, p.dst)
    mappings[p.src] = (container_id, container_addr, p.dst)
    print(mappings)

def filter_packet(p):
    return p.dport == lport and (lhost == '' or p.dst == lhost)

def iptables_stop_rst():
    run(['iptables', '-t', 'filter', '-A', 'OUTPUT', '-p', 'tcp',
        '--tcp-flags', 'ALL', 'RST,ACK',
        '--sport', str(lport), '-j', 'DROP'])

def iptables_rst_rst():
    run(['iptables', '-t', 'filter', '-D', 'OUTPUT',
        '-p', 'tcp', '--tcp-flags', 'ALL', 'RST,ACK',
        '--sport', str(lport), '-j', 'DROP'])

signal.signal(signal.SIGINT, sigint_handler)
iptables_stop_rst()

while True:
    packets = IP(s.recv(max_syn_size))
    for p in packets:
        if filter_packet(p) and (p[TCP].flags == SYN):
            p.show()
            add_mapping(p)

