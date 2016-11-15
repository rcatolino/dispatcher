#!/usr/bin/python3

import random
from scapy.all import IP, TCP, hexdump, send
import signal
import socket
from subprocess import run, PIPE, DEVNULL
import sys
import time

# Configuration:
lport = 8255 # Local port
dport = 2222 # Container port
lhost = ''   # Local address to listen on

max_syn_size = 160
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

mappings = {}

def sigint_handler(signal, frame):
    giveup("Received sigint")

def giveup(msg):
    print("{}".format(msg))
    print("Stop dropping RST")
    iptables_rst('-D', 'OUTPUT', str(lport))
    print("Cleaning up containers")
    for (client_addr, (container_id, container_addr, dst_addr)) in mappings.items():
        docker_stop(container_id)
    iptables_del_chain()
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
    run(['/usr/bin/iptables', '-t', 'nat', action, 'DISPATCHER', '1',
        '-s', client_addr, '-d', own_addr,
        '-p', 'tcp', '--dport', '8255',
        #'!', '--syn', # We have to let syn go through or the dnat target won't work
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
    # Give some time for the container to get up
    time.sleep(1)
    iptables_route('-I', p.src, container_addr, p.dst)
    mappings[p.src] = (container_id, container_addr, p.dst)
    print(mappings)

def filter_packet(p):
    return p.dport == lport and (lhost == '' or p.dst == lhost)

def iptables_rst(action, chain, src_port, dst=None):
    command = ['iptables', '-t', 'filter', action, chain, '-p', 'tcp',
        '--tcp-flags', 'ALL', 'RST,ACK']
    if dst:
        command.extend(['-d', dst])
    command.extend(['--sport', src_port, '-j', 'DROP'])
    run(command)

def iptables_add_chain():
    run(['iptables', '-t', 'nat', '-N', 'DISPATCHER'])
    run(['iptables', '-t', 'nat', '-A', 'DISPATCHER', '-j', 'RETURN'])
    run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp',
        '-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'DISPATCHER'])

def iptables_del_chain():
    run(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp',
        '-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'DISPATCHER'], stderr=DEVNULL)
    run(['iptables', '-t', 'nat', '-F', 'DISPATCHER'], stderr=DEVNULL)
    run(['iptables', '-t', 'nat', '-X', 'DISPATCHER'], stderr=DEVNULL)

s = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_TCP)
s.bind((lhost, 0))

signal.signal(signal.SIGINT, sigint_handler)
iptables_del_chain()
iptables_add_chain()
iptables_rst('-A', 'OUTPUT', str(lport))

while True:
    packets = IP(s.recv(max_syn_size))
    for p in packets:
        if filter_packet(p) and (p[TCP].flags == SYN):
            p.show()
            add_mapping(p)
            new_dst = mappings[p.src][1]

