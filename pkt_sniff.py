#!/usr/bin/env python
from scapy.all import *
from datetime import datetime


interface = 'en0'
filter_bpf = 'udp and port 53'
# ------ SELECT/FILTER MSGS
def select_DNS(pkt):
    pkt_time = pkt.sprintf('%sent.time%')
# ------ SELECT/FILTER DNS MSGS
    try:
        if DNSQR in pkt and pkt.dport == 53:
        # queries
           query = pkt[DNSQR].qname
           type =  pkt[DNSQR].sprintf('%qtype%')
           print '[**] Detected DNS Message at: ' + pkt_time, query

    except:
    	print "An exception was throwed!"
        pass
# ------ START SNIFFER 
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS)