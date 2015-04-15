#!/usr/bin/env python
from scapy.all import *
from datetime import datetime

# TODO
class DNS_pair_stamped(object):
  def __init__(self, time_q, pkt_q, time_a, pkt_a):
    self.time_q = time_q
    self.pkt_q = pkt_q
    self.time_a = time_a
    self.pkt_a = pkt_a


  def description(self):
    print "DNS Id =", self.pkt_q[DNS].id
    print "Query time", self.time_q
    print "Answer time", self.time_a 


interface = 'en0'
filter_bpf = 'udp and port 53'

packetCount = 0
DNS_DICT = {}
DNS_PAIRS = []

# ------ SELECT/FILTER MSGS
def select_DNS(pkt):
  global DNS_DICT, packetCount
  pkt_time = pkt.sprintf('%.time%')
# ------ SELECT/FILTER DNS MSGS
  try:
    if DNSQR in pkt and pkt.dport == 53:
      # queries
      dns_id = pkt[DNS].id
      query = pkt[DNSQR].qname
      type =  pkt[DNSQR].sprintf('%qtype%')

      DNS_DICT[dns_id] = (pkt_time, pkt)

    elif DNSRR in pkt and pkt.sport == 53:
      # responses
      dns_id = pkt[DNS].id
      srv_ip = pkt[IP].src
      response = pkt[DNSRR].rdata

      previous_pkt_time = DNS_DICT[dns_id][0]
      previous_pkt = DNS_DICT[dns_id][1]
      dns_pair_stamped = DNS_pair_stamped(previous_pkt_time, previous_pkt, pkt_time, pkt)

      del(DNS_DICT[dns_id])
      DNS_PAIRS.append(dns_pair_stamped)

    packetCount += 1
  except:
    print "An exception was throwed!"
  
# ------ START SNIFFER 
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS, count=10)
for p in DNS_PAIRS:
  p.description()


