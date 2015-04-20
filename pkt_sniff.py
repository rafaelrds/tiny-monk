#!/usr/bin/env python
from scapy.all import *
import datetime

def extract_records():
  pass

class DNS_pair_stamped(object):
  def __init__(self, time_q, pkt_q, time_r, pkt_r):
    self.time_q = time_q
    self.pkt_q = pkt_q
    self.time_r = time_r
    self.pkt_r = pkt_r

  def diff_time_in_miliseconds(self):
    t1 = datetime.datetime.strptime(self.time_q, '%H:%M:%S.%f').time()
    t2 = datetime.datetime.strptime(self.time_r, '%H:%M:%S.%f').time()
    h1, m1, s1, mm1 = t1.hour, t1.minute, t1.second, t1.microsecond
    h2, m2, s2, mm2 = t2.hour, t2.minute, t2.second, t2.microsecond
    t1_secs = s1 + 60 * (m1 + 60*h1)
    t2_secs = s2 + 60 * (m2 + 60*h2)
    t1_msecs = (t1_secs * int(1e6)) + mm1
    t2_msecs = (t2_secs * int(1e6)) + mm2
    delta = t2_msecs - t1_msecs
    return (delta)/1000.0 if delta > 0 else (24*60*60*int(1e6) + delta)/1000.0


  def __repr__(self):
    print 35*"*"
    print "Transaction ID:", self.pkt_q[DNS].id
    print "Query:", self.time_q, self.pkt_q[DNS].qd.qname
    print "Response:", self.time_r
    print "Response time", self.diff_time_in_miliseconds(),"ms"
    print 35*"*"
    return ""


interface = 'en0'
filter_bpf = 'udp and port 53'

packetCount = 0
DNS_DICT = {}
DNS_PAIRS = []

# ------ SELECT/FILTER MSGS
def select_DNS(pkt):
  global DNS_DICT, packetCount
  pkt_time = pkt.sprintf('%.time%')
  packetCount += 1

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

  except:
    print "An exception was throwed!"
  
# ------ START SNIFFER 
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS, timeout=10)

# ------ ANALYSIS
total_time = 0
for p in DNS_PAIRS:
  print p
  total_time += p.diff_time_in_miliseconds()


print "Total of %d packets" % (packetCount)
print "Sum of QR time %fms" % (total_time)
print "Average of response time %fms" % (total_time/(packetCount/2.0))
 

