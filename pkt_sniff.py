#!/usr/bin/env python
from scapy.all import *
import datetime, sys

def diff_time_in_miliseconds(t1, t2):
  DAY_MSECS = 24*60*60*int(1e6)
  t1 = datetime.datetime.strptime(t1, '%H:%M:%S.%f').time()
  t2 = datetime.datetime.strptime(t2, '%H:%M:%S.%f').time()
  h1, m1, s1, mm1 = t1.hour, t1.minute, t1.second, t1.microsecond
  h2, m2, s2, mm2 = t2.hour, t2.minute, t2.second, t2.microsecond
  t1_secs = s1 + 60 * (m1 + 60*h1)
  t2_secs = s2 + 60 * (m2 + 60*h2)
  t1_msecs = (t1_secs * int(1e6)) + mm1
  t2_msecs = (t2_secs * int(1e6)) + mm2
  delta = t2_msecs - t1_msecs
  return (delta)/1000.0 if delta > 0 else (DAY_MSECS + delta)/1000.0

def max_response_time(list_of_dnspairs):
  max_rtime = 0.0
  for pair in list_of_dnspairs:
    max_rtime = max(max_rtime, diff_time_in_miliseconds(pair.time_q, pair.time_r))
  return max_rtime

def min_response_time(list_of_dnspairs):
  min_rtime = 1e6
  for pair in list_of_dnspairs:
    min_rtime = min(min_rtime, diff_time_in_miliseconds(pair.time_q, pair.time_r))
  return min_rtime

def calculate_total_dnsload(list_of_dnspairs):
  first_pair = list_of_dnspairs[0]
  last_pair = list_of_dnspairs[-1]
  return diff_time_in_miliseconds(first_pair.time_q, last_pair.time_r)

def clear_dnsrecords():
  import psutil, platform
  plat = platform.platform().lower()
  if 'darwin' in plat:
    for proc in psutil.process_iter():
      if 'mDNSResponder' == proc.name():
        proc.kill()
  
  elif 'linux' in plat:
    sys.exit("\nLINUX DNS CLEANING IS NOT YET IMPLEMENTED\n")
  
def open_firefox(url=""):
  import webbrowser
  webbrowser.get('firefox').open(url)

def close_firefox():
  import psutil
  for proc in psutil.process_iter():
    if 'firefox' == proc.name():
      proc.kill()
  return True 

class DNS_pair_stamped(object):
  def __init__(self, time_q, pkt_q, time_r, pkt_r):
    self.time_q = time_q
    self.pkt_q = pkt_q
    self.time_r = time_r
    self.pkt_r = pkt_r

  def __repr__(self):
    print 50*"*"
    print "Transaction ID:", self.pkt_q[DNS].id
    print "Query time:", self.time_q
    print "Query name:", self.pkt_q[DNS].qd.qname
    print "Response:", self.time_r
    print "Response time", diff_time_in_miliseconds(self.time_q, self.time_r),"ms"
    print 50*"*"
    return ""


# ------ GLOBAL VARIABLES ------
interface = 'en0'
filter_bpf = 'udp and port 53'

packetCount = 0
DNS_DICT = {}
DNS_PAIRS = []
safe_packets = []


# ------ SELECT/FILTER MSGS ------
def select_DNS(pkt):
  global DNS_DICT, packetCount, safe_packets

  safe_packets.append(pkt)
  pkt_time = pkt.sprintf('%.time%')
  packetCount += 1
  if packetCount % 5 == 0:
    print packetCount, 
  sys.stdout.flush()

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
      response = pkt[DNSRR].rdata

      previous_pkt_time = DNS_DICT[dns_id][0]
      previous_pkt = DNS_DICT[dns_id][1]
      dns_pair_stamped = DNS_pair_stamped(previous_pkt_time, previous_pkt, pkt_time, pkt)

      del(DNS_DICT[dns_id])
      DNS_PAIRS.append(dns_pair_stamped)

  except:
    print "An exception was throwed!"
    sys.exit("\nAn exception was throwed! FIX IT UP BEFORE IT DESTROY EVERYTHING\n")

def total_time_packets():
  '''Calculate total time according to the 
     global dictionary DNS_PAIRS'''
  global DNS_PAIRS
  total_time = 0
  for p in DNS_PAIRS:
    # print p
    total_time += diff_time_in_miliseconds(p.time_q, p.time_r)
  return total_time

def print_experiment_summary():
  '''Print a small summary according to the global
     variables'''
  global packetCount, DNS_PAIRS, DNS_DICT, safe_packets
  total_time = total_time_packets()
  print "\nTotal of %d packets" % (packetCount)
  print "Total of %d pairs" % (len(DNS_PAIRS))
  print "Maximum response time %.3f ms" % (max_response_time(DNS_PAIRS))
  print "Minimum response time %.3f ms" % (min_response_time(DNS_PAIRS))
  print "Time between first Q and last R %.3f ms" % (calculate_total_dnsload(DNS_PAIRS))
  print "Sum of QR time %.3f ms" % (total_time)
  print "Average of response time %.6f ms" % (total_time/(packetCount/2.0))
  print "Orfan queries: %d" % (len(DNS_DICT.keys()))
  if (len(safe_packets) == packetCount):
    print "All the packets can be saved"


def save_packets(name):
  from time import strftime, gmtime
  current_gmt_time = strftime("%d_%b_%Y_%H_%M_%S", gmtime())
  curated_url = url[url.find('.')+1:]
  file_name = "pcap/%s.pcap" % (curated_url + "_" + current_gmt_time)
  wrpcap(file_name, safe_packets)
  
def print_global_vars(count=True, dict_dns=True, pairs=False, s_packets=False):
  print "GLOBAL VARIABLES"
  if count:
    print "packetCount:",packetCount
  if dict_dns:
    print "DNS_DICT:", DNS_DICT
  if pairs:
    print "DNS_PAIRS:", DNS_PAIRS
  if s_packets:
    print "safe_packets:", safe_packets

def reset_global_vars():
  global packetCount
  global DNS_DICT, DNS_PAIRS, safe_packets
  packetCount = 0
  DNS_DICT = {}
  DNS_PAIRS = []
  safe_packets = []


def do_experiment(url):
  # ------ BROWSER + SNIFFING ------
  open_firefox(url=url)

  print "Cleaning DNS records"
  clear_dnsrecords()

  sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS, timeout=45)

  # ------ ANALYSIS ------
  print_experiment_summary()

  print "Saving pcap"
  save_packets(name=url)
  print "Saved with success"

  print "Closing browser"
  close_firefox()
  print "Experiment finished"

  reset_global_vars()

url_list = ['http://www.nytimes.com']
do_experiment(url=url)
print_global_vars()