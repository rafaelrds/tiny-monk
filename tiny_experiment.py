#!/usr/bin/env python
from scapy.all import *
import datetime, sys, time

interface = 'en0'
filter_bpf = 'port 53 and udp'
experiment_number = 0

#Define which plataform is begin used
import psutil, platform
plat = platform.platform().lower()
if 'darwin' in plat:
	plat = 'mac'
	print 'MAC OS detected'
elif 'linux' in plat:
    plat = 'linux'
    print 'LINUX OS detected'

def clear_dnsrecords():
  if 'mac' == plat: #For Mac OS
    proc_name = 'mDNSResponder'
  elif 'linux' == plat:
    proc_name = 'dnsmasq'
  else:
    sys.exit("\nDNS CLEANING ON THAT PLATAFORM IS NOT YET IMPLEMENTED!\n")
  for proc in psutil.process_iter():
    if proc_name == proc.name():
      proc.kill()

def open_firefox(url):
  import webbrowser
  webbrowser.get('firefox').open(url)

def close_firefox():
  import psutil
  for proc in psutil.process_iter():
    if 'firefox' == proc.name():
      proc.kill()
  return True 

def pcap_filename(url):
	from time import strftime, gmtime
	current_gmt_time = strftime("%d_%b_%Y_%H_%M_%S", gmtime())
	curated_url = url.split('/')[2]
	if curated_url[:3] == 'www':
		curated_url = curated_url[4:]
	file_name = "pcap/%s.pcap" % (curated_url + "_" + current_gmt_time)
	return file_name

# http://bb.secdev.org/scapy/issue/913/dns-responses-are-malformed-after
# Due to this issue, the following actions need to be performed before saving a packet in pcap
def clear_to_store(packets):
	for p in packets:
		del(p[IP].len)
		del(p[UDP].len)
		del(p[UDP].chksum)

def save_packets(name, packets):
	file_name = pcap_filename(name)
	clear_to_store(packets)
	try:
		wrpcap(file_name, packets)
		return True
	except:
		sys.exit('Failed to save pcap file %s' % (file_name))

packet_count = 0
def dns_monitor_callback(pkt):
	global packet_count
	packet_count += 1
	if packet_count % 5 == 0:
		print packet_count,
		sys.stdout.flush()

def reset_global_vars():
	global packet_count
	packet_count = 0

def do_experiment(website):
  global experiment_number
  experiment_timeout = 45
  experiment_number += 1
  open_firefox(url=website)

  print "Cleaning DNS records"
  clear_dnsrecords()
  print "Starting sniffing. This experiment will take %d seconds" % (experiment_timeout)
  packets = sniff(iface=interface, filter=filter_bpf, store=1, prn=dns_monitor_callback, timeout=experiment_timeout)
  
  print "Saving pcap"
  save_packets(website, packets)
  print "Saved with success:", pcap_filename(website)

  print "Closing browser"
  close_firefox()
  print "Experiment #%d finished" % (experiment_number)

  reset_global_vars()
  time.sleep(3) # wait for firefox to be finished

# Be aware to use sys arguments!
def main():
	with open(sys.argv[1], 'r') as my_file:
		for line in my_file.readlines():
	  		url = line.strip()
	  		do_experiment(url)

	print "Everything is finished"

if __name__ == "__main__":
	main()
