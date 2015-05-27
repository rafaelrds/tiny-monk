#!/usr/bin/env python
from scapy.all import *

import sys, time
from collections import defaultdict, OrderedDict
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt

def get_experiment_files():
	import os
	files = []
	for dirname, dirnames, filenames in os.walk('pcap'):
	    # print path to all filenames.
	    for filename in filenames:
	        files.append((os.path.join(dirname, filename)))
	return files

import re
pattern = re.compile(r'\/([a-z.]+)')
def filename_to_website(file_name):
	return pattern.findall(file_name)[0]

def get_type_list(type_website):
	websites = []
	with open('urls/'+type_website, 'r') as my_file:
		for line in my_file.readlines():
			website = '.'.join(filename_to_website(line.strip()).split(".")[1:])
			websites.append(website)
	return websites

#There shall be used for grouping
social_websites = get_type_list('social_list.txt')
news_websites = get_type_list('news_list.txt')
institutional_websites = get_type_list('institutional_list.txt')


def plot_packet_frequency_per_website():
	### Count packet frequency per website
	pkt_frequency = defaultdict(int)
	for website in website_to_packets:
		website_packets = website_to_packets[website]
		pkt_frequency[website] = (sum(len(pkt) for pkt in website_packets)/ float(len(website_packets)))

	websites = pkt_frequency.keys()
	frequency = np.asarray(pkt_frequency.values())
	y_pos = np.arange(len(websites))
	plt.barh(y_pos, frequency, align='center')
	plt.yticks(y_pos, websites)
	plt.xlabel('DNS Lookups')
	plt.title('How many DNS lookups common websites usually have?')
	plt.show()


files = get_experiment_files()

d = defaultdict(list)
for f in files:
	key = filename_to_website(f)
	d[key].append(f)

website_to_packets = defaultdict(list)
for i, website in enumerate(d):
	for f in d[website]:
		packets = rdpcap(f)
		website_to_packets[website].append(packets)
	print (i+1),
	sys.stdout.flush(); 
print "Everything is Loaded"


del(website_to_packets['nu.nl'])

group_frequency = defaultdict(list)
for website in website_to_packets:
	for pkt in website_to_packets[website]:
		if website in social_websites:
			group_frequency['social'].append(len(pkt))
		elif website in news_websites:
			group_frequency['news'].append(len(pkt))
		elif website in institutional_websites:
			group_frequency['institutional'].append(len(pkt))


for k in group_frequency:
	pkt_size_arr = group_frequency[k]
	group_frequency[k] = sum(pkt_size_arr) / float(len(pkt_size_arr))

print group_frequency

groups = group_frequency.keys()
frequency = np.asarray(group_frequency.values())
y_pos = np.arange(len(groups))
plt.barh(y_pos, frequency, align='center', alpha=0.4)
plt.yticks(y_pos, groups)
plt.xlabel('DNS Lookups')
plt.title('How many DNS lookups common websites usually have?')
plt.xlim((0,200))
plt.show()





