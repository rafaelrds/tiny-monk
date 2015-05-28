#!/usr/bin/env python
from scapy.all import *

import sys, time
from collections import defaultdict, OrderedDict
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt

def random_color_array(N, hexa=False):
	if N > 150:
		raise "The color dictionary only have 150 colors at the moment"
	import matplotlib, numpy
	colors = matplotlib.colors.cnames.items()
	arr = []
	for i in xrange(N):
		r = numpy.random.randint(len(colors))
		choice = colors[r][0] if not hexa else colors[r][1]
		colors.pop(r)
		arr.append(choice)
	return arr


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


def plot_packet_frequency_groupingbtype():
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

	groups = group_frequency.keys()
	frequency = np.asarray(group_frequency.values())
	y_pos = np.arange(len(groups))
	plt.barh(y_pos, frequency, align='center', alpha=0.4)
	plt.yticks(y_pos, groups)
	plt.xlabel('DNS Lookups')
	plt.title('How many DNS lookups common websites usually have?')
	plt.xlim((0,200))
	plt.show()

def plot_in_out_grouping():
	group_in_out = defaultdict(int)
	for website in website_to_packets:
		if website in institutional_websites:
			key = website
		else:
			continue
		
		for packets in website_to_packets[website]:
			for pkt in packets:
				if DNSRR in pkt: # response
					group_in_out[key+"_"+'in'] += 1
				else: # query 
					group_in_out[key+"_"+'out'] += 1

	print group_in_out

	groups, frequency = [], []
	for k in sorted(group_in_out):
		groups.append(k)
		frequency.append(group_in_out[k])

	# groups = group_in_out.keys()
	frequency = np.asarray(frequency)
	y_pos = np.arange(len(groups))
	colors = np.random.rand(len(groups))
	plt.barh(y_pos, frequency, align='center', alpha=0.4, height=0.3)
	plt.yticks(y_pos, groups)
	plt.xlabel('DNS Lookups')
	plt.title('How many DNS packets went IN/OUT?\nAt Institutional websites')
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



frequency_cctld = defaultdict(int)

acc = set(['com','edu','nl','net','local','org','br'])
for website in website_to_packets:
	for packets in website_to_packets[website]:
		for pkt in packets:
			if DNSRR not in pkt: #only answers
				key = pkt[DNS].qd.qname.split('.')[-2]
				if key in acc:
					frequency_cctld[key] +=  1
				else:
					frequency_cctld['others'] += 1

for i in frequency_cctld.items():
	print i

groups = frequency_cctld.keys()
frequency = np.asarray(frequency_cctld.values())
x_pos = np.arange(len(groups))
colors = np.random.rand(len(groups))
plt.bar(x_pos, frequency, align='center', alpha=0.4 ,color=colors)
plt.xticks(x_pos, groups)
plt.xlabel('DNS Lookups')
plt.title('What were the most frequent ccTLDs?\nOverview')
plt.show()








