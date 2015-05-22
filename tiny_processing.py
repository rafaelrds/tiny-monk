#!/usr/bin/env python
from scapy.all import *

import sys
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
def file_name_to_website(file_name):
	return pattern.findall(file_name)[0]


files = get_experiment_files()
websites = set()

packets = []
n = 0
for f in files:
	print "File name:%s \nWebsite:%s\n" % (f, file_name_to_website(f))

