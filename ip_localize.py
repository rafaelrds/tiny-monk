'''
Convert String IP to Integer according the below formula:
(first octet * 256^3) + (second octet * 256^2) + (third octet * 256) + (fourth octet)
'''
import struct,socket
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

'''
Convert Integer IP to String IP reversing the formula of ip2int method.
'''
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

'''
Gets external IP by using a external IP service.
'''
def get_external_ip(site="http://www.checkip.com"):
	# src: http://stackoverflow.com/questions/2311510/getting-a-machines-external-ip-address
	import urllib, re
	content = urllib.urlopen(site).read()
	grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', content)
	address = grab[0]
	return address

'''
Retrieves line in the GeoLiteCity-Blocks.csv according to index
'''
def get_GeoLiteBlockLine(index, my_file = 'GeoLite/GeoLiteCity-Blocks.csv'):
	import linecache
	HEADER_SIZE = 1
	file_line = linecache.getline(my_file, index + HEADER_SIZE).split(",")
	return map(lambda x : int(x.strip()[1:-1]), file_line) if len(file_line) > 1 else None

'''
Binary Searches what is the ID of the parameter IP Address (Integer)
consulting the GeoLiteCity-Blocks.csv file.
!!!File index is still hardcoded between 1 and 2019668, inclusive!!!
'''
def get_GeoLiteBlockId(item):
	first = 1
	last = 2019668 ### counted using wc -> should change
	found = False

	while first<=last and not found:
		midpoint = (first + last)//2
		mid_el = get_GeoLiteBlockLine(midpoint)

		if mid_el[0] <= item and item <= mid_el[1]:
			return mid_el
			found = True
		else:
			if item < mid_el[0]:
				last = midpoint-1
			else:
				first = midpoint+1
	return -1

''' 
Retrieves the location of an IP Address (String) in an array format.
[locId, country, region, city, postalCode, latitude, longitude, metroCode, areaCode]
'''
def get_GeoLiteLocation(ip_addr):
	import linecache
	HEADER_SIZE = 1
	id_location = get_GeoLiteBlockId(ip2int(ip_addr))[2]
	return linecache.getline('GeoLite/GeoLiteCity-Location.csv', id_location + HEADER_SIZE).strip().split(",")

'''
Retrieves line in the GeoIPASNum2.csv according to index
'''
def get_LineIPAS(index, my_file = 'GeoLite/GeoIPASNum2.csv'):
	import linecache
	HEADER_SIZE = 0
	file_line = linecache.getline(my_file, index + HEADER_SIZE).split(",")
	return map(int, file_line[0:2]) + [file_line[2].strip()[1:-1]] if len(file_line) > 1 else None

'''
Binary Searches what is the Autonomous System(AS) of the given IP Address (String)
consulting the GeoIPASNum2.csv file.
!!!File index is still hardcoded between 1 and 224846, inclusive!!!
'''
def get_IPAS(ip_addr):
	item = ip2int(ip_addr)
	first = 1
	last = 224846 ### counted using wc -> should change
	found = False

	while first<=last and not found:
		midpoint = (first + last)//2
		mid_el = get_LineIPAS(midpoint)

		if mid_el[0] <= item and item <= mid_el[1]:
			return mid_el[2]
			found = True
		else:
			if item < mid_el[0]:
				last = midpoint-1
			else:
				first = midpoint+1
	return -1

'''
Returns correspondent Host Name
by using host UNIX service.
'''
def host(ip="8.8.8.8"):
	from subprocess import Popen, PIPE
	p = Popen(['host', ip], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	output, err = p.communicate(b"input data that is passed to subprocess' stdin")
	return output.rstrip().split()[-1]

''''
Uses dig service by Internet Systems Consortium (ISC) returns information about every hop
during the DNS resolving process.
Return array:
[bytes received, time elapsed, ip, NS, AS, [location_array], ... ] 
[location_array] = [locId, country, region, city, postalCode, latitude, longitude, metroCode, areaCode]
'''
def dig(site="www.example.com"):
	from subprocess import Popen, PIPE
	p = Popen(['dig', '+trace', site], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	output, err = p.communicate(b"input data that is passed to subprocess' stdin")
	b = output.strip().split('\n')
	traces = []
	for i in range(len(b)):
		line = b[i].split()
		if len(line) > 0 and (line[1] == 'Received'):
			s = line[5]
			ip_address = s[s.find('(')+1 : s.find(')')]
			n_bytes = line[2]
			response_time = line[7]
			traces.append( [n_bytes, response_time, ip_address, host(ip_address), get_IPAS(ip_address), get_GeoLiteLocation(ip_address)] )
	return traces


#Method testing/execution area:

# dig(site="www.facebook.com")
# my_ips = parse_dig(output)
# for ip in my_ips:	
# 	print ip, get_GeoLiteLocation(ip)
# print "130.89.93.44", get_GeoLiteLocation("130.89.93.44")

my_external_ip = get_external_ip()
print my_external_ip
# print my_external_ip
# print dig(site="www.google.uk")
# print get_GeoLiteLocation(my_external_ip), get_IPAS(my_external_ip)
site = "vitrines-inteligentes-1251445001.us-east-1.elb.amazonaws.com."
traces = dig(site=site)
for t in traces:
	print t
# my_ips = ["54.76.117.96", "54.76.116.11", "200.215.195.1"]
# for ip in my_ips:
# 	print get_GeoLiteLocation(ip)