import struct,socket
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def parse_dig(text):
	return [c[1] for c in [b.split('(') for b in text.split(')')] if len(c) > 1]

# http://stackoverflow.com/questions/2311510/getting-a-machines-external-ip-address
def get_external_ip(site="http://www.checkip.com"):
	import urllib, re
	content = urllib.urlopen(site).read()
	grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', content)
	address = grab[0]
	return address

'''Use starting with index 1, until 2019668, that is the last line'''
def get_GeoLiteBlockLine(index, my_file = 'GeoLite/GeoLiteCity-Blocks.csv'):
	import linecache
	HEADER_SIZE = 1
	file_line = linecache.getline(my_file, index + HEADER_SIZE).split(",")
	return map(lambda x : int(x.strip()[1:-1]), file_line)


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


def get_IPASLine(index, my_file = 'GeoLite/GeoIPASNum2.csv'):
	import linecache
	HEADER_SIZE = 0
	file_line = linecache.getline(my_file, index + HEADER_SIZE).split(",")
	return map(int, file_line[0:2]) + [file_line[2].strip()[1:-1]] if len(file_line) > 1 else None


def get_IPAS(ip_addr):
	item = ip2int(ip_addr)
	first = 1
	last = 224846 ### counted using wc -> should change
	found = False

	while first<=last and not found:
		midpoint = (first + last)//2
		mid_el = get_IPASLine(midpoint)

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
	Return array content:
	[locId, country, region, city, postalCode, latitude, longitude, metroCode, areaCode]
'''
def get_GeoLiteBlockLocation(ip_addr):
	import linecache
	HEADER_SIZE = 1
	id_location = get_GeoLiteBlockId(ip2int(ip_addr))[2]
	return linecache.getline('GeoLite/GeoLiteCity-Location.csv', id_location + HEADER_SIZE).strip().split(",")

'''
	Return correspondent host name
	by using host UNIX service.
'''
def host(ip="8.8.8.8"):
	from subprocess import Popen, PIPE
	p = Popen(['host', ip], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	output, err = p.communicate(b"input data that is passed to subprocess' stdin")
	return output.rstrip().split()[-1]

''''
	Return array:
	[(bytes, time, ip, NS, [location_array], ... ] 
	[location_array] = [locId, country, region, city, postalCode, latitude, longitude, metroCode, areaCode]
'''
def dig(site="www.example.com"):
	from subprocess import Popen, PIPE
	p = Popen(['dig', '+trace', site], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	output, err = p.communicate(b"input data that is passed to subprocess' stdin")
	b = output.strip().split('\n')
	for i in range(len(b)):
		line = b[i].split()
		if len(line) > 0 and (line[1] == 'Received'):
			s = line[5]
			ip_address = s[s.find('(')+1 : s.find(')')]
			n_bytes = line[2]
			response_time = line[7]
			print (n_bytes, response_time, ip_address, host(ip_address), get_GeoLiteBlockLocation(ip_address))
	for i in range(len(b)):
		line = b[i].split()
		if len(line) > 0 and (line[0] not in ';;'):
			print "Server:%-20s Type:%-15s address:%-10s" % (line[0], line[3], line[4])

# dig(site="www.facebook.com")
# my_ips = parse_dig(output)
# for ip in my_ips:	
# 	print ip, get_GeoLiteBlockLocation(ip)
# print "130.89.93.44", get_GeoLiteBlockLocation("130.89.93.44")

my_external_ip = get_external_ip()
print my_external_ip, get_IPAS(my_external_ip)
# print get_GeoLiteBlockLocation(my_external_ip)
# site = "vitrines-inteligentes-1251445001.us-east-1.elb.amazonaws.com."
# site = "plus.google.com"
# print dig(site=site)
# my_ips = ["54.76.117.96", "54.76.116.11", "200.215.195.1"]
# for ip in my_ips:
# 	print get_GeoLiteBlockLocation(ip)