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
def get_GeoLiteBlockLine(index):
	import linecache
	HEADER_SIZE = 1
	return map(lambda x : int(x.strip()[1:-1]), linecache.getline('GeoLite/GeoLiteCity-Blocks.csv', index + HEADER_SIZE).split(","))

def get_GeoLiteBlockId(item):
	first = 1
	last = 2019668 ### counted using wc -> should change
	found = False

	while first<=last and not found:
		midpoint = (first + last)//2
		if get_GeoLiteBlockLine(midpoint)[0] <= item and item <= get_GeoLiteBlockLine(midpoint)[1]:
			return get_GeoLiteBlockLine(midpoint)
			found = True
		else:
			if item < get_GeoLiteBlockLine(midpoint)[0]:
				last = midpoint-1
			else:
				first = midpoint+1
		# print "DEBBUG",get_GeoLiteBlockLine(midpoint),midpoint
	return -1

''' 
	Return array content:
	[locId, country, region, city, postalCode, latitude, longitude, metroCode, areaCode]
'''
def get_GeoLiteBlockLocation(ip_addr):
	import linecache
	HEADER_SIZE = 1
	id_location = get_GeoLiteBlockId(ip2int(ip_addr))[2]
	return linecache.getline('GeoLite/GeoLiteCity-Location.csv', id_location + HEADER_SIZE).split(",")

def dig(site="www.google.co.uk"):
	from subprocess import Popen, PIPE
	p = Popen(['dig', '+trace', site], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	output, err = p.communicate(b"input data that is passed to subprocess' stdin")
	b = output.strip().split('\n')
	for i in range(len(b)):
		line = b[i].split()
		if len(line) > 0 and (line[1] == 'Received'):
			s = line[5]
			print line[1], line[2], line[3], line[4], s[s.find('(')+1 : s.find(')')], line[6], line[7], line[8]
	for i in range(len(b)):
		line = b[i].split()
		if len(line) > 0 and (line[0] not in ';;'):
			if line [0] == '.': line[0] = 'root'
			print "Server:%-20s Type:%-15s address:%-10s" % (line[0], line[3], line[4])

# dig(site="www.facebook.com")
# my_ips = parse_dig(output)
# for ip in my_ips:	
# 	print ip, get_GeoLiteBlockLocation(ip)
# print "130.89.93.44", get_GeoLiteBlockLocation("130.89.93.44")

my_external_ip = get_external_ip()
print my_external_ip, ip2int(my_external_ip), get_GeoLiteBlockId(ip2int(my_external_ip))
print get_GeoLiteBlockLocation(my_external_ip)