import struct,socket
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def parse_dig(text):
	return [c[1] for c in [b.split('(') for b in text.split(')')] if len(c) > 1]

'''Use starting with index 1, until 2019668, that is the last line'''
def get_GeoLiteBlockLine(index):
	import linecache
	HEADER_SIZE = 1
	return map(lambda x : int(x.strip()[1:-1]), linecache.getline('GeoLite/GeoLiteCity-Blocks.csv', index + HEADER_SIZE).split(","))

def get_GeoLiteBlockId(item):
	first = 1
	last = 2019668
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

def get_GeoLiteBlockLocation(ip_addr):
	import linecache
	HEADER_SIZE = 1
	id_location = get_GeoLiteBlockId(ip2int(ip_addr))[2]
	return linecache.getline('GeoLite/GeoLiteCity-Location.csv', id_location + HEADER_SIZE).split(",")


# f = open('ufcg_dns.txt', 'r+')
from subprocess import Popen, PIPE
my_domain = "www.ufcg.com.br"
p = Popen(['dig', '+trace', my_domain], stdin=PIPE, stdout=PIPE, stderr=PIPE)
output, err = p.communicate(b"input data that is passed to subprocess' stdin")
rc = p.returncode

my_ips = parse_dig(output)
for ip in my_ips:	
	print ip, " ".join(get_GeoLiteBlockLocation(ip))

