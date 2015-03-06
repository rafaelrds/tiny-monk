import struct,socket
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def parse_dig(text):
	return [c[1] for c in [b.split('(') for b in text.split(')')] if len(c) > 1]


# f = open('ufcg_dns.txt', 'r+')
from subprocess import Popen, PIPE
random_domain = "www.ufcg.com.br"
p = Popen(['dig', '+trace', random_domain], stdin=PIPE, stdout=PIPE, stderr=PIPE)
output, err = p.communicate(b"input data that is passed to subprocess' stdin")
rc = p.returncode


my_ips = parse_dig(output)

for ip in my_ips:	
	ip_int = ip2int(ip)
	print ip_int

	import csv, linecache
	csvfile = open( "GeoLite/GeoLiteCity-Blocks.csv", "rb" )
	reader = csv.reader( csvfile)
	header = reader.next()

	i = 0
	HEADER_SIZE = 1
	for row in reader:
	    if int(row[0]) < ip_int and ip_int < int(row[1]) :
	        id_location = int(row[2])
	        print linecache.getline('GeoLite/GeoLiteCity-Location.csv', id_location + HEADER_SIZE).split(",")
	        break
	csvfile.close()