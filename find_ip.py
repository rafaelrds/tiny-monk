# http://stackoverflow.com/questions/2311510/getting-a-machines-external-ip-address
def get_external_ip(site="http://www.checkip.com"):
	import urllib, re
	content = urllib.urlopen(site).read()
	grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', content)
	address = grab[0]
	return address
