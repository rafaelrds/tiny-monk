import sys

# import os
# os.environ['http_proxy']=''

import urllib2
from bs4 import BeautifulSoup

url = 'http://www.alexa.com/topsites/global;'
index = 0
N = int(sys.argv[1])
sites_set = set([])
sites_list = []


while (len(sites_list) < N):
        html = urllib2.urlopen(url + str(index)).read()
        soup = BeautifulSoup(html, 'html.parser')

        for tag in soup.find_all( "p", { "class" : "desc-paragraph"}):
                full_url = tag.a['href']
                website = full_url.split('/')[-1]
                ws_name = website.split('.')[0]
                if ws_name not in sites_set:
                	sites_set.add(ws_name)
                	sites_list.append(website)
                # else:
                #         print "colision: %s, %s already exists " % (website, ws_name)
        index += 1 #next page

for i, site in enumerate(sites_list[0:N]):
	print 'http://www.'+site

