#!/bin/bash
sudo yum install -y vim xorg-x11-server-Xvfb.i686  libXrender-0.9.6-1.fc14.i686 xulrunner-1.9.2.24-1.fc14.i686
sudo yum install -y xorg-x11*
sudo yum install -y bind-utils

sudo yum install -y git-all

curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"
sudo python get-pip.py
sudo pip install beautifulsoup4 pyvirtualdisplay selenium

wget https://ftp.mozilla.org/pub/firefox/releases/32.0/linux-i686/en-US/firefox-32.0.tar.bz2
tar xvf firefox-32.0.tar.bz2
sudo mv firefox /usr/local/
cd /usr/local/
sudo ln -s /usr/local/firefox/firefox /usr/bin/firefox

#wget http://python.org/ftp/python/2.7.6/Python-2.7.6.tgz
#tar zxvf Python-2.7.6.tgz
#./configure --prefix=/usr/local --enable-unicode=ucs4 --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib"

sudo python enjoy.py http://www.nu.nl 60 & sudo timeout 65 tcpdump -ieth0 'port 53' -w 'nu_nl.pcap' & wait
