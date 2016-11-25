#!/bin/bash
set -e

echo "Installing dependecies..."
apt-get install flex bison build-essential checkinstall libpcap-dev libnet1-dev libpcre3-dev libmysqlclient15-dev libnetfilter-queue-dev iptables-dev

wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
wget https://www.snort.org/downloads/snort/snort-2.9.8.3.tar.gz
wget https://github.com/dugsong/libdnet/archive/libdnet-1.12.tar.gz

tar zxvf libdnet-1.12.tar.gz -C /usr/src/
tar xvfz daq-2.0.6.tar.gz -C /usr/src/
tar xvfz snort-2.9.8.3.tar.gz -C /usr/src/

cd /usr/src/libdnet-libdnet-1.12/
./configure; make
checkinstall
dpkg -i libdnet-libdnet_1.12-1_i386.deb
ln -s /usr/local/lib/libdnet.1.0.1 /usr/lib/libdnet.1

cd /usr/src/daq-2.0.6
./configure "CFLAGS=-fPIC"; make
checkinstall
dpkg -i daq_2.0.6-1_amd64.deb

echo "Installing Snort..."
cd /usr/src/snort-2.9.8.3
./configure --enable-sourcefire; make
checkinstall
dpkg -i snort-2.9.8.3-1_amd64.deb
ln -s /usr/local/bin/snort /usr/sbin/snort
ldconfig -v

echo "Configuring Snort..."
mkdir /etc/snort
mkdir /etc/snort/rules
mkdir /var/log/snort

echo "include /etc/snort/rules/dhcp.rules" > /etc/snort/snort.conf
echo "alert icmp any any -> any any (msg:"ICMP Packet"; sid:477; rev:3;)" > /etc/snort/rules/icmp.rules
echo "alert udp !10.0.0.1/24 67 -> any 68 (msg: "DHCP Spoofing!!"; sid:1000001;)" > /etc/snort/rules/dhcp.rules

echo "Completed! Start use: snort -c /etc/snort/snort.conf -l /var/log/snort/"
