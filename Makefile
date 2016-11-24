CC=gcc
LD=$(CC)
CFLAGS=-Wall -g
LDFLAGS=-g

all: dhcp_spoofer

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

dhcp_spoofer: dhcp_spoofer.o dhcp.o udp4.o ipv4.o checksum.o mac.o
	$(LD) $(LDFLAGS) -o $@ $+


clean:
	rm -f arp_spoofer arp_dump dhcp_spoofer *.o
