CC=clang
LD=$(CC)
CFLAGS=-Wall -O2
LDFLAGS=

all: dhcp_spoofer arp_spoofer arp_dump

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

dhcp_spoofer: dhcp_spoofer.o dhcp.o udp4.o ipv4.o checksum.o mac.o
	$(LD) $(LDFLAGS) -o $@ $+

arp_spoofer: arp_spoofer.o arp.o mac.o
	$(LD) $(LDFLAGS) -o $@ $+

arp_dump: arp_dump.o arp.c mac.c
	$(LD) $(LDFLAGS) -o $@ $+

clean:
	rm -f arp_spoofer arp_dump dhcp_spoofer *.o
