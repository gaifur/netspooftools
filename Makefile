CC=gcc
LD=$(CC)
CFLAGS=-Wall -O2
LDFLAGS=

all: arp_spoofer arp_dump

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

arp_spoofer: arp_spoofer.o arp.o mac.o
	$(LD) $(LDFLAGS) -o $@ $+

arp_dump: arp_dump.o arp.o mac.o
	$(LD) $(LDFLAGS) -o $@ $+


clean:
	rm -f arp_spoofer arp_dump *.o
