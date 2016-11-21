#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stddef.h>

#include "mac.h"

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#ifndef IP_MAXLEN
#define IP_MAXLEN (MAC_MAXLEN-sizeof(ipv4_t))
#endif

#ifndef UDP_PROTO
#define UDP_PROTO 0x11
#endif

typedef uint8_t ipaddr_t[IP_ALEN];

typedef struct ipv4_t {
  uint8_t version;
  uint8_t tos;
  uint16_t total_len;
  uint16_t id;
  uint16_t fragmentation;
  uint8_t ttl;
  uint8_t proto;
  uint16_t header_checksum;
  ipaddr_t src_ip;
  ipaddr_t des_ip;
  uint8_t payload[];
} ipv4_t;

void *ipv4_payload(ipv4_t *pkg);
uint16_t ipv4_checksum(ipv4_t *pkg);

int send_ipv4(raw_iface_t *iface,
	      macaddr_t src_mac, ipaddr_t src_ip,
	      macaddr_t target_mac, ipaddr_t target_ip,
	      void *payload, size_t len, uint8_t proto, uint8_t ttl);

#endif
