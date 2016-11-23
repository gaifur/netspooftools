#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stddef.h>

#include <arpa/inet.h>

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

typedef uint32_t ipaddr_t;

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
  ipaddr_t dst_ip;
  uint8_t payload[];
} ipv4_t;

typedef struct ipv4_iface_t {
  raw_iface_t raw_interface;
  ipaddr_t ifip;
	
} ipv4_iface_t;

void *ipv4_payload(ipv4_t *pkg);
uint16_t ipv4_checksum(ipv4_t *pkg);

int get_ipv4_addr(raw_iface_t *iface, struct in_addr *addr);

int send_ipv4(raw_iface_t *iface,
	      macaddr_t src_mac, ipaddr_t src_ip,
	      macaddr_t dst_mac, ipaddr_t dst_ip,
	      void *payload, size_t len, uint8_t proto, uint8_t ttl);

#endif

/* Local Variables: */
/* mode: c */
/* tab-width: 2 */
/* End: */
