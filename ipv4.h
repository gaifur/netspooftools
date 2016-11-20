#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stddef.h>

#ifndef IP_ALEN
#define IP_ALEN 4
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
  uint8_t opt_payload[0];
} ipv4_t;

void *ipv4_payload(ipv4_t *pkg);
uint16_t ipv4_checksum(ipv4_t *pkg);


#endif
