#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "ipv4.h"
#include "mac.h"
#include "checksum.h"

void *ipv4_payload(ipv4_t *pkg) {
  unsigned offset = ((pkg->version & 0x0F)<<2)-sizeof(ipv4_t);
  return &(pkg->payload[offset]);
}

uint16_t ipv4_checksum(ipv4_t *pkg) {
  unsigned len;

  len = ((pkg->version & 0x0F)<<2);

  return checksum16(pkg, len);
}

/* basic ipv4 assembler
 * payload should not be greater than IP_MAXLEN
 * since we are not implementing fragmentation */
int send_ipv4(raw_iface_t *iface,
	      macaddr_t src_mac, ipaddr_t src_ip,
	      macaddr_t target_mac, ipaddr_t target_ip,
	      void *payload, size_t len, uint8_t proto, uint8_t ttl) {

  ipv4_t pkg;

  if(len > IP_MAXLEN) return -1;

  bzero(&pkg, sizeof(ipv4_t));
  pkg.version = 0x45;
  pkg.total_len = len + sizeof(ipv4_t);
  pkg.fragmentation = htons(0x4000);
  pkg.ttl = ttl;
  pkg.proto = proto;
  memcpy(pkg.src_ip, src_ip, IP_ALEN);
  memcpy(pkg.des_ip, target_ip, IP_ALEN);
  pkg.header_checksum = ipv4_checksum(&pkg);

  memcpy(ipv4_payload(&pkg), payload, len);
  
  return send_frame(iface, &pkg, pkg.total_len,
		    src_mac, target_mac, IPV4_ETHERTYPE);
}

