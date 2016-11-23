#ifndef UDP4_H
#define UDP4_H

#include "ipv4.h"
#include "udp.h"

#ifndef UDP4_MAXLEN
#define UDP4_MAXLEN (IP_MAXLEN-sizeof(udp_t))
#endif

uint16_t udp4_checksum(udp_t *frame, ipaddr_t src_ip, ipaddr_t dst_ip);

int send_udp4(raw_iface_t *iface,
							macaddr_t src_mac, ipaddr_t src_ip, uint16_t src_port,
							macaddr_t dst_mac, ipaddr_t dst_ip, uint16_t dst_port,
							void *payload, size_t len, uint8_t ttl);

#endif
