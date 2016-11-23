#ifndef DHCP_H
#define DHCP_H

#include <stddef.h>
#include <stdint.h>

#include "ipv4.h"
#include "mac.h"

typedef struct dhcp_t {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  ipaddr_t ciaddr;
  ipaddr_t yiaddr;
  ipaddr_t siaddr;
  ipaddr_t giaddr;
  uint16_t chaddr[16];
  uint8_t sname[64];
  uint8_t bfile[128];
  uint32_t magic;
  uint8_t options[];
} dhcp_t;

#define DHCP_OPREQUEST 0x01
#define DHCP_OPREPLAY 0x02
#define DHCP_MAGIC 0x63825363

#define DHCP_MSG_TYPE 53
#define DHCP_DISCOVERY 01
#define DHCP_OFFER 02
#define DHCP_REQ 03
#define DHCP_ACK 05

#define DHCP_SRVID 54
#define DHCP_DNS 6
#define DHCP_ROUTER 3
#define DHCP_NETMASK 1
#define DHCP_LEASETIME 51
#define DHCP_TERMINATE 0xFF

int send_dhcpreply(raw_iface_t *iface, uint8_t type, uint32_t xid,
		   macaddr_t src_mac, ipaddr_t src_ip,
		   macaddr_t dst_mac, ipaddr_t dst_ip,
		   ipaddr_t gateway, ipaddr_t dns,
		   macaddr_t chaddr, ipaddr_t ciaddr);

int dhcp_parse_request(dhcp_t *dhcp, ipaddr_t *rq_addr);
int dhcp_parse_type(dhcp_t *dhcp, uint8_t *type);

#endif
