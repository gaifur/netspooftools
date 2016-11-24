#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "dhcp.h"
#include "udp4.h"

static void fill_dhcp_reply (uint32_t xid, dhcp_t *frame,
			     ipaddr_t src_ip, macaddr_t chaddr,
			     ipaddr_t dst_ip) {

  bzero(frame, sizeof(dhcp_t));
  
  frame->op = DHCP_OPREPLAY;
  frame->htype = 0x01;
  frame->hlen = ETH_ALEN;
  frame->xid = xid;
  frame->magic = htonl(DHCP_MAGIC);
  
  frame->yiaddr = dst_ip;
  frame->siaddr = src_ip;
  memcpy(frame->chaddr, chaddr, ETH_ALEN);
}

int send_dhcpreply(raw_iface_t *iface, uint8_t type, uint32_t xid,
		 macaddr_t src_mac, ipaddr_t src_ip,
		 macaddr_t dst_mac, ipaddr_t dst_ip,
		 ipaddr_t gateway, ipaddr_t dns,
		 macaddr_t chaddr, ipaddr_t ciaddr) {
  uint8_t buffer[UDP4_MAXLEN];
  size_t len; 
  dhcp_t *frame;
  uint32_t ttl;
  unsigned opts = 0;

  frame = (dhcp_t*)buffer;
  len = sizeof(dhcp_t);

  fill_dhcp_reply(xid, frame, src_ip, chaddr, ciaddr);

  frame->options[opts++] = DHCP_MSG_TYPE;
  frame->options[opts++] = 1;
  frame->options[opts++] = type;

  frame->options[opts++] = DHCP_SRVID;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, &src_ip, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_LEASETIME;
  frame->options[opts++] = 4;
  ttl = htonl(86400);
  memcpy(frame->options+opts, &ttl, sizeof(uint32_t));
  opts+= sizeof(uint32_t);

  frame->options[opts++] = DHCP_NETMASK;
  frame->options[opts++] = 4;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0x00;

  frame->options[opts++] = DHCP_ROUTER;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, &gateway, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_DNS;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, &dns, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_TERMINATE;

  len+=opts;

  return send_udp4(iface,
		   src_mac, src_ip, 67,
		   dst_mac, dst_ip, 68,
		   frame, len, 64);
}

int dhcp_parse_request(dhcp_t *dhcp, ipaddr_t *rq_addr) {
  uint8_t *a;

  a = dhcp->options;

  if(dhcp->magic != htonl(DHCP_MAGIC))
    return -2;
  
  while(*a != DHCP_TERMINATE) {
    if(*a == 50) {
      memcpy(rq_addr, a+2, IP_ALEN);
      return a-(dhcp->options);
    }
    a += *a ? *(a+1)+2 : 1;
  }

  return -1;
}

int dhcp_parse_type(dhcp_t *dhcp, uint8_t *type) {
  uint8_t *a;

  a = dhcp->options;

  if(dhcp->magic != htonl(DHCP_MAGIC))
    return -2;

  while(*a != DHCP_TERMINATE) {
    if(*a == DHCP_MSG_TYPE) {
      *type = *(a+2);
      return a-(dhcp->options);
    }
    a += *a ? *(a+1)+2 : 1;
  }

  return -1;
}
