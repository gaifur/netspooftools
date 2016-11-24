#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "dhcp.h"
#include "udp4.h"

static void fill_dhcp_header (uint32_t xid, dhcp_t *frame,
                              ipaddr_t src_ip, macaddr_t chaddr,
                              ipaddr_t dst_ip, uint8_t op) {

  bzero(frame, sizeof(dhcp_t));
  
  frame->op = op;
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
                   ipaddr_t gateway, ipaddr_t dns, ipaddr_t netmask,
                   macaddr_t chaddr, ipaddr_t ciaddr) {
  uint8_t buffer[UDP4_MAXLEN];
  size_t len; 
  dhcp_t *frame;
  uint32_t ttl;
  unsigned opts = 0;

  frame = (dhcp_t*)buffer;
  len = sizeof(dhcp_t);

  fill_dhcp_header(xid ,frame, src_ip, chaddr, ciaddr, DHCP_OPREPLAY);
  
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
  memcpy(frame->options+opts, &netmask, IP_ALEN);
  opts+= IP_ALEN;

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

int send_dhcp_discovery(raw_iface_t *iface, macaddr_t src_mac) {
  uint8_t buffer[UDP4_MAXLEN];
  size_t len; 
  dhcp_t *frame;
  unsigned opts = 0;

  frame = (dhcp_t*)buffer;
  len = sizeof(dhcp_t);

  bzero(frame, sizeof(dhcp_t));
  
  frame->op = DHCP_OPREQUEST;
  frame->htype = 0x01;
  frame->hlen = ETH_ALEN;
  frame->xid = random();
  frame->magic = htonl(DHCP_MAGIC);
  
  memcpy(frame->chaddr, src_mac, ETH_ALEN);
  
  frame->options[opts++] = DHCP_MSG_TYPE;
  frame->options[opts++] = 1;
  frame->options[opts++] = DHCP_DISCOVERY;

  frame->options[opts++] = DHCP_CLIENT_ID;
  frame->options[opts++] = 7;
  frame->options[opts++] = 1;
  memcpy(frame->options+opts, src_mac, 6);
  opts+=6;

  frame->options[opts++] = DHCP_TERMINATE;

  len+=opts;

  return send_udp4(iface, src_mac, 0, 68,
                   broadcast_macaddr, -1, 67,
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

int dhcp_parse_dns(dhcp_t *dhcp, ipaddr_t *dns) {
  uint8_t *a;

  a = dhcp->options;

  if(dhcp->magic != htonl(DHCP_MAGIC))
    return -2;
  
  while(*a != DHCP_TERMINATE) {
    if(*a == 6) {
      memcpy(dns, a+2, IP_ALEN);
      return a-(dhcp->options);
    }
    a += *a ? *(a+1)+2 : 1;
  }

  return -1;
}

int dhcp_parse_netmask(dhcp_t *dhcp, ipaddr_t *netmask) {
  uint8_t *a;

  a = dhcp->options;

  if(dhcp->magic != htonl(DHCP_MAGIC))
    return -2;
  
  while(*a != DHCP_TERMINATE) {
    if(*a == 1) {
      memcpy(netmask, a+2, IP_ALEN);
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

/* Local Variables: */
/* mode: c */
/* tab-width: 2 */
/* indent-tabs-mode: nil */
/* End: */
