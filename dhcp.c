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
  
  memcpy(frame->yiaddr, dst_ip, IP_ALEN);
  memcpy(frame->siaddr, src_ip, IP_ALEN);
  memcpy(frame->chaddr, chaddr, ETH_ALEN);
}

int send_dhcpack(raw_iface_t *iface, uint32_t xid,
		 macaddr_t src_mac, ipaddr_t src_ip,
		 macaddr_t dst_mac, ipaddr_t dst_ip,
		 ipaddr_t gateway, ipaddr_t dns,
		 macaddr_t chaddr, ipaddr_t ciaddr) {
  uint8_t buffer[UDP4_MAXLEN];
  size_t len; 
  dhcp_t *frame;
  unsigned opts = 0;

  frame = (dhcp_t*)buffer;
  len = sizeof(dhcp_t);

  fill_dhcp_reply(xid, frame, src_ip, chaddr, ciaddr);

  frame->options[opts++] = DHCP_MSG_TYPE;
  frame->options[opts++] = 1;
  frame->options[opts++] = DHCP_ACK;

  frame->options[opts++] = DHCP_SRVID;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, src_ip, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_LEASETIME;
  frame->options[opts++] = 4;
 *(uint32_t*)(frame->options+opts) = htonl(3600);
  opts+= 4;

  frame->options[opts++] = DHCP_NETMASK;
  frame->options[opts++] = 4;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0x00;

  frame->options[opts++] = DHCP_ROUTER;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, gateway, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_DNS;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, dns, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_TERMINATE;

  len+=opts;

  return send_udp4(iface,
		   src_mac, src_ip, 67,
		   dst_mac, dst_ip, 68,
		   frame, len, 64);
}

int send_dhcpoffer(raw_iface_t *iface, uint32_t xid,
		   macaddr_t src_mac, ipaddr_t src_ip,
		   macaddr_t dst_mac, ipaddr_t dst_ip,
		   ipaddr_t gateway, ipaddr_t dns,
		   macaddr_t chaddr, ipaddr_t ciaddr) {
  uint8_t buffer[UDP4_MAXLEN];
  size_t len; 
  dhcp_t *frame;
  unsigned opts = 0;

  frame = (dhcp_t*)buffer;
  len = sizeof(dhcp_t);

  fill_dhcp_reply(xid, frame, src_ip, chaddr, ciaddr);

  frame->options[opts++] = DHCP_MSG_TYPE;
  frame->options[opts++] = 1;
  frame->options[opts++] = DHCP_OFFER;

  frame->options[opts++] = DHCP_SRVID;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, src_ip, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_LEASETIME;
  frame->options[opts++] = 4;
  *(uint32_t*)(frame->options+opts) = htonl(3600);
  opts+= 4;

  frame->options[opts++] = DHCP_NETMASK;
  frame->options[opts++] = 4;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0xff;
  frame->options[opts++] = 0x00;

  frame->options[opts++] = DHCP_ROUTER;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, gateway, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_DNS;
  frame->options[opts++] = IP_ALEN;
  memcpy(frame->options+opts, dns, IP_ALEN);
  opts+= IP_ALEN;

  frame->options[opts++] = DHCP_TERMINATE;

  len+=opts;

  return send_udp4(iface,
		   src_mac, src_ip, 67,
		   dst_mac, dst_ip, 68,
		   frame, len, 64);
}
