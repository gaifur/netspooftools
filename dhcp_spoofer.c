#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>


#include "dhcp.h"
#include "mac.h"
#include "udp4.h"

static volatile unsigned keepRunning = 1;

static const uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

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
	ipaddr_t target_ip, client_ip;
  static struct in_addr start_ip, current_ip, end_ip, dns, myIp;

  macframe_t *frame = (macframe_t*)buffer;
  ipv4_t *ippkg = (ipv4_t*)(frame->payload);
  udp_t *udppkg = (udp_t*)(ippkg->payload);
  dhcp_t *dhcpmsg = (dhcp_t*)(udppkg->payload);
  uint8_t dhcptype;

  if (argc < 5) {
    fprintf(stderr, "Usage: %s <iface> <dns> <range start> <range end>\n", argv[0]);
    return 1;
  }

  if(!inet_aton(argv[2], &dns)) {
    fprintf(stderr, "Invalid ip addr %s\n", argv[2]);
    return 1;
  }

  if(!inet_aton(argv[3], &start_ip)) {
    fprintf(stderr, "Invalid ip addr %s\n", argv[2]);
    return 1;
  }

  if(!inet_aton(argv[4], &end_ip)) {
    fprintf(stderr, "Invalid ip addr %s\n", argv[2]);
    return 1;
  }

  current_ip = start_ip;

  if((fd = open_raw_socket(&iface, argv[1], ETH_P_IP)) < 0)
    return -1;

  if(get_ipv4_addr(&iface, &myIp) < 0)
    return -1;

  // Enables ip_forward
  if(!((ip_forward = fopen("/proc/sys/net/ipv4/ip_forward", "w")) &&
       (fputc('1', ip_forward) == '1')))
    fprintf(stderr, "WARNING: Unable to set ip_forward\n");
  
  if(ip_forward)
    fclose(ip_forward);

  signal(SIGINT, intHandler);
  while(keepRunning) {
    if((len = recv_frame(&iface, buffer, sizeof(buffer))) < 0) {
      close(fd);
      return -1;
    }
    if((frame->ethertype == htons(ETH_P_IP)) &&
       (ippkg->proto == UDP_PROTO) &&
       (udppkg->dst_port == htons(67)) &&
       (dhcp_parse_type(dhcpmsg, &dhcptype) >= 0)){
			
      switch(dhcptype) {
      case DHCP_DISCOVERY:
				client_ip = current_ip.s_addr;
				send_dhcpreply(&iface, DHCP_OFFER, dhcpmsg->xid,
											 iface.macaddr, myIp.s_addr,
											 target_mac, target_ip,
											 myIp.s_addr, dns.s_addr,
											 frame->src, client_ip);
				client_ip = ntohl(current_ip.s_addr)+1;
				current_ip.s_addr = htonl(client_ip > ntohl(end_ip.s_addr) ?
																	ntohl(start_ip.s_addr) : client_ip);
				break;
      case DHCP_REQ:
				if(dhcp_parse_request(dhcpmsg, &client_ip) >= 0) {
					if((int16_t)ntohs(dhcpmsg->flags) < 0) {
						target_ip = -1;
						target_mac = broadcast_macaddr;
					} else {
						target_ip = client_ip;
						target_mac = frame->src;
					}
					send_dhcpreply(&iface, DHCP_ACK, dhcpmsg->xid,
												 iface.macaddr, myIp.s_addr,
												 target_mac, target_ip,
												 myIp.s_addr, dns.s_addr,
												 frame->src, client_ip);
				}
				break;
      }
    }
  }
	
  close(fd);
  return 0;
}

/* Local Variables: */
/* mode: c */
/* tab-width: 2 */
/* End: */
