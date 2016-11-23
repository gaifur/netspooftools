// -----------------------------------------------------------
// Developed By Marcos Luiggi Sartori
//              Leonardo Pavanatto Soares
// Pontifical Catholic University of Rio Grande do Sul (PUCRS)
// Computer Networks Laboratory - April 11, 2016
// -----------------------------------------------------------
// File: mac.c
// Description: applies ethernet protocol to a given payload.
// -----------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#include "mac.h"

#define BUFFER_SIZE MAC_MTU

macaddr_t broadcast_macaddr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Creates an raw socket and put the interface into promiscous mode
int open_raw_socket(raw_iface_t *rs, char *ifname, uint16_t ethertype) {
  struct ifreq ifr;
  
  /* Creates a RAW socket descriptor */
  if((rs->fd = socket(PF_PACKET,SOCK_RAW, htons(ethertype))) < 0) {
    perror("socket");
    return -1;
  }

  rs->socket_addr.sll_halen = ETH_ALEN;
	
  /* Gets network interface */
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
  if(ioctl(rs->fd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
		close(rs->fd);
    return -1;
  }
  rs->socket_addr.sll_ifindex = ifr.ifr_ifindex;

  /* Gets interface flags */
  if (ioctl(rs->fd, SIOCGIFFLAGS, &ifr) < 0){
    perror("ioctl");
		close(rs->fd);
    return -1;
  }

  /* Puts interface in promisc mode */
  ifr.ifr_flags |= IFF_PROMISC;
  if(ioctl(rs->fd, SIOCSIFFLAGS, &ifr) < 0) {
    perror("ioctl");
		close(rs->fd);
    return -1;
  }

  /* Gets interface MAC Adress */
  if (ioctl(rs->fd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("SIOCGIFHWADDR");
		close(rs->fd);
    return -1;
  }

  memcpy(rs->macaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	strncpy(rs->ifname, ifname, IFNAMSIZ-1);

  return rs->fd;
}

// Assembles a MAC frame and sends into the wire
int send_frame(raw_iface_t *rs, void *payload, size_t length,
	       macaddr_t source, macaddr_t target, uint16_t ethertype) {
  uint8_t buffer[MAC_MTU];
  int ret;

  macframe_t *frame = (macframe_t*)buffer;

  // Set destinantion mac_addr
  memcpy(rs->socket_addr.sll_addr, target, ETH_ALEN);
  memcpy(frame->dest, target, ETH_ALEN);

  // Set source mac_addr
  memcpy(frame->src, source, ETH_ALEN);

  // Set Ethertype
  frame->ethertype = htons(ethertype);

  // Set the payload
  memcpy(frame->payload, payload, length);
  length += sizeof(macframe_t);

  // Send package
  if((ret = sendto(rs->fd, buffer, length, 0, (struct sockaddr*) &(rs->socket_addr),
		   sizeof(struct sockaddr_ll))) < 0)
    perror("sendto");

  return ret;
}

// Wrapper for recv syscall, so raw_iface_t abstraction is used
int recv_frame(raw_iface_t *rs, void *buffer, size_t buff_len) {
  int ret;
	// Receive package
  if ((ret = recv(rs->fd, buffer, buff_len, 0)) < 0)
    perror("recv");

  return ret;
}

/* Local Variables: */
/* mode: c */
/* tab-width: 2 */
/* End: */
