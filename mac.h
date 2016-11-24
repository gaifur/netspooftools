// -----------------------------------------------------------
// Developed By Marcos Luiggi Sartori
//              Leonardo Pavanatto Soares
// Pontifical Catholic University of Rio Grande do Sul (PUCRS)
// Computer Networks Laboratory - April 11, 2016
// -----------------------------------------------------------
// File: mac.h
// Description: ethernet protocol data structure.
// -----------------------------------------------------------
#ifndef MAC_H
#define MAC_H

#include <stddef.h>
#include <stdint.h>

#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef MAC_MTU
#define MAC_MTU 1500
#endif

#ifndef MAC_MAXLEN
#define MAC_MAXLEN (MAC_MTU-sizeof(macframe_t))
#endif

// type for MAC Adress
typedef uint8_t macaddr_t[ETH_ALEN];

/* Structure encapsulaton required information for
 * sending and receving raw ethernet frames */
typedef struct raw_iface_t {
  struct sockaddr_ll socket_addr;
  char ifname[IFNAMSIZ];
  macaddr_t  macaddr;
  int fd;
} raw_iface_t;

// ethernet frame data structure
typedef struct macframe_t {
  macaddr_t dest;
  macaddr_t src;
  uint16_t ethertype;
  uint8_t payload[];
} macframe_t;

extern macaddr_t broadcast_macaddr;

// Creates an raw socket and put the interface into promiscous mode
int open_raw_socket(raw_iface_t *rs, char *ifname, uint16_t ethertype);
// Assembles a MAC frame and sends into the wire
int send_frame(raw_iface_t *rs, void *payload, size_t length,
	       macaddr_t source, macaddr_t target, uint16_t ethertype);
// Wrapper for recv syscall, so raw_iface_t abstraction is used
int recv_frame(raw_iface_t *rs, void *buffer, size_t buff_len);

#endif /* !MAC_H */

/* Local Variables: */
/* mode: c */
/* tab-width: 2 */
/* indent-tabs-mode: nil */
/* End: */
