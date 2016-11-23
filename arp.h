// -----------------------------------------------------------
// Developed By Marcos Luiggi Sartori
//              Leonardo Pavanatto Soares
// Pontifical Catholic University of Rio Grande do Sul (PUCRS)
// Computer Networks Laboratory - April 11, 2016
// -----------------------------------------------------------
// File: arp.h
// Description: arp protocol data structure.
// -----------------------------------------------------------
#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#include "mac.h"
#include "ipv4.h"

#define ARP_REQUEST 1
#define ARP_REPLY 2

// ARP for ipv4 on ethernet payload structure
typedef struct arp4_payload_t {
  macaddr_t src_macaddr;
  ipaddr_t src_ipaddr;
  macaddr_t dest_macaddr;
  ipaddr_t dest_ipaddr;
} arp4_payload_t;

typedef union arp_payload_t {
  arp4_payload_t v4;
  uint8_t raw[0];
} arp_payload_t;

// ARP frame structure
typedef struct arp_t {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t operation;
  arp_payload_t payload;
} arp_t;

// Functions for manipulating ARP's variable size raw payload
static inline uint8_t* arp_source_haddr(arp_t *pkg) {
	return pkg->payload.raw;
}

static inline uint8_t* arp_source_paddr(arp_t *pkg) {
	return pkg->payload.raw + pkg->hlen;
}

static inline uint8_t* arp_target_haddr(arp_t *pkg) {
	return pkg->payload.raw + pkg->hlen + pkg->plen;
}

static inline uint8_t* arp_target_paddr(arp_t *pkg) {
	return pkg->payload.raw + ((size_t)pkg->hlen << 1) + pkg->plen;
}

void print_bytearray(uint8_t *array, unsigned length, unsigned base, char separator);
void arp_print(arp_t *arp);

int send_arp4_request(raw_iface_t *iface, macaddr_t src_macaddr, ipaddr_t src_ipaddr,
		      macaddr_t target_macaddr, ipaddr_t target_ip);

int send_arp4_reply(raw_iface_t *iface, macaddr_t src_macaddr, ipaddr_t src_ipaddr,
		    macaddr_t target_macaddr, ipaddr_t target_ip);

int arp4_lookup(raw_iface_t *iface, ipaddr_t src_ipaddr, macaddr_t src_mac,
		ipaddr_t target_ipaddr, macaddr_t target_mac);


#endif /* !ARP_H */
