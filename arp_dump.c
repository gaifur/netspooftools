// -----------------------------------------------------------
// Developed By Marcos Luiggi Sartori
//              Leonardo Pavanatto Soares
// Pontifical Catholic University of Rio Grande do Sul (PUCRS)
// Computer Networks Laboratory - April 11, 2016
// -----------------------------------------------------------
// File: arp_dump.c
// Description: atack a local network.
// -----------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#include "arp.h"
#include "mac.h"

#define BUFFER_SIZE 1600

static volatile unsigned keepRunning = 1;

static void intHandler() {
  keepRunning = 0;
}

int main(int argc, char *argv[]) {
  raw_iface_t iface;
  uint8_t buffer[BUFFER_SIZE];
  macframe_t *frame = (macframe_t*)buffer;
  int fd;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
    return 1;
  }

  if((fd = open_raw_socket(&iface, argv[1])) < 0)
    exit(1);

  /* until SIGINT is received keep sending fake requests
   * directly to attacked hosts every second */
  signal(SIGINT, intHandler);
  while(keepRunning) {
    if(recv_frame(&iface, buffer, sizeof(buffer)) < 0) {
      close(fd);
      return -1;
    }

    if(ntohs(frame->ethertype) == ARP_ETHERTYPE) {
      printf("Destination MAC: ");
      print_bytearray(frame->dest, ETH_ALEN, 16, ':');
      printf("\nSource MAC: ");
      print_bytearray(frame->src, ETH_ALEN, 16, ':');
      printf("\n");
      arp_print((arp_t*)(frame->payload));
      printf("---------------------------------------------\n");
    }
  }

  printf("Good bye!\n");
  close(fd);
  return 0;
}
