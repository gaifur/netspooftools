#include <stdlib.h>

#include "ipv4.h"

void *ipv4_payload(ipv4_t *pkg) {
  unsigned offset = ((pkg->version & 0x0F)<<2)-sizeof(ipv4_t);
  return &(pkg->opt_payload[offset]);
}


uint16_t ipv4_checksum(ipv4_t *pkg) {
  uint32_t sum = 0;
  unsigned len;
  uint16_t *a;

  len = ((pkg->version & 0x0F)<<2);
  a = (uint16_t*)pkg;

  //since len is garantee to be even, we are fine this way
  while(len) {
    sum += *(a++);
    if(sum & 0x80000000) /* if high bit order set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  /* since we are using two complement
     folding is necessary to achive one complement sum */
  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}
