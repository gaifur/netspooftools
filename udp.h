#ifndef UDP_H
#define UDP_H

#include <stdint.h>

typedef struct udp_t {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
  uint8_t payload[];
} udp_t;

#endif
