#include "checksum.h"

/* checksumming is endiannes independent according to RFC1071 */
uint16_t checksum16(void *data, size_t len) {
  uint32_t sum = 0;
  uint16_t *a = data;

  while(len > 1) {
    sum += *(a++);
    if(sum & 0x80000000) /* if high bit order set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  /* in case of odd length compute spare byte as well */
  if(len)
    sum += *((uint8_t*)a);
  
  /* since we are using two complement
     folding is necessary to achive one complement sum */
  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}
