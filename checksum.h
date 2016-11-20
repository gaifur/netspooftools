#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

/* performs checksum according to RFC 1071 */
uint16_t checksum16(void *data, size_t len);

#endif
