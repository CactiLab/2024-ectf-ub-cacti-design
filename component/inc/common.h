#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

int rng_init(void);
int rng_get_bytes(uint8_t* buffer, int size);

#endif