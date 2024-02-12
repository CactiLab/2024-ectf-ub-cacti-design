#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#define STCSR (*(int *)0xE000E010)
#define STRVR (*(int *)0xE000E014)
#define STCVR (*(int *)0xE000E018)

int rng_init(void);
int rng_get_bytes(uint8_t* buffer, int size);
int get_current_cpu_cycle();
void panic(void);

#endif