#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

int rng_init(void);
int rng_get_bytes(uint8_t* buffer, int size);
void panic(void);

#define RANDOM_DELAY_TINY(result) do { \
    uint8_t non_volatile_delay_cycles; \
    volatile uint8_t delay_cycles; \
    if (rng_get_bytes(&non_volatile_delay_cycles, sizeof(non_volatile_delay_cycles)) != 0) { \
        panic(); /* Handle TRNG failure */ \
    } \
    delay_cycles = non_volatile_delay_cycles; /* Copy to volatile variable */ \
    volatile uint8_t dummy_var = 0; \
    for (volatile uint8_t i = 0; i < delay_cycles; i++) { \
        dummy_var ^= i; /* Trivial operation to avoid optimization */ \
    } \
    (result) = dummy_var; /* Assign the result of the operation to the output variable */ \
} while(0)

#endif