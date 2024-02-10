#ifndef COMMON_H
#define COMMON_H

#define STCSR (*(int *)0xE000E010)
#define STRVR (*(int *)0xE000E014)
#define STCVR (*(int *)0xE000E018)

#include <stdint.h>
#include <stddef.h>

int rng_init(void);
int rng_get_bytes(uint8_t* buffer, int size);
void panic(void);
unsigned int get_current_cpu_cycle();

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

#define RANDOM_DELAY_TINY_2 do { \
    uint8_t non_volatile_delay_cycles; \
    volatile uint8_t delay_cycles; \
    if (rng_get_bytes(&non_volatile_delay_cycles, sizeof(non_volatile_delay_cycles)) != 0) { \
        panic(); /* Handle TRNG failure */ \
    } \
    delay_cycles = non_volatile_delay_cycles; /* Copy to volatile variable */ \
    volatile uint8_t dummy_var = 0; \
    volatile uint8_t dummy_var_2 = 0; \
    print_info("delay_cycles=%d\n", delay_cycles);  \
    for (volatile uint8_t i = 0; i < delay_cycles; i++) { \
        dummy_var ^= i; /* Trivial operation to avoid optimization */ \
        dummy_var_2 |= i;   \
    } \
    if ((dummy_var | dummy_var_2) == 0) { \
        print_error("TRNG failure\n");  \
        panic();    \
    }   \
} while(0)

#endif