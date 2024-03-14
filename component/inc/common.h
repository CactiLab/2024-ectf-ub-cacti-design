#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

int rng_init(void);
int rng_get_bytes(uint8_t* buffer, int size);
void panic(void);
void enable_defense_bit();       // defined in component.c

#define RANDOM_DELAY_TINY do { \
    uint8_t non_volatile_delay_cycles; \
    volatile uint8_t delay_cycles; \
    do {    \
        if (rng_get_bytes(&non_volatile_delay_cycles, sizeof(non_volatile_delay_cycles)) != 0) { \
            panic(); /* Handle TRNG failure */ \
        } \
    } while(!non_volatile_delay_cycles);   \
    delay_cycles = non_volatile_delay_cycles; /* Copy to volatile variable */ \
    volatile uint8_t dummy_var = 0; \
    volatile uint8_t i = 0;     \
    for (; i < delay_cycles; i++) { \
        dummy_var += 1; /* Trivial operation to avoid optimization */ \
    } \
    if (!((dummy_var == delay_cycles) && (i == delay_cycles))) { \
        panic();    \
    }   \
} while(0)



#define EXPR_EXECUTE(EXPR, ERR)     \
    (if_val_1 = (ERR));             \
    (if_val_2 = (ERR));             \
    RANDOM_DELAY_TINY;              \
    (if_val_1 = (EXPR));            \
    RANDOM_DELAY_TINY;              \
    (if_val_2 = (EXPR));            \
    RANDOM_DELAY_TINY;

#define EXPR_CHECK(ERR)         \
    if (if_val_1 != if_val_2 || if_val_1 == ERR || if_val_2 == ERR) {   \
        panic();                \
    }

#define EXPR_EXECUTE_CHECK(EXPR, ERR)    \
    EXPR_EXECUTE(EXPR, ERR)              \
    EXPR_CHECK(ERR)

#endif