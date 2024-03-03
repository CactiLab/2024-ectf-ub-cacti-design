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
void enable_defense_bit();       // defined in component.c

#define RANDOM_DELAY_TINY_2 do { \
    uint8_t non_volatile_delay_cycles; \
    volatile uint8_t delay_cycles; \
    do {    \
        if (rng_get_bytes(&non_volatile_delay_cycles, sizeof(non_volatile_delay_cycles)) != 0) { \
            panic(); /* Handle TRNG failure */ \
        } \
    } while(!non_volatile_delay_cycles);   \
    delay_cycles = non_volatile_delay_cycles; /* Copy to volatile variable */ \
    volatile uint8_t dummy_var = 0; \
    volatile uint8_t dummy_var_2 = 0; \
    for (volatile uint8_t i = 0; i < delay_cycles; i++) { \
        dummy_var += i; /* Trivial operation to avoid optimization */ \
        dummy_var_2 |= i;   \
    } \
    if ((dummy_var | dummy_var_2) == 0) { \
        panic();    \
    }   \
} while(0)

/**
 * Double-if, anti-glitching
 * @param EXPR, VAL: equivelent to if (EXPR != VAL) {...}
 * @param ERR: And error value in integer, make sure the EXPR will never return a value equals to ERR
 * followed by the code of true-branch
 * end with CONDITION_BRANCH_ENDING
*/
#define CONDITION_NEQ_BRANCH(EXPR, VAL, ERR)  \
    (if_val_1 = (ERR)); \
    (if_val_2 = (ERR)); \
    if ((if_val_1 = (EXPR)) != VAL) { \
        RANDOM_DELAY_TINY_2;    \
        if ((if_val_2 = (EXPR)) != VAL) {   \
            RANDOM_DELAY_TINY_2;    \

/**
 * Double-if, anti-glitching
 * @param EXPR, VAL: equivelent to if (EXPR == VAL) {...}
 * @param ERR: And error value in integer, make sure the EXPR will never return a value equals to ERR
 * followed by the code of true-branch
 * end with CONDITION_BRANCH_ENDING
*/
#define CONDITION_EQ_BRANCH(EXPR, VAL, ERR)  \
    (if_val_1 = (ERR)); \
    (if_val_2 = (ERR)); \
    if ((if_val_1 = (EXPR)) == VAL) { \
        RANDOM_DELAY_TINY_2;    \
        if ((if_val_2 = (EXPR)) == VAL) {   \
            RANDOM_DELAY_TINY_2;    \

/**
 * CONDITION_XXX_BRANCH and CONDITION_BRANCH_ENDING include the true-branch code
 * @param ERR: same as the ERR param in the CONDITION_XXX_BRANCH macro
*/
#define CONDITION_BRANCH_ENDING(ERR)   \
        }   \
    }   \
    if ((if_val_1 == (ERR)) || (if_val_2 == (ERR))) {   \
        panic();    \
    }   \

#endif