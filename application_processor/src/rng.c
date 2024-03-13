#include "board.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "trng.h"
// #include "timer.h"
#include "mxc_delay.h"

#include "common.h"

/**
 * @brief Initializes the random number generator.
 * 
 * This function initializes the random number generator by calling the `MXC_TRNG_Init()` function.
 * 
 * @return Success/Fail, see MXC_Error_Codes for a list of return codes.
 */
int rng_init(void) {
    return MXC_TRNG_Init();
}

/**
 * @brief Generates random bytes using the True Random Number Generator (TRNG).
 *
 * This function generates random bytes using the TRNG and stores them in the specified buffer.
 *
 * @param buffer Pointer to the buffer where the generated random bytes will be stored.
 * @param size The number of random bytes to generate.
 * @return Success/Fail, see MXC_Error_Codes for a list of return codes.
 */
int rng_get_bytes(uint8_t* buffer, int size) {
    int r = MXC_TRNG_Random(buffer, size);
    if (r != 0) {
        panic();
    }
    return r;
}

/**
 * @brief Panic function
 * 
 * This function is called when a critical error occurs. It disables interrupts and enters an infinite loop.
 */
void panic(void) {
    enable_defense_bit();
    // cancel_continuous_timer();
    __disable_irq();

    asm volatile(
        "udf #0\n"  // Execute an undefined instruction to trigger HardFault
        :
        :
        : "memory"
    );
}

/**
 * random delay for up to @param limit useconds
*/
void random_delay_us(uint32_t limit) {
    uint32_t i;
    uint32_t *p = &i;
    rng_get_bytes((uint8_t *) p, sizeof(uint32_t));
    MXC_Delay(i % limit);
}