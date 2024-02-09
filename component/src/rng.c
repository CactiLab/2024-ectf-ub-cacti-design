#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "trng.h"

#include "common.h"


/**
 * @brief Initializes the random number generator.
 * 
 * This function initializes the random number generator by calling the `MXC_TRNG_Init()` function.
 */
int rng_init(void) {
    STRVR = 0xFFFFFF;  // max count
    STCVR = 0;         // force a re-load of the counter value register
    STCSR = 5;         // enable FCLK count without interrupt

    return MXC_TRNG_Init();
}

/**
 * @brief Generates random bytes and stores them in the provided buffer.
 *
 * This function fills the buffer with random bytes using the hardware True Random Number Generator (TRNG).
 * The buffer must have enough space to store the specified number of bytes.
 *
 * @param buffer Pointer to the buffer where the random bytes will be stored.
 * @param size   Number of random bytes to generate and store in the buffer.
 */
int rng_get_bytes(uint8_t* buffer, int size) {
    return MXC_TRNG_Random(buffer, size);
}

/**
 * @brief return current CPU cycle in int
*/
int get_current_cpu_cycle() {
    return STCVR;
}