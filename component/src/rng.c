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