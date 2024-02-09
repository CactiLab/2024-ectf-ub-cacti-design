#include "board.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "trng.h"

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
    return MXC_TRNG_Random(buffer, size);
}

/**
 * @brief Panic function
 * 
 * This function is called when a critical error occurs. It disables interrupts and enters an infinite loop.
 */
void __attribute__((noreturn)) panic(void) {
    __disable_irq();

    volatile uint32_t counter = 0;
    while (1) {
        counter++;

        // Additional fault injection tolerance: 
        // Implement a check that verifies the loop is still executing correctly.
        // If the counter wraps around (an unlikely event in a tight loop),
        // it indicates the loop has been running for a long time or
        // an attempt to manipulate the execution path has occurred.
        if (counter == 0) {
            // Forcefully reset the counter to maintain the loop's visibility to the compiler,
            counter = 1;
        }
    }

    // End of function, which should never be reached.
    while (1); // Additional safety loop, redundant but ensures noreturn.
}