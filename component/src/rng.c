#include "board.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "trng.h"
// #include "timer.h"

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
    int r = MXC_TRNG_Random(buffer, size);
    if (r != 0) {
        // panic();
    }
    return r;
}

/**
 * @brief return current CPU cycle in int
*/
int get_current_cpu_cycle() {
    return STCVR;
}

// /**
//  * @brief Panic function
//  * 
//  * This function is called when a critical error occurs. It disables interrupts and enters an infinite loop.
//  */
// void __attribute__((noreturn)) panic(void) {
//     enable_defense_bit();
//     cancel_continuous_timer();
//     __disable_irq();

//     volatile uint32_t counter = 0;
//     while (1) {
//         counter++;

//         // Additional fault injection tolerance: 
//         // Implement a check that verifies the loop is still executing correctly.
//         // If the counter wraps around (an unlikely event in a tight loop),
//         // it indicates the loop has been running for a long time or
//         // an attempt to manipulate the execution path has occurred.
//         if (counter == 0) {
//             // Forcefully reset the counter to maintain the loop's visibility to the compiler,
//             counter = 1;
//         }
//     }

//     // End of function, which should never be reached.
//     while (1); // Additional safety loop, redundant but ensures noreturn.
// }