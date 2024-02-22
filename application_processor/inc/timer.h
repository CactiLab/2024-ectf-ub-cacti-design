#include "tmr.h"

#define CONT_FREQ 10 // (Hz)
#define CONT_TIMER MXC_TMR1
#define CONT_CLOCK_SOURCE MXC_TMR_8M_CLK

#define TIMER_LIMIT_ATTEST 10
#define TIMER_LIMIT_REPLACE 5
#define TIMER_LIMIT_BOOT 10
#define TIMER_LIMIT_I2C_COMMUNICATION 10

void continuous_timer_handler();

void continuous_timer();

void cancel_continuous_timer();