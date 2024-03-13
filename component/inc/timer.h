#ifndef __TIMER_H
#define __TIMER_H

#include "tmr.h"
#include "nvic_table.h"

#define CONT_FREQ 20 // (Hz)
#define CONT_TIMER MXC_TMR1
#define CONT_CLOCK_SOURCE MXC_TMR_8M_CLK

#define TIMER_LIMIT_ATTEST 60
#define TIMER_LIMIT_BOOT 60
#define TIMER_LIMIT_I2C_COMMUNICATION 20
#define TIMER_LIMIT_I2C_MSG 3
#define TIMER_LIMIT_I2C_MSG_3 7
#define TIMER_LIMIT_I2C_MSG_2 6
#define TIMER_LIMIT_I2C_MSG_4 12
#define TIMER_LIMIT_I2C_MSG_VAL_5 5
#define TIMER_LIMIT_I2C_MSG_VAL_8 8
#define TIMER_LIMIT_I2C_MSG_VAL_14 14
#define TIMER_LIMIT_I2C_MSG_VAL_16 16
#define TIMER_LIMIT_I2C_MSG_VAL_20 20

void continuous_timer_handler();

void continuous_timer();

void start_continuous_timer(int);

void cancel_continuous_timer();

#endif