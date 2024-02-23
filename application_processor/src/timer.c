#include "timer.h"
#include "common.h"

static int timer_count = 0;
int timer_count_limit = 1;


// Toggles GPIO when continuous timer repeats
void continuous_timer_handler()
{
    // Clear interrupt
    MXC_TMR_ClearFlags(CONT_TIMER);
    ++timer_count;
    if (timer_count >= timer_count_limit) {
        timer_count = 0;
        NVIC_SystemReset();
    }
}

void continuous_timer()
{
    mxc_tmr_cfg_t tmr;
    uint32_t periodTicks = MXC_TMR_GetPeriod(CONT_TIMER, CONT_CLOCK_SOURCE, 128, CONT_FREQ);

    MXC_TMR_Shutdown(CONT_TIMER);

    tmr.pres = TMR_PRES_128;
    tmr.mode = TMR_MODE_CONTINUOUS;
    tmr.bitMode = TMR_BIT_MODE_16B;
    tmr.clock = CONT_CLOCK_SOURCE;
    tmr.cmp_cnt = periodTicks; //SystemCoreClock*(1/interval_time);
    tmr.pol = 0;

    if (MXC_TMR_Init(CONT_TIMER, &tmr, true) != E_NO_ERROR) {
        panic();
        return;
    }
}

void start_continuous_timer(int limit) {
    timer_count_limit = limit;
    MXC_NVIC_SetVector(TMR1_IRQn, continuous_timer_handler);
    NVIC_EnableIRQ(TMR1_IRQn);
    continuous_timer();
}

void cancel_continuous_timer() {
    MXC_TMR_Shutdown(CONT_TIMER);
    timer_count = 0;
}