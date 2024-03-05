//*****************************************************************************
//
// mpu_init.c - Driver for the Cortex-M4 memory protection unit (MPU).
//
// Copyright (c) 2007-2020 Texas Instruments Incorporated.  All rights reserved.
// Software License Agreement
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions
//   are met:
//
//   Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
//   Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the
//   distribution.
//
//   Neither the name of Texas Instruments Incorporated nor the names of
//   its contributors may be used to endorse or promote products derived
//   from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// This is part of revision 2.2.0.295 of the Tiva Peripheral Driver Library.
//
//*****************************************************************************

#include "mpu_init.h"
#include <stdint.h>

#define MPU_RGN_SIZE_224K                                                      \
    (MPU_RGN_SIZE_64K + MPU_RGN_SIZE_64K + MPU_RGN_SIZE_64K + MPU_RGN_SIZE_32K)

void MPUEnable(uint32_t ui32MPUConfig) {
    //
    // Check the arguments.
    //
    ASSERT(
        !(ui32MPUConfig & ~(MPU_CONFIG_PRIV_DEFAULT | MPU_CONFIG_HARDFLT_NMI)));

    //
    // Set the MPU control bits according to the flags passed by the user,
    // and also set the enable bit.
    //
    HWREG(NVIC_MPU_CTRL) = ui32MPUConfig | NVIC_MPU_CTRL_ENABLE;
}

void MPUDisable(void) {
    //
    // Turn off the MPU enable bit.
    //
    HWREG(NVIC_MPU_CTRL) &= ~NVIC_MPU_CTRL_ENABLE;
}

void MPURegionSet(uint32_t ui32Region, uint32_t ui32Addr, uint32_t ui32Flags) {
    //
    // Check the arguments.
    //
    ASSERT(ui32Region < 8);
    ASSERT(ui32Addr ==
           (ui32Addr & ~0 << (((ui32Flags & NVIC_MPU_ATTR_SIZE_M) >> 1) + 1)));

    //
    // Program the base address, use the region field to select the
    // region at the same time.
    //
    HWREG(NVIC_MPU_BASE) = ui32Addr | ui32Region | NVIC_MPU_BASE_VALID;

    //
    // Program the region attributes.  Set the TEX field and the S, C,
    // and B bits to fixed values that are suitable for all Tiva C and
    // E Series memory.
    //
    HWREG(NVIC_MPU_ATTR) =
        ((ui32Flags & ~(NVIC_MPU_ATTR_TEX_M | NVIC_MPU_ATTR_CACHEABLE)) |
         NVIC_MPU_ATTR_SHAREABLE | NVIC_MPU_ATTR_BUFFRABLE);
}

void MPURegionEnable(uint32_t ui32Region) {
    //
    // Check the arguments.
    //
    ASSERT(ui32Region < 8);

    //
    // Select the region to modify.
    //
    HWREG(NVIC_MPU_NUMBER) = ui32Region;

    //
    // Modify the enable bit in the region attributes.
    //
    HWREG(NVIC_MPU_ATTR) |= NVIC_MPU_ATTR_ENABLE;
}

void mpu_init() {
    __asm("dmb");

    // 0x1000E000 to 0x10045FFF - Firmware (executable, read-only)
    MPURegionSet(0, 0x1000E000,
                 MPU_RGN_SIZE_224K | MPU_RGN_PERM_EXEC |
                     MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE);
    // 0x1007C000 to 0x1007DFFF - Flash status data (no-execute, read/write)
    // MPURegionSet(1, 0x1007C000,
    //              MPU_RGN_SIZE_4K | MPU_RGN_PERM_NOEXEC |
    //                  MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE);
    // 0x20000000 to 0x2001FFFF - SRAM region (no-execute, read/write)
    MPURegionSet(1, 0x20000000,
                 MPU_RGN_SIZE_128K | MPU_RGN_PERM_NOEXEC |
                     MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE);
    // Enable the Memory Protection Unit
    MPUEnable(MPU_CONFIG_HARDFLT_NMI);

    __asm("dsb");
    __asm("isb");
}