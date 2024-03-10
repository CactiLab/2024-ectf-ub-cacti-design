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
#include "mxc_device.h"
#include <stdint.h>

#define MPU_RGN_SIZE_224K                                                      \
    (MPU_RGN_SIZE_64K + MPU_RGN_SIZE_64K + MPU_RGN_SIZE_64K + MPU_RGN_SIZE_32K)

uint32_t MPURegionCountGet(void) {
    //
    // Read the DREGION field of the MPU type register and mask off
    // the bits of interest to get the count of regions.
    //
    return ((HWREG(NVIC_MPU_TYPE) & NVIC_MPU_TYPE_DREGION_M) >>
            NVIC_MPU_TYPE_DREGION_S);
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
    HWREG(NVIC_MPU_ATTR) = ((ui32Flags & ~(MPU_RASR_TEX_Msk | MPU_RASR_C_Msk)) |
                            MPU_RASR_S_Msk | MPU_RASR_B_Msk);
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

    if (MPURegionCountGet() < 8) {
        return;
    }

    ARM_MPU_Disable();

    // 0x1000E000 to 0x10045FFF - Firmware (executable, read-only)
    MPURegionSet(0, 0x1000E000,
                 MPU_RGN_SIZE_224K | MPU_RGN_PERM_EXEC |
                     MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE);
    MPURegionEnable(0);

    // 0x1007C000 to 0x1007DFFF - Flash status data (no-execute, read/write)
    MPURegionSet(1, 0x1007C000,
                 MPU_RGN_SIZE_8K | MPU_RGN_PERM_NOEXEC |
                     MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE);
    MPURegionEnable(1);
    // 0x20000000 to 0x2001FFFF - SRAM region (no-execute, read/write)
    MPURegionSet(2, 0x20000000,
                 MPU_RGN_SIZE_128K | MPU_RGN_PERM_NOEXEC |
                     MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE);
    MPURegionEnable(2);

    // Disable all other regions
    for (uint32_t i = 1; i < MPURegionCountGet(); i++) {
        ARM_MPU_ClrRegion(i);
    }

    // Enable the Memory Protection Unit
    ARM_MPU_Enable(MPU_CONFIG_PRIV_DEFAULT);
}