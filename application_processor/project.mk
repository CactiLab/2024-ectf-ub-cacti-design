# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

ROOT=.
# LIBMBEDTLS_ROOT=${ROOT}/lib/libmbedtls

IPATH+=../deployment
IPATH+=inc/
# IPATH += ${LIBMBEDTLS_ROOT}/include
VPATH+=src/

# PROJ_LDFLAGS += -L${LIBMBEDTLS_ROOT}/lib
# PROJ_LIBS += everest
# PROJ_LIBS += mbedcrypto
# PROJ_LIBS += mbedx509
# PROJ_LIBS += mbedtls
# PROJ_LIBS += p256m

PROJ_LDFLAGS += -Wl,--no-warn-rwx-segments

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
CRYPTO_EXAMPLE=0

# Enable Crypto Example
#CRYPTO_EXAMPLE=1
