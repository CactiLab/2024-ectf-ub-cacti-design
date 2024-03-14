/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "monocypher.h"
#include "simple_flash.h"
#include "syscalls.h"
#include "mpu_init.h"
#include "common.h"
#include "timer.h"

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
// #include "global_secrets.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/
#define ERR_VALUE -15   // an error value that functions will never return

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF
#define CP_PRIV_KEY_OFFSET      offsetof(flash_entry, cp_priv_key)
#define AP_PUB_KEY_OFFSET       offsetof(flash_entry, ap_pub_key)
#define ATTEST_CIPHER_OFFSET    offsetof(flash_entry, cipher_attest_data)
#define CIPHER_BOOT_TEXT_OFFSET offsetof(flash_entry, cipher_boot_text)

#define PRIV_KEY_SIZE           64
#define PUB_KEY_SIZE            32
#define NONCE_SIZE              64
#define SIGNATURE_SIZE          64
#define MAX_POST_BOOT_MSG_LEN   64
#define CIPHER_ATTESTATION_DATA_LEN 243
#define CIPHER_ATTESTATION_DATA_LEN_ROUND 244
#define COMPONENT_ID_SIZE       4
#define AEAD_MAC_SIZE           16
#define BOOT_MSG_PLAIN_TEXT_SIZE        128
#define BOOT_MSG_CIPHER_TEXT_SIZE       BOOT_MSG_PLAIN_TEXT_SIZE + AEAD_MAC_SIZE

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST,
    COMPONENT_CMD_MSG_FROM_AP_TO_CP,
    COMPONENT_CMD_MSG_FROM_CP_TO_AP,
    COMPONENT_CMD_BOOT_2
} component_cmd_t;

// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

typedef struct __attribute__((packed)) __packed {
    uint8_t cmd_label;
    uint8_t nonce[NONCE_SIZE];
    uint8_t id[4];
} packet_plain_with_id;

typedef struct __attribute__((packed)) __packed {
    uint8_t cmd_label;
    uint8_t nonce[NONCE_SIZE];
    uint8_t id[COMPONENT_ID_SIZE];
} packet_boot_1_ap_to_cp;

typedef struct __attribute__((packed)) __packed {
    uint8_t sig_auth[SIGNATURE_SIZE];
    uint8_t nonce[NONCE_SIZE];
} packet_boot_1_cp_to_ap;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint8_t cp_priv_key[PRIV_KEY_SIZE];
    uint8_t ap_pub_key[PUB_KEY_SIZE];
    uint8_t cipher_attest_data[CIPHER_ATTESTATION_DATA_LEN_ROUND];
    uint8_t cipher_boot_text[BOOT_MSG_CIPHER_TEXT_SIZE];
    uint32_t mode;   // 0: normal, 1: defense, refers to system_modes
} flash_entry;

// system mode
// when in the defense mode, system will be delayed for 4 seconds
typedef enum {
    SYS_MODE_NORMAL,
    SYS_MODE_DEFENSE
} system_modes;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t global_buffer_recv[MAX_I2C_MESSAGE_LEN + 1];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN + 1];

// Variable for information stored in flash memory
flash_entry flash_status;

volatile uint32_t if_val_1;
volatile uint32_t if_val_2;

/***************************** FLASH RELATED OPERATIONS ******************************/
/**
 * @brief Retrieves CP's private key from flash memory.
 * 
 * This function reads CP's private key from the specified flash address
 * and stores it in the global `flash_status.cp_priv_key` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_cp_priv_key() {
    flash_simple_read(FLASH_ADDR + CP_PRIV_KEY_OFFSET, (uint32_t*)flash_status.cp_priv_key, PRIV_KEY_SIZE);
}

/**
 * @brief Retrieves AP's public key from flash memory.
 * 
 * This function reads AP's public key from the specified flash address
 * and stores it in the global `flash_status.ap_pub_key` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_ap_pub_key() {
    flash_simple_read(FLASH_ADDR + AP_PUB_KEY_OFFSET, (uint32_t*)flash_status.ap_pub_key, PUB_KEY_SIZE);
}

/**
 * @brief Retrieves encrypted attestation data from flash memory.
 * 
 * This function reads encrypted attestation data from the specified flash address
 * and stores it in the global `flash_status.cipher_attest_data` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_attest_cipher() {
    flash_simple_read(FLASH_ADDR + ATTEST_CIPHER_OFFSET, (uint32_t*)flash_status.cipher_attest_data, CIPHER_ATTESTATION_DATA_LEN);
}

/**
 * @brief Retrieves encrypted boot message from flash memory.
 * 
 * This function reads encrypted boot message from the specified flash address
 * and stores it in the global `flash_status.cipher_boot_text` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_boot_cipher() {
    flash_simple_read(FLASH_ADDR + CIPHER_BOOT_TEXT_OFFSET, (uint32_t*)flash_status.cipher_boot_text, BOOT_MSG_CIPHER_TEXT_SIZE);
}

// write current value in flast_status to the flash memory
// for defense/normal mode for the current design
#define WRITE_FLASH_MEMORY  \
    retrive_ap_pub_key();   \
    retrive_cp_priv_key();  \
    retrive_attest_cipher();    \
    retrive_boot_cipher();    \
    flash_simple_erase_page(FLASH_ADDR);    \
    flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));  \
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));  \
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));    \
    crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));  \
    crypto_wipe(flash_status.cipher_boot_text, BOOT_MSG_CIPHER_TEXT_SIZE);


/***************************** UTILITY FUNCTIONS ******************************/
/** 
 * Convert an uint32_t to an array of uint8_t
 * @param buf at least 4 elements
 * @param i the uint32_t variable
*/
void convert_32_to_8(uint8_t *buf, uint32_t i) {
    if (!buf)
        return;
    buf[0] = i & 0xff;
    buf[1] = (i >> 8) & 0xff;
    buf[2] = (i >> 16) & 0xff;
    buf[3] = (i >> 24) & 0xff;
}

/**
 * compare an integer @param i with the array of uint8_t array @param buf (4 elements)
 * @return 0 if they are the same
*/
int compare_32_and_8(uint8_t *buf, uint32_t i) {
    uint8_t tarray[4] = {0};
    convert_32_to_8(tarray, i);
    if (tarray[0] - buf[0] == 0) {
        if (tarray[1] - buf[1] == 0) {
            if (tarray[2] - buf[2] == 0) {
                if (tarray[3] - buf[3] == 0) {
                    return 0;
                }
            }
        }
    }

    return -1;
}

/**
 * When the system detects a possible attack, go to the defense mode
 * delay 4 seconds
*/
void defense_mode() {
    __disable_irq();
    flash_status.mode = SYS_MODE_DEFENSE;
    WRITE_FLASH_MEMORY;
    MXC_Delay(4000000); // 4 seconds
    flash_status.mode = SYS_MODE_NORMAL;
    WRITE_FLASH_MEMORY;
    __enable_irq();
}

/**
 * Set the system to defense mode, but do not delay
*/
void enable_defense_bit() {
    flash_status.mode = SYS_MODE_DEFENSE;
    WRITE_FLASH_MEMORY;
    MXC_Delay(500000);
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {
    MXC_Delay(10);

    // check the message length
    if (len > MAX_I2C_MESSAGE_LEN) {
        return;
    }

    // define variables
    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
    volatile int result = ERROR_RETURN;

    // receive AP's packet of the `reading` command and nonce
    result = wait_and_receive_packet(receiving_buf);
    if (result <= 0 || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_CP_TO_AP) {
        return;
    }

    MXC_Delay(50);

    // plain text for the message signature (in general_buf_2)
    general_buf_2[0] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;         // cmd label
    general_buf_2[1] = COMPONENT_ADDRESS;                       // component address
    memcpy(general_buf_2 + 2, receiving_buf + 1, NONCE_SIZE);   // nonce
    memcpy(general_buf_2 + 2 + NONCE_SIZE, buffer, len);        // plain message

    // calculate the auth and msg singatures and construct the sneding packet (sign(auth), sign(msg), msg)
    retrive_cp_priv_key();
    crypto_eddsa_sign(sending_buf, flash_status.cp_priv_key, general_buf_2, NONCE_SIZE + 2 + len); // msg sign
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
    memcpy(sending_buf + SIGNATURE_SIZE, buffer, len);      // plain message

    // send the packet (sign(auth), sign(msg), msg)
    send_packet_and_ack(SIGNATURE_SIZE + len, sending_buf);

    // clear the buffers
    crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(sending_buf, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(general_buf_2, MAX_I2C_MESSAGE_LEN + 1);
    
    MXC_Delay(500);
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
    // return wait_and_receive_packet(buffer);

    MXC_Delay(50);

    // define variables
    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    volatile int result = ERROR_RETURN;

    // receive AP's packet (cmd label)
    result = wait_and_receive_packet(receiving_buf);
    if (result != sizeof(uint8_t) || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_AP_TO_CP) {
        return result;
    }

    // construct the sending packet, generate a challenge (nonce)
    rng_get_bytes(sending_buf, NONCE_SIZE);

    MXC_Delay(50);

    // send the challenge packet
    send_packet_and_ack(NONCE_SIZE, sending_buf);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG_VAL_20);

    MXC_Delay(50);

    // receive sign(p,nonce,address) + sign(msg) + msg
    result = wait_and_receive_packet(receiving_buf);
    cancel_continuous_timer();
    if (result <= 0) {
        return result;
    }

    // plain message length
    volatile int len = result - SIGNATURE_SIZE;
    if (len <= 0 || len > MAX_POST_BOOT_MSG_LEN) {
        return 0;
    }

    // construct the plain text for verifying the message signature (in general_buf)
    general_buf[0] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;               // cmd_label
    general_buf[1] = COMPONENT_ADDRESS;                             // CP address
    memcpy(general_buf + 2, sending_buf, NONCE_SIZE);               // nonce
    memcpy(general_buf + 2 + NONCE_SIZE, receiving_buf + SIGNATURE_SIZE, len);  // plain message

    // calculate the msg signature and verify
    retrive_ap_pub_key();
    EXPR_EXECUTE(crypto_eddsa_check(receiving_buf , flash_status.ap_pub_key, general_buf, NONCE_SIZE + 2 + len), ERR_VALUE);
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    EXPR_CHECK(ERR_VALUE);
    RANDOM_DELAY_TINY;
    if (if_val_2 != 0) {
        defense_mode();
        return 0;
    }
    RANDOM_DELAY_TINY;
    if (if_val_2 != 0) {
        panic();
        return 0;
    }
    memcpy(buffer, receiving_buf + SIGNATURE_SIZE, len);
    
    MXC_Delay(500);
    return len;
}

/******************************* FUNCTION DEFINITIONS *********************************/



// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) global_buffer_recv;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        defense_mode();
        break;
    }
}

void process_boot() {

    MXC_Delay(200);

    // define variables
    uint32_t component_id = COMPONENT_ID;       // component ID
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    volatile int result = ERROR_RETURN;

    // receive the `boot` command and nonce from the AP (already in the global_buffer_recv)
    // global_buffer_recv already has the data
    // check the cmd label
    packet_boot_1_ap_to_cp *pkt_receive_1 = (packet_boot_1_ap_to_cp *) global_buffer_recv;
    if (pkt_receive_1->cmd_label != COMPONENT_CMD_BOOT) {
        return;
    }

    // check the component ID
    EXPR_EXECUTE_CHECK(compare_32_and_8(pkt_receive_1->id, component_id), ERROR_RETURN);
    if (if_val_2 != 0) {
        // ID check failure
        defense_mode();
        return;
    }
    RANDOM_DELAY_TINY;
    if (if_val_2 != 0) {
        // ID check failure
        panic();
        return;
    }
    // ID check ok

    MXC_Delay(50);

    // the whole sending packet (sign(p, nonce, address), nonce)
    packet_boot_1_cp_to_ap *pkt_send_1 = (packet_boot_1_cp_to_ap *) transmit_buffer;

    // construct the plain text of the auth signature (in general_buf)
    packet_plain_with_id *plain_auth = (packet_plain_with_id *) general_buf;
    plain_auth->cmd_label = COMPONENT_CMD_BOOT;
    convert_32_to_8(plain_auth->id, component_id);
    memcpy(plain_auth->nonce, pkt_receive_1->nonce, NONCE_SIZE);

    // construct the sending packet
    // sign the AP's nonce
    retrive_cp_priv_key();
    crypto_eddsa_sign(pkt_send_1->sig_auth, flash_status.cp_priv_key, global_buffer_recv, NONCE_SIZE + 5);
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
    // generate a nonce
    rng_get_bytes(pkt_send_1->nonce, NONCE_SIZE);

    // send
    send_packet_and_ack(SIGNATURE_SIZE + NONCE_SIZE, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG_VAL_20);

    // receive the response
    MXC_Delay(50);
    result = wait_and_receive_packet(global_buffer_recv);
    cancel_continuous_timer();
    if (result <= 0) {
        return;
    }

    // construct the plaintext for verifying the auth signature
    packet_plain_with_id *plain_auth_2 = (packet_plain_with_id *) general_buf;
    plain_auth_2->cmd_label = COMPONENT_CMD_BOOT_2;
    convert_32_to_8(plain_auth_2->id, component_id);
    memcpy(plain_auth_2->nonce, pkt_send_1->nonce, NONCE_SIZE);

    // verify the auth signature
    retrive_ap_pub_key();
    EXPR_EXECUTE(crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 5), ERR_VALUE);
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    EXPR_CHECK(ERR_VALUE);
    if (if_val_2 != 0) {
        // verification failure
        defense_mode();
        return;
    }
    RANDOM_DELAY_TINY;
    if (if_val_2 != 0) {
        // verification failure
        panic();
        return;
    }

    // verification passes
    MXC_Delay(50);

    // respond with the encrypted cp boot message
    retrive_boot_cipher();
    memcpy((void*)transmit_buffer, flash_status.cipher_boot_text, BOOT_MSG_CIPHER_TEXT_SIZE);
    send_packet_and_ack(BOOT_MSG_CIPHER_TEXT_SIZE, transmit_buffer);
    MXC_Delay(30);
    crypto_wipe(flash_status.cipher_boot_text, BOOT_MSG_CIPHER_TEXT_SIZE);

    // clear buffers
    crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(transmit_buffer, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(general_buf, MAX_I2C_MESSAGE_LEN + 1);

    MXC_Delay(50);

    // Boot
    #ifdef POST_BOOT
        POST_BOOT
    #else

    while (1) {

    }
    #endif
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_attest() {
    // defeine variables
    uint8_t general_buffer[MAX_I2C_MESSAGE_LEN + 1];

    // generate a challenge (nonce)
    rng_get_bytes(transmit_buffer, NONCE_SIZE);

    // send nonce
    send_packet_and_ack(NONCE_SIZE, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG_VAL_20);

    // receive the response sign(p, nonce, id)
    volatile uint8_t len = wait_and_receive_packet(global_buffer_recv);
    cancel_continuous_timer();
    if (len != SIGNATURE_SIZE) {
        return;
    }

    // construct the plain text for verifying the auth signature (in general_buffer)
    uint32_t component_id = COMPONENT_ID;
    packet_plain_with_id *plain_auth = (packet_plain_with_id *) general_buffer;
    plain_auth->cmd_label = COMPONENT_CMD_ATTEST;
    memcpy(plain_auth->nonce, transmit_buffer, NONCE_SIZE);
    convert_32_to_8(plain_auth->id, component_id);

    MXC_Delay(50);

    // verify
    retrive_ap_pub_key();
    EXPR_EXECUTE(crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buffer, NONCE_SIZE + 5), ERR_VALUE);
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    EXPR_CHECK(ERR_VALUE);
    RANDOM_DELAY_TINY;
    if (if_val_2 != 0) {
        defense_mode();
        return;
    }
    RANDOM_DELAY_TINY;
    if (if_val_2 != 0) {
        panic();
        return;
    }
    
    // verification passed
    // retrive encrypted attest data and send
    retrive_attest_cipher();
    memcpy(transmit_buffer, flash_status.cipher_attest_data, CIPHER_ATTESTATION_DATA_LEN);
    send_packet_and_ack(CIPHER_ATTESTATION_DATA_LEN, transmit_buffer);
    // wipe cipher text
    crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));
    
    // wipe buffers
    crypto_wipe(transmit_buffer, sizeof(transmit_buffer));
    crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(general_buffer, MAX_I2C_MESSAGE_LEN + 1);
}

void init() {
    // Initialize the MPU
    mpu_init();

    // Enable Global Interrupts
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.mode = SYS_MODE_NORMAL;

        uint8_t cp_private_key[] = {CP_PRIVATE_KEY};
        uint8_t ap_public_key[] = {AP_PUBLIC_KEY};
        uint8_t attest_cipher[] = {ATTESTATION_CIPHER_DATA};
        uint8_t boot_cipher[] = {CIPHER_CP_BOOT_MSG};
        memcpy(flash_status.cp_priv_key, cp_private_key, PRIV_KEY_SIZE);
        memcpy(flash_status.ap_pub_key, ap_public_key, PUB_KEY_SIZE);
        memcpy(flash_status.cipher_attest_data, attest_cipher, CIPHER_ATTESTATION_DATA_LEN);
        memcpy(flash_status.cipher_boot_text, boot_cipher, BOOT_MSG_CIPHER_TEXT_SIZE);

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

        crypto_wipe(cp_private_key, sizeof(cp_private_key));
        crypto_wipe(ap_public_key, sizeof(ap_public_key));
        crypto_wipe(attest_cipher, sizeof(attest_cipher));
        crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
        crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
        crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));
        crypto_wipe(flash_status.cipher_boot_text, BOOT_MSG_CIPHER_TEXT_SIZE);
    }

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    if (board_link_init(addr) != E_NO_ERROR) {
        panic();
    }

    // Initialize TRNG
    if (rng_init() != E_NO_ERROR) {
        panic();
    }

    // check if the system status is defense mode
    if (flash_status.mode != SYS_MODE_NORMAL) {
        defense_mode();
    }
}

/*********************************** MAIN *************************************/

int main(void) {
    init();

    MXC_Delay(500000);

    while (1) {
        wait_and_receive_packet(global_buffer_recv);
        component_process_cmd();
    }
}
