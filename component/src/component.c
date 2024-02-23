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
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "syscalls.h"
#include "common.h"
#include "simple_i2c_peripheral.h"
#include "board_link.h"
#include "simple_flash.h"

#include "monocypher.h"

#include "timer.h"

// Includes from containerized build
#include "ectf_params.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

extern int timer_count_limit;

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

/******************************** TYPE DEFINITIONS ********************************/
#define PRIV_KEY_SIZE 64
#define PUB_KEY_SIZE 32
#define CP_PRIV_KEY_OFFSET offsetof(flash_entry, cp_priv_key)
#define AP_PUB_KEY_OFFSET offsetof(flash_entry, ap_pub_key)
#define ATTEST_CIPHER_OFFSET offsetof(flash_entry, cipher_attest_data)
#define NONCE_SIZE 64
#define SIGNATURE_SIZE 64
#define MAX_POST_BOOT_MSG_LEN 64
#define CIPHER_ATTESTATION_DATA_LEN 243
#define CIPHER_ATTESTATION_DATA_LEN_ROUND 244

// system mode
typedef enum {
    SYS_MODE_NORMAL,
    SYS_MODE_DEFENSE
} system_modes;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint8_t cp_priv_key[PRIV_KEY_SIZE];
    uint8_t ap_pub_key[PUB_KEY_SIZE];
    uint8_t cipher_attest_data[CIPHER_ATTESTATION_DATA_LEN_ROUND];
    uint32_t mode;   // 0: normal, 1: defense
} flash_entry;

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

/******************************** TYPE DEFINITIONS ********************************/
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

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

/********************************* UTILITIES **********************************/

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

#define WRITE_FLASH_MEMORY  \
    retrive_ap_pub_key();   \
    retrive_cp_priv_key();  \
    retrive_attest_cipher();    \
    flash_simple_erase_page(FLASH_ADDR);    \
    flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));  \
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));  \
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));    \
    crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));

/**
 * When the system detects a possible attack, go to the defense mode
 * delay 4 seconds
*/
void defense_mode() {
    // LED_On(LED1);
    cancel_continuous_timer();
    flash_status.mode = SYS_MODE_DEFENSE;
    WRITE_FLASH_MEMORY;
    MXC_Delay(4000000); // 4 seconds
    flash_status.mode = SYS_MODE_NORMAL;
    WRITE_FLASH_MEMORY;
    // LED_Off(LED1);
}

/**
 * @brief Initialize the device.
 * 
 * This function must be called on startup to initialize the flash and i2c interfaces.
 */
void init() {

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        printf("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;

        uint8_t cp_private_key[] = {CP_PRIVATE_KEY};
        uint8_t ap_public_key[] = {AP_PUBLIC_KEY};
        uint8_t attest_cipher[] = {ATTESTATION_CIPHER_DATA};
        memcpy(flash_status.cp_priv_key, cp_private_key, PRIV_KEY_SIZE);
        memcpy(flash_status.ap_pub_key, ap_public_key, PUB_KEY_SIZE);
        memcpy(flash_status.cipher_attest_data, attest_cipher, CIPHER_ATTESTATION_DATA_LEN);

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

        crypto_wipe(cp_private_key, sizeof(cp_private_key));
        crypto_wipe(ap_public_key, sizeof(ap_public_key));
        crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
        crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
        crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));
    }
    
    // Initialize board link interface
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    if (board_link_init(addr) != E_NO_ERROR) {
        panic();
    }

    if(rng_init() != E_NO_ERROR) {
        panic();
    }

    LED_On(LED2);
}

void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
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
    MXC_Delay(50);

    if (len > MAX_I2C_MESSAGE_LEN) {
        panic();
    }
    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;

    // printf("secure_send 1\n");

    // receive reading command and nonce
    result = wait_and_receive_packet(receiving_buf);
    if (result <= 0 || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_CP_TO_AP) {
        return;
    }

    // printf("secure_send 2, receiving_buf=");
    // print_hex(receiving_buf, result);

    // sign nonce and msg
    MXC_Delay(50);
    memcpy(general_buf, receiving_buf + 1, NONCE_SIZE);
    general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    general_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
    retrive_cp_priv_key();
    crypto_eddsa_sign(sending_buf, flash_status.cp_priv_key, general_buf, NONCE_SIZE + 2);
    crypto_eddsa_sign(sending_buf + SIGNATURE_SIZE, flash_status.cp_priv_key, buffer, len);
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
    memcpy(sending_buf + SIGNATURE_SIZE * 2, buffer, len);
    send_packet_and_ack(SIGNATURE_SIZE * 2 + len, sending_buf);
    
    MXC_Delay(500);

    // printf("secure_send 3, sending_buf=");
    // print_hex(sending_buf, SIGNATURE_SIZE * 2 + len);
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
    MXC_Delay(50);

    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;

    // receive sending command
    // printf("securereceive 1\n");
    result = wait_and_receive_packet(receiving_buf);
    if (result != sizeof(uint8_t) || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_AP_TO_CP) {
        return result;
    }
    // printf("securereceive 2, receiving_buf=");
    // print_hex(receiving_buf, result);

    // generate a challenge (nonce)
    rng_get_bytes(sending_buf, NONCE_SIZE);
    // printf("securereceive 2.5, sending_buf=");
    // print_hex(sending_buf, NONCE_SIZE);

    MXC_Delay(50);
    send_packet_and_ack(NONCE_SIZE, sending_buf);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // printf("securereceive 3, sending_buf=");
    // print_hex(sending_buf, NONCE_SIZE);

    // receive sign(p,nonce,address) + sign(msg) + msg
    MXC_Delay(50);
    result = wait_and_receive_packet(receiving_buf);
    cancel_continuous_timer();
    if (result <= 0) {
        return result;
    }

    // printf("securereceive 4, receiving_buf=");
    // print_hex(receiving_buf, result);

    int len = result - SIGNATURE_SIZE * 2;
    sending_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    sending_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
    retrive_ap_pub_key();
    if (crypto_eddsa_check(receiving_buf, flash_status.ap_pub_key, sending_buf, NONCE_SIZE + 2)) {
        defense_mode();
        return 0;
    }
    if (crypto_eddsa_check(receiving_buf + SIGNATURE_SIZE, flash_status.ap_pub_key, receiving_buf + SIGNATURE_SIZE * 2, len)) {
        defense_mode();
        return 0;
    }
    // printf("securereceive 5, ap_pub_key=");
    // print_hex(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    // printf("securereceive 6, s1=");
    // print_hex(receiving_buf, SIGNATURE_SIZE);
    // printf("securereceive 7, s2=");
    // print_hex(receiving_buf + SIGNATURE_SIZE, SIGNATURE_SIZE);
    // printf("securereceive 8, msg=");
    // print_hex(receiving_buf + SIGNATURE_SIZE * 2, len);
    // printf("securereceive 9, len=%d\n", len);
    // crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    // printf("securereceive 10, ap_pub_key=");
    // print_hex(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    // if (r1 != 0 || r2 != 0) {
    //     panic();
    //     return 0;
    // }
    memcpy(buffer, receiving_buf + SIGNATURE_SIZE * 2, len);

    MXC_Delay(500);
    return len;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {
    MXC_Delay(100);
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else

    // test 1
    // printf("starting test 1 post-boot\n");
    // uint8_t buffer[256];
    // int r = secure_receive(buffer);
    // printf("buffer=");
    // print_hex(buffer, r);

    // test 2
    // printf("starting test 2 post-boot\n");
    // uint8_t buffer[] = "I love you.";
    // secure_send(buffer, sizeof(buffer));

    // test 3
    // uint8_t buffer1[256];
    // uint8_t buffer2[] = "I love you.";
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));

    // test 4
    // uint8_t buffer1[256];
    // uint8_t buffer2[] = "I love you.";
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));

    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

void process_boot1() {
    MXC_Delay(200);

    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;

    // receive the `boot` command and nonce from the AP
    if (receive_buffer[0] != COMPONENT_CMD_BOOT || receive_buffer[NONCE_SIZE + 1] != (COMPONENT_ADDRESS)) {
        return;
    }
    MXC_Delay(50);
    // sign the AP's nonce
    retrive_cp_priv_key();
    crypto_eddsa_sign(transmit_buffer, flash_status.cp_priv_key, receive_buffer, NONCE_SIZE + 2);
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
    // generate a nonce
    rng_get_bytes(transmit_buffer + SIGNATURE_SIZE, NONCE_SIZE);
    // send
    send_packet_and_ack(SIGNATURE_SIZE + NONCE_SIZE, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG_3);

    // receive the response and boot
    MXC_Delay(50);
    result = wait_and_receive_packet(receive_buffer);
    cancel_continuous_timer();
    if (result <= 0) {
        return;
    }
    general_buf[0] = COMPONENT_CMD_BOOT_2;
    memcpy(general_buf + 1, transmit_buffer + SIGNATURE_SIZE, NONCE_SIZE);
    general_buf[NONCE_SIZE + 1] = (COMPONENT_ADDRESS);
    retrive_ap_pub_key();
    if (crypto_eddsa_check(receive_buffer, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 2)) {
        crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
        // panic();
        defense_mode();
        return;
    }
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));

    // respond with the boot message
    MXC_Delay(50);
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    send_packet_and_ack(len, transmit_buffer);
    MXC_Delay(50);

    // Call the boot function
    boot();
}

// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot1();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    // case COMPONENT_CMD_VALIDATE:
    //     // process_validate();
    //     break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

// void process_boot() {
//     MXC_Delay(50);
//     // printf("process_boot 1 \n");
//     // The AP requested a boot. Set `component_boot` for the main loop and
//     // respond with the boot message
//     uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
//     memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
//     send_packet_and_ack(len, transmit_buffer);
//     MXC_Delay(50);
//     // printf("process_boot 2 \n");
//     // Call the boot function
//     // printf("before booting\n");
//     boot();
// }

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

// void process_validate() {
//     // The AP requested a validation. Respond with the Component ID
//     validate_message* packet = (validate_message*) transmit_buffer;
//     packet->component_id = COMPONENT_ID;
//     send_packet_and_ack(sizeof(validate_message), transmit_buffer);
// }

void process_attest() {
    uint8_t general_buffer[MAX_I2C_MESSAGE_LEN];

    // generate a challenge (nonce)
    rng_get_bytes(transmit_buffer, NONCE_SIZE);
    send_packet_and_ack(NONCE_SIZE, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // receive the response sign(p, nonce, addr)
    uint8_t len = wait_and_receive_packet(receive_buffer);
    cancel_continuous_timer();
    if (len != SIGNATURE_SIZE) {
        cancel_continuous_timer();
        return;
    }
    general_buffer[0] = COMPONENT_CMD_ATTEST;
    memcpy(general_buffer + 1, transmit_buffer, NONCE_SIZE);
    general_buffer[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
    retrive_ap_pub_key();
    if (crypto_eddsa_check(receive_buffer, flash_status.ap_pub_key, general_buffer, SIGNATURE_SIZE + 2)) {
        crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
        // panic();
        defense_mode();
        return;
    }
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));

    // retrive encrypted attest data
    retrive_attest_cipher();
    memcpy(transmit_buffer, flash_status.cipher_attest_data, CIPHER_ATTESTATION_DATA_LEN);
    send_packet_and_ack(CIPHER_ATTESTATION_DATA_LEN, transmit_buffer);
    crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));
    crypto_wipe(transmit_buffer, sizeof(transmit_buffer));

    // // The AP requested attestation. Respond with the attestation data
    // uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
    //             ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    // send_packet_and_ack(len, transmit_buffer);
}

/*********************************** MAIN *************************************/

int main(void) {
    // Initialize board
    init();

    printf("Component Started\n");

    while (1) {
        wait_and_receive_packet(receive_buffer);

        component_process_cmd();
    }
}
