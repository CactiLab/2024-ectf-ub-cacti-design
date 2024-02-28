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

// glaobal variables
volatile uint8_t if_val_1;
volatile uint8_t if_val_2;

#define ERR_VALUE -15

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
#define PRIV_KEY_SIZE           64
#define PUB_KEY_SIZE            32
#define CP_PRIV_KEY_OFFSET      offsetof(flash_entry, cp_priv_key)
#define AP_PUB_KEY_OFFSET       offsetof(flash_entry, ap_pub_key)
#define ATTEST_CIPHER_OFFSET    offsetof(flash_entry, cipher_attest_data)
#define NONCE_SIZE              64
#define SIGNATURE_SIZE          64
#define MAX_POST_BOOT_MSG_LEN   64
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
uint8_t global_buffer_recv[MAX_I2C_MESSAGE_LEN];
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
    printf("defense\n");
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

typedef struct __attribute__((packed)) {
    uint8_t cmd_label;
    uint8_t nonce[NONCE_SIZE];
    uint8_t address;
} packet_plain_with_addr;

typedef struct __attribute__((packed)) {
    uint8_t cmd_label;
    uint8_t address;
    uint8_t nonce[NONCE_SIZE];
    uint8_t msg[MAX_POST_BOOT_MSG_LEN];
} packet_plain_msg;

typedef struct __attribute__((packed)) {
    uint8_t sig_auth[SIGNATURE_SIZE];
    uint8_t sig_msg[SIGNATURE_SIZE];
    uint8_t msg[MAX_POST_BOOT_MSG_LEN];
} packet_sign_sign_msg;

typedef struct __attribute__((packed)) {
    uint8_t cmd_label;
    uint8_t nonce[NONCE_SIZE];
} packet_read_msg;


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
    uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int recv_len = ERROR_RETURN;

    // printf("secure_send 1\n");

    // receive the `reading` command and nonce
    recv_len = wait_and_receive_packet(receiving_buf);
    packet_read_msg *pkt_recv = (packet_read_msg *)receiving_buf;
    if (recv_len <= 0 || pkt_recv->cmd_label != COMPONENT_CMD_MSG_FROM_CP_TO_AP) {
        return;
    }

    // construct the plain text for auth signature
    packet_plain_with_addr *plain_auth = (packet_plain_with_addr *) general_buf;
    plain_auth->address = COMPONENT_ADDRESS;
    plain_auth->cmd_label = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    memcpy(plain_auth->nonce, pkt_recv->nonce, NONCE_SIZE);

    // construct the plain text for msg signature
    packet_plain_msg *plain_msg = (packet_plain_msg *) general_buf_2;
    plain_msg->address = COMPONENT_ADDRESS;
    plain_msg->cmd_label = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    memcpy(plain_msg->msg, buffer, len);
    memcpy(plain_msg->nonce, pkt_recv->nonce, NONCE_SIZE);

    // the whole sending pakcet buffer
    packet_sign_sign_msg *pkt_send = (packet_sign_sign_msg *) sending_buf;
    memcpy(pkt_send->msg, buffer, len);

    MXC_Delay(50);

    // sign (2 signatures)
    // memcpy(general_buf, receiving_buf + 1, NONCE_SIZE);
    // general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    // general_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
    retrive_cp_priv_key();
    // crypto_eddsa_sign(sending_buf, flash_status.cp_priv_key, general_buf, NONCE_SIZE + 2);
    // crypto_eddsa_sign(sending_buf + SIGNATURE_SIZE, flash_status.cp_priv_key, buffer, len);
    crypto_eddsa_sign(pkt_send->sig_auth, flash_status.cp_priv_key, general_buf, NONCE_SIZE + 2);
    crypto_eddsa_sign(pkt_send->sig_msg, flash_status.cp_priv_key, general_buf_2, NONCE_SIZE + 2 + len);
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
    // memcpy(sending_buf + SIGNATURE_SIZE * 2, buffer, len);
    send_packet_and_ack(SIGNATURE_SIZE * 2 + len, sending_buf);
    
    // printf("general_buf\n");
    // print_hex(general_buf, NONCE_SIZE + 2);
    // printf("general_buf_2\n");
    // print_hex(general_buf_2, NONCE_SIZE + 2 + len);
    // printf("sending_buf\n");
    // print_hex(sending_buf, SIGNATURE_SIZE * 2 + len);
    // printf("receiving_buf\n");
    // print_hex(receiving_buf, NONCE_SIZE + 1);

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
    MXC_Delay(50);

    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int receive_len = ERROR_RETURN;

    // receive the `sending command`
    receive_len = wait_and_receive_packet(receiving_buf);
    if (receive_len != sizeof(uint8_t) || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_AP_TO_CP) {
        defense_mode();
        return receive_len;
    }

    // generate a challenge (nonce)
    rng_get_bytes(sending_buf, NONCE_SIZE);
    // send the challenge
    MXC_Delay(50);
    send_packet_and_ack(NONCE_SIZE, sending_buf);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // receive sign(p,nonce,address) + sign(msg) + msg
    MXC_Delay(50);
    receive_len = wait_and_receive_packet(receiving_buf);
    cancel_continuous_timer();
    if (receive_len <= 0) {
        return receive_len;
    }
    packet_sign_sign_msg *pkt_receive = (packet_sign_sign_msg *) receiving_buf;
    int len = receive_len - SIGNATURE_SIZE * 2;         // message length
    // printf("receiving_buf, len=%d\n", receive_len);
    // print_hex(receiving_buf, receive_len);

    // construct the plain text for the auth signature
    packet_plain_with_addr *plain_auth = (packet_plain_with_addr *) general_buf;
    plain_auth->address = COMPONENT_ADDRESS;
    plain_auth->cmd_label = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    memcpy(plain_auth->nonce, sending_buf, NONCE_SIZE);

    // construct the plain text for the msg signature
    packet_plain_msg *plain_msg = (packet_plain_msg *) general_buf_2;
    plain_msg->address = COMPONENT_ADDRESS;
    plain_msg->cmd_label = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    memcpy(plain_msg->nonce, sending_buf, NONCE_SIZE);
    memcpy(plain_msg->msg, pkt_receive->msg, len);
    // printf("1\n");
    
    // sending_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    // sending_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
    retrive_ap_pub_key();
    // if (crypto_eddsa_check(receiving_buf, flash_status.ap_pub_key, sending_buf, NONCE_SIZE + 2)) {
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(pkt_receive->sig_auth, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 2), 0, ERR_VALUE);
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    defense_mode();
    return 0;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // printf("2\n");
    // }
    // if (crypto_eddsa_check(receiving_buf + SIGNATURE_SIZE, flash_status.ap_pub_key, receiving_buf + SIGNATURE_SIZE * 2, len)) {
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(pkt_receive->sig_msg, flash_status.ap_pub_key, general_buf_2, NONCE_SIZE + 2 + len), 0, ERR_VALUE);
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    defense_mode();
    return 0;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // printf("3\n");
    // }
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    memcpy(buffer, receiving_buf + SIGNATURE_SIZE * 2, len);
    // printf("4\n");
    // printf("general_buf\n");
    // print_hex(general_buf, NONCE_SIZE + 2);
    // printf("general_buf_2\n");
    // print_hex(general_buf_2, NONCE_SIZE + 2 + len);

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
    uint8_t buffer1[256];
    uint8_t buffer2[] = "I love you.";
    secure_receive(buffer1);
    secure_send(buffer2, sizeof(buffer2));

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
    if (global_buffer_recv[0] != COMPONENT_CMD_BOOT || global_buffer_recv[NONCE_SIZE + 1] != (COMPONENT_ADDRESS)) {
        return;
    }
    MXC_Delay(50);
    // sign the AP's nonce
    retrive_cp_priv_key();
    crypto_eddsa_sign(transmit_buffer, flash_status.cp_priv_key, global_buffer_recv, NONCE_SIZE + 2);
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
    // generate a nonce
    rng_get_bytes(transmit_buffer + SIGNATURE_SIZE, NONCE_SIZE);
    // send
    send_packet_and_ack(SIGNATURE_SIZE + NONCE_SIZE, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG_3);

    // receive the response and boot
    MXC_Delay(50);
    result = wait_and_receive_packet(global_buffer_recv);
    cancel_continuous_timer();
    if (result <= 0) {
        return;
    }
    general_buf[0] = COMPONENT_CMD_BOOT_2;
    memcpy(general_buf + 1, transmit_buffer + SIGNATURE_SIZE, NONCE_SIZE);
    general_buf[NONCE_SIZE + 1] = (COMPONENT_ADDRESS);
    retrive_ap_pub_key();
    // if (crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 2)) {
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 2), 0, ERR_VALUE);
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    // panic();
    defense_mode();
    return;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // }
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
    command_message* command = (command_message*) global_buffer_recv;

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
        // TODO: Defense mode
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_attest() {
    uint8_t general_buffer[MAX_I2C_MESSAGE_LEN];

    // generate a challenge (nonce)
    rng_get_bytes(transmit_buffer, NONCE_SIZE);
    send_packet_and_ack(NONCE_SIZE, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // receive the response sign(p, nonce, addr)
    uint8_t len = wait_and_receive_packet(global_buffer_recv);
    cancel_continuous_timer();
    if (len != SIGNATURE_SIZE) {
        cancel_continuous_timer();
        return;
    }
    general_buffer[0] = COMPONENT_CMD_ATTEST;
    memcpy(general_buffer + 1, transmit_buffer, NONCE_SIZE);
    general_buffer[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
    retrive_ap_pub_key();
    // if (crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buffer, SIGNATURE_SIZE + 2)) {
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buffer, SIGNATURE_SIZE + 2), 0, ERR_VALUE);
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    // panic();
    defense_mode();
    return;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // }
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));

    // retrive encrypted attest data
    retrive_attest_cipher();
    memcpy(transmit_buffer, flash_status.cipher_attest_data, CIPHER_ATTESTATION_DATA_LEN);
    send_packet_and_ack(CIPHER_ATTESTATION_DATA_LEN, transmit_buffer);
    crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));
    crypto_wipe(transmit_buffer, sizeof(transmit_buffer));
}

/*********************************** MAIN *************************************/

int main(void) {
    // Initialize board
    init();

    printf("Component Started\n");

    while (1) {
        wait_and_receive_packet(global_buffer_recv);

        component_process_cmd();
    }
}
