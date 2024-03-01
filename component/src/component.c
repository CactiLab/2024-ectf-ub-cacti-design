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
#define COMPONENT_ID_SIZE       4

#define print_info(...) printf("%%info: "); printf(__VA_ARGS__); printf("%%"); fflush(stdout)
#define print_hex_info(...) printf("%%info: "); print_hex(__VA_ARGS__); printf("%%"); fflush(stdout)

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

typedef struct __attribute__((packed)) {
    uint8_t cmd_label;
    uint8_t nonce[NONCE_SIZE];
    uint8_t id[4];
} packet_plain_with_id;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

typedef struct __attribute__((packed)) {
    uint8_t cmd_label;
    uint8_t nonce[NONCE_SIZE];
    uint8_t id[COMPONENT_ID_SIZE];
} packet_boot_1_ap_to_cp;

typedef struct __attribute__((packed)) {
    uint8_t sig_auth[SIGNATURE_SIZE];
    uint8_t nonce[NONCE_SIZE];
} packet_boot_1_cp_to_ap;

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
    __disable_irq();
    cancel_continuous_timer();
    flash_status.mode = SYS_MODE_DEFENSE;
    WRITE_FLASH_MEMORY;
    MXC_Delay(4000000); // 4 seconds
    flash_status.mode = SYS_MODE_NORMAL;
    WRITE_FLASH_MEMORY;
    __enable_irq();
    // LED_Off(LED1);
}

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
    int r = 0;
    r += (tarray[0] - buf[0]);
    r += (tarray[1] - buf[1]);
    r += (tarray[2] - buf[2]);
    r += (tarray[3] - buf[3]);
    return r;
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

#define print_debug(...) printf("%%debug: "); printf(__VA_ARGS__); printf("%%"); fflush(stdout)
#define print_hex_info(...) printf("%%info: "); print_hex(__VA_ARGS__); printf("%%"); fflush(stdout)
#define print_hex_debug(...) printf("%%debug: "); print_hex(__VA_ARGS__); printf("%%"); fflush(stdout)

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
    print_info("cpsend - start\n");
    print_hex_info(buffer, len);
    MXC_Delay(10);

    // check the message length
    if (len > MAX_I2C_MESSAGE_LEN) {
        print_info("cpsend - 1\n");
        panic();
        return;
    }

    // define variables
    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;

    // receive AP's packet of the `reading` command and nonce
    result = wait_and_receive_packet(receiving_buf);
    if (result <= 0 || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_CP_TO_AP) {
        // crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);
        panic();
        print_info("cpsend - 2\n");
        return;
    }

    MXC_Delay(50);

    // plain text for the authentication signature (in general_buf)
    memcpy(general_buf, receiving_buf + 1, NONCE_SIZE);
    general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    general_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;

    // plain text for the message signature (in general_buf_2)
    general_buf_2[0] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    general_buf_2[1] = COMPONENT_ADDRESS;
    memcpy(general_buf_2 + 2, receiving_buf + 1, NONCE_SIZE);
    memcpy(general_buf_2 + 2 + NONCE_SIZE, buffer, len);

    // calculate the auth and msg singatures and construct the sneding packet (sign(auth), sign(msg), msg)
    retrive_cp_priv_key();
    crypto_eddsa_sign(sending_buf, flash_status.cp_priv_key, general_buf, NONCE_SIZE + 2);
    crypto_eddsa_sign(sending_buf + SIGNATURE_SIZE, flash_status.cp_priv_key, general_buf_2, NONCE_SIZE + 2 + len);
    crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
    memcpy(sending_buf + SIGNATURE_SIZE * 2, buffer, len);

    // send the packet (sign(auth), sign(msg), msg)
    send_packet_and_ack(SIGNATURE_SIZE * 2 + len, sending_buf);

    // clear the buffers
    // crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(sending_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(general_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(general_buf_2, MAX_I2C_MESSAGE_LEN + 1);
    
    MXC_Delay(200);
    print_info("cpsend - End\n");
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

    // define variables
    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;

    // receive AP's packet (cmd label)
    result = wait_and_receive_packet(receiving_buf);
    if (result != sizeof(uint8_t) || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_AP_TO_CP) {
        // crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);
        // panic();
        return result;
    }

    // construct the sending packet, generate a challenge (nonce)
    rng_get_bytes(sending_buf, NONCE_SIZE);

    MXC_Delay(50);

    // send the challenge packet
    send_packet_and_ack(NONCE_SIZE, sending_buf);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // receive sign(p,nonce,address) + sign(msg) + msg
    MXC_Delay(50);
    result = wait_and_receive_packet(receiving_buf);
    cancel_continuous_timer();
    if (result <= 0) {
        // crypto_wipe(sending_buf, MAX_I2C_MESSAGE_LEN + 1);
        // crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);
        // panic();
        return result;
    }

    // construct the plain text for verifying the authentication signature (in sending_buf)
    int len = result - SIGNATURE_SIZE * 2;      // plain message length
    sending_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    sending_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;

    // construct the plain text for verifying the message signature (in general_buf)
    general_buf[0] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    general_buf[1] = COMPONENT_ADDRESS;
    memcpy(general_buf + 2, sending_buf, NONCE_SIZE);
    memcpy(general_buf + 2 + NONCE_SIZE, receiving_buf + SIGNATURE_SIZE * 2, len);

    // calculate the auth and msg signatures and verify
    retrive_ap_pub_key();
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(receiving_buf, flash_status.ap_pub_key, sending_buf, NONCE_SIZE + 2), 0, ERR_VALUE);
    // verification failed - auth
    // crypto_wipe(general_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(sending_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);
    defense_mode();
    return 0;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // verification passed - auth

    CONDITION_NEQ_BRANCH(crypto_eddsa_check(receiving_buf + SIGNATURE_SIZE, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 2 + len), 0, ERR_VALUE);
    // verification failed - msg
    // crypto_wipe(general_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(sending_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);
    defense_mode();
    return 0;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // verification passed - msg

    // wipe
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));

    // clear the buffers
    // crypto_wipe(general_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(sending_buf, MAX_I2C_MESSAGE_LEN + 1);
    // crypto_wipe(receiving_buf, MAX_I2C_MESSAGE_LEN + 1);

    // save the plain message
    memcpy(buffer, receiving_buf + SIGNATURE_SIZE * 2, len);

    MXC_Delay(500);
    return len;
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
// /**
//  * @brief Secure Send 
//  * 
//  * @param buffer: uint8_t*, pointer to data to be send
//  * @param len: uint8_t, size of data to be sent 
//  * 
//  * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
//  * This function must be implemented by your team to align with the security requirements.
// */
// void secure_send_1(uint8_t* buffer, uint8_t len) {
//     MXC_Delay(50);

//     print_debug("cpsend - start, address=%x, id=%x, len=%d, buffer = \n", COMPONENT_ADDRESS, COMPONENT_ID, len);
//     print_hex_debug(buffer, len);

//     if (len > MAX_I2C_MESSAGE_LEN) {
//         print_debug("cpsend - 1 - len check failed, len = %d\n", len);
//         panic();
//     }
//     uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     int recv_len = ERROR_RETURN;

//     // printf("secure_send 1\n");

//     // receive the `reading` command and nonce
//     recv_len = wait_and_receive_packet(receiving_buf);
//     packet_read_msg *pkt_recv = (packet_read_msg *)receiving_buf;
//     if (recv_len <= 0 || pkt_recv->cmd_label != COMPONENT_CMD_MSG_FROM_CP_TO_AP) {
//         print_debug("cpsend - 2 - receive cmd failed, len=%d, receiving_buf[0]=%x\n", recv_len, receiving_buf[0]);
//         panic();
//         return;
//     }
//     print_debug("cpsend - 3 - receive cmd succeed, len=%d, receiving_buf = \n", recv_len);
//     print_hex_debug(receiving_buf, recv_len);

//     // construct the plain text for auth signature
//     packet_plain_with_addr *plain_auth = (packet_plain_with_addr *) general_buf;
//     plain_auth->address = COMPONENT_ADDRESS;
//     plain_auth->cmd_label = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
//     memcpy(plain_auth->nonce, pkt_recv->nonce, NONCE_SIZE);
//     print_debug("cpsend - 4 - general_buf = \n");
//     print_hex_debug(general_buf, NONCE_SIZE + 2);

//     // construct the plain text for msg signature
//     packet_plain_msg *plain_msg = (packet_plain_msg *) general_buf_2;
//     plain_msg->address = COMPONENT_ADDRESS;
//     plain_msg->cmd_label = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
//     memcpy(plain_msg->msg, buffer, len);
//     memcpy(plain_msg->nonce, pkt_recv->nonce, NONCE_SIZE);
//     print_debug("cpsend - 5 - general_buf_2 = \n");
//     print_hex_debug(general_buf_2, NONCE_SIZE + 2 + len);

//     // the whole sending pakcet buffer
//     packet_sign_sign_msg *pkt_send = (packet_sign_sign_msg *) sending_buf;
//     memcpy(pkt_send->msg, buffer, len);

//     MXC_Delay(50);

//     // sign (2 signatures)
//     // memcpy(general_buf, receiving_buf + 1, NONCE_SIZE);
//     // general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
//     // general_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
//     retrive_cp_priv_key();
//     // crypto_eddsa_sign(sending_buf, flash_status.cp_priv_key, general_buf, NONCE_SIZE + 2);
//     // crypto_eddsa_sign(sending_buf + SIGNATURE_SIZE, flash_status.cp_priv_key, buffer, len);
//     crypto_eddsa_sign(pkt_send->sig_auth, flash_status.cp_priv_key, general_buf, NONCE_SIZE + 2);
//     crypto_eddsa_sign(pkt_send->sig_msg, flash_status.cp_priv_key, general_buf_2, NONCE_SIZE + 2 + len);
//     crypto_wipe(flash_status.cp_priv_key, sizeof(flash_status.cp_priv_key));
//     // memcpy(sending_buf + SIGNATURE_SIZE * 2, buffer, len);
//     send_packet_and_ack(SIGNATURE_SIZE * 2 + len, sending_buf);
//     print_debug("cpsend - 6 - Everything's fine, sending_buf = \n");
//     print_hex_debug(sending_buf, SIGNATURE_SIZE * 2 + len);
    
//     // printf("general_buf\n");
//     // print_hex(general_buf, NONCE_SIZE + 2);
//     // printf("general_buf_2\n");
//     // print_hex(general_buf_2, NONCE_SIZE + 2 + len);
//     // printf("sending_buf\n");
//     // print_hex(sending_buf, SIGNATURE_SIZE * 2 + len);
//     // printf("receiving_buf\n");
//     // print_hex(receiving_buf, NONCE_SIZE + 1);

//     MXC_Delay(300);
// }

// /**
//  * @brief Secure Receive
//  * 
//  * @param buffer: uint8_t*, pointer to buffer to receive data to
//  * 
//  * @return int: number of bytes received, negative if error
//  * 
//  * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
//  * This function must be implemented by your team to align with the security requirements.
// */
// int secure_receive_1(uint8_t* buffer) {
//     MXC_Delay(50);

//     print_debug("cprecv - start, id=%x, address=%x\n", COMPONENT_ID, COMPONENT_ADDRESS);

//     uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
//     int receive_len = ERROR_RETURN;

//     // receive the `sending command`
//     receive_len = wait_and_receive_packet(receiving_buf);
//     if (receive_len != sizeof(uint8_t) || receiving_buf[0] != COMPONENT_CMD_MSG_FROM_AP_TO_CP) {
//         print_debug("cprecv - 1 - receive 1 wrong, len=%d, receiving_buf[0]=%x\n", receive_len, receiving_buf[0]);
//         defense_mode();
//         return receive_len;
//     }
//     print_debug("cprecv - 2 - receive 1 ok, len=%d, receiving_buf[0]=%x\n", receive_len, receiving_buf[0]);
    
//     // generate a challenge (nonce)
//     rng_get_bytes(sending_buf, NONCE_SIZE);
//     // send the challenge
//     MXC_Delay(50);
//     send_packet_and_ack(NONCE_SIZE, sending_buf);
//     start_continuous_timer(TIMER_LIMIT_I2C_MSG_2);
//     print_debug("cprecv - 3 - sent nonce, sending_buf = \n");
//     print_hex_debug(sending_buf, NONCE_SIZE);

//     // receive sign(p,nonce,address) + sign(msg) + msg
//     MXC_Delay(50);
//     receive_len = wait_and_receive_packet(receiving_buf);
//     cancel_continuous_timer();
//     if (receive_len <= 0) {
//         print_debug("cprecv - 4 - receive response failed, len=%d\n", receive_len);
//         return receive_len;
//     }
//     print_debug("cprecv - 5 - receive response succeed, len=%d, receiving_buf = \n", receive_len);
//     print_hex_debug(receiving_buf, receive_len);
//     packet_sign_sign_msg *pkt_receive = (packet_sign_sign_msg *) receiving_buf;
//     int len = receive_len - SIGNATURE_SIZE * 2;         // message length
//     // printf("receiving_buf, len=%d\n", receive_len);
//     // print_hex(receiving_buf, receive_len);

//     // construct the plain text for the auth signature
//     packet_plain_with_addr *plain_auth = (packet_plain_with_addr *) general_buf;
//     plain_auth->address = COMPONENT_ADDRESS;
//     plain_auth->cmd_label = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
//     memcpy(plain_auth->nonce, sending_buf, NONCE_SIZE);
//     print_debug("cprecv - 6 - general_buf = \n");
//     print_hex_debug(general_buf, NONCE_SIZE + 2);

//     // construct the plain text for the msg signature
//     packet_plain_msg *plain_msg = (packet_plain_msg *) general_buf_2;
//     plain_msg->address = COMPONENT_ADDRESS;
//     plain_msg->cmd_label = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
//     memcpy(plain_msg->nonce, sending_buf, NONCE_SIZE);
//     memcpy(plain_msg->msg, pkt_receive->msg, len);
//     // printf("1\n");
//     print_debug("cprecv - 7 - general_buf_2 = \n");
//     print_hex_debug(general_buf_2, NONCE_SIZE + 2 + len);
    
//     // sending_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
//     // sending_buf[NONCE_SIZE + 1] = COMPONENT_ADDRESS;
//     retrive_ap_pub_key();

//     CONDITION_NEQ_BRANCH(crypto_eddsa_check(pkt_receive->sig_auth, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 2), 0, ERR_VALUE);
//     print_debug("cprecv - 8 - check auth fail = \n");
//     crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
//     defense_mode();
//     return 0;
//     CONDITION_BRANCH_ENDING(ERR_VALUE);
//     print_debug("cprecv - 9 - check auth succeed = \n");

//     // printf("2\n");
//     CONDITION_NEQ_BRANCH(crypto_eddsa_check(pkt_receive->sig_msg, flash_status.ap_pub_key, general_buf_2, NONCE_SIZE + 2 + len), 0, ERR_VALUE);
//     print_debug("cprecv - 10 - check msg fail = \n");
//     crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
//     defense_mode();
//     return 0;
//     CONDITION_BRANCH_ENDING(ERR_VALUE);
//     print_debug("cprecv - 10 - check msg succeed = \n");

//     // printf("3\n");
//     // }
//     crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
//     memcpy(buffer, receiving_buf + SIGNATURE_SIZE * 2, len);
//     print_debug("cprecv - 11 - Ev;eryting's fine, len=%d, buffer = %s\n", len, buffer);
//     print_hex_debug(buffer, len);
//     // printf("4\n");
//     // printf("general_buf\n");
//     // print_hex(general_buf, NONCE_SIZE + 2);
//     // printf("general_buf_2\n");
//     // print_hex(general_buf_2, NONCE_SIZE + 2 + len);

//     MXC_Delay(300);
//     return len;
// }

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
    // printf("buffer=%s\n", buffer);
    // print_hex(buffer, r);

    // test 2
    // printf("starting test 2 post-boot\n");
    // uint8_t buffer[] = "ectf{testing_1afa95d5de6bea59}";
    // // uint8_t buffer[1] = {0};
    // secure_send(buffer, sizeof(buffer));

    // test 3
    // uint8_t buffer1[256];
    // uint8_t buffer2[] = "I love you.";
    // secure_receive(buffer1);
    // secure_send(buffer2, sizeof(buffer2));

    // test 4
    // uint8_t buffer1[256];
    // uint8_t buffer2[] = "ectf{testing_1afa95d5de6bea59}";
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

void process_boot() {
    MXC_Delay(200);

    // define variables
    uint32_t component_id = COMPONENT_ID;       // component ID
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;

    // receive the `boot` command and nonce from the AP (already in the global_buffer_recv)
    // global_buffer_recv already has the data
    // check the cmd label
    packet_boot_1_ap_to_cp *pkt_receive_1 = (packet_boot_1_ap_to_cp *) global_buffer_recv;
    if (pkt_receive_1->cmd_label != COMPONENT_CMD_BOOT) {
        crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
        defense_mode();
        return;
    }

    // check the component ID
    CONDITION_NEQ_BRANCH(compare_32_and_8(pkt_receive_1->id, component_id), 0, ERR_VALUE);
    // ID check failure
    crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
    defense_mode();
    return;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // ID check ok

    MXC_Delay(50);

    // the whole sending packet
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
    start_continuous_timer(TIMER_LIMIT_I2C_MSG_3);

    // receive the response
    MXC_Delay(50);
    result = wait_and_receive_packet(global_buffer_recv);
    cancel_continuous_timer();
    if (result <= 0) {
        crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
        crypto_wipe(transmit_buffer, MAX_I2C_MESSAGE_LEN + 1);
        crypto_wipe(general_buf, MAX_I2C_MESSAGE_LEN + 1);
        panic();
        return;
    }

    // construct the plaintext for verifying the auth signature
    packet_plain_with_id *plain_auth_2 = (packet_plain_with_id *) general_buf;
    plain_auth_2->cmd_label = COMPONENT_CMD_BOOT_2;
    convert_32_to_8(plain_auth_2->id, component_id);
    memcpy(plain_auth_2->nonce, pkt_send_1->nonce, NONCE_SIZE);

    // verify the auth signature
    retrive_ap_pub_key();
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buf, NONCE_SIZE + 5), 0, ERR_VALUE);
    // verification failure
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    defense_mode();
    return;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // verification passes

    // wipe
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));

    MXC_Delay(50);

    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    send_packet_and_ack(len, transmit_buffer);

    // clear buffers
    crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(transmit_buffer, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(general_buf, MAX_I2C_MESSAGE_LEN + 1);

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
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        defense_mode();
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
    // defeine variables
    uint8_t general_buffer[MAX_I2C_MESSAGE_LEN + 1];

    // generate a challenge (nonce)
    rng_get_bytes(transmit_buffer, NONCE_SIZE);

    // send nonce
    send_packet_and_ack(NONCE_SIZE, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // receive the response sign(p, nonce, id)
    uint8_t len = wait_and_receive_packet(global_buffer_recv);
    cancel_continuous_timer();
    if (len != SIGNATURE_SIZE) {
        crypto_wipe(transmit_buffer, MAX_I2C_MESSAGE_LEN + 1);
        crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
        panic();
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
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(global_buffer_recv, flash_status.ap_pub_key, general_buffer, NONCE_SIZE + 5), 0, ERR_VALUE);
    // verification failed
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));
    crypto_wipe(transmit_buffer, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(general_buffer, MAX_I2C_MESSAGE_LEN + 1);
    defense_mode();
    return;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // verification passed

    // wipe
    crypto_wipe(flash_status.ap_pub_key, sizeof(flash_status.ap_pub_key));

    // retrive encrypted attest data and send
    retrive_attest_cipher();
    memcpy(transmit_buffer, flash_status.cipher_attest_data, CIPHER_ATTESTATION_DATA_LEN);
    send_packet_and_ack(CIPHER_ATTESTATION_DATA_LEN, transmit_buffer);
    crypto_wipe(flash_status.cipher_attest_data, sizeof(flash_status.cipher_attest_data));
    crypto_wipe(transmit_buffer, sizeof(transmit_buffer));
    crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
    crypto_wipe(general_buffer, MAX_I2C_MESSAGE_LEN + 1);
}

/*********************************** MAIN *************************************/

int main(void) {
    // Initialize board
    init();

    printf("Component Started\n");

    while (1) {
        wait_and_receive_packet(global_buffer_recv);

        component_process_cmd();
        crypto_wipe(global_buffer_recv, MAX_I2C_MESSAGE_LEN + 1);
    }
}
