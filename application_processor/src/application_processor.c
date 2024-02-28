/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "syscalls.h"
#include "common.h"
#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"

#include "monocypher.h"
#include "timer.h"
extern int timer_count_limit;

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"

// glaobal variables
volatile uint8_t if_val_1;
volatile uint8_t if_val_2;

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
#define ERR_VALUE -15

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

#define PRIV_KEY_SIZE       64
#define PUB_KEY_SIZE        32
#define COMPONENT_IDS_OFFSET    offsetof(flash_entry, component_ids)
#define AP_PRIV_KEY_OFFSET      offsetof(flash_entry, ap_priv_key)
#define CP_PUB_KEY_OFFSET       offsetof(flash_entry, cp_pub_key)
#define HASH_KEY_OFFSET         offsetof(flash_entry, hash_key)
#define HASH_SALT_OFFSET        offsetof(flash_entry, hash_salt)
#define PIN_HASH_OFFSET         offsetof(flash_entry, pin_hash)
#define TOKEN_HASH_OFFSET       offsetof(flash_entry, token_hash)
#define AEAD_KEY_OFFSET         offsetof(flash_entry, aead_key)
#define AEAD_NONCE_OFFSET       offsetof(flash_entry, aead_nonce)
#define NONCE_SIZE              64
#define SIGNATURE_SIZE          64
#define MAX_POST_BOOT_MSG_LEN   64
#define PIN_LEN                 6
#define TOKEN_LEN               16
#define HASH_KEY_LEN            128
#define HASH_SALT_LEN           128
#define NB_BLOCKS_PIN           108
#define NB_BLOCKS_TOKEN         108
#define NB_PASSES               3
#define NB_LANES                1
#define HASH_LEN                64
#define HOST_INPUT_BUF_SIZE     64
// #define CIPHER_ATTESTATION_DATA_LEN 243
#define AEAD_MAC_SIZE           16
#define AEAD_NONCE_SIZE         24
#define AEAD_KEY_SIZE                        32
#define ATT_DATA_MAX_SIZE               64
#define ATT_PADDING_SIZE                    16
#define ATT_FINAL_TEXT_SIZE                 ATT_DATA_MAX_SIZE * 3 + AEAD_MAC_SIZE + 3 + ATT_PADDING_SIZE * 2
#define ATT_PLAIN_TEXT_SIZE                 ATT_DATA_MAX_SIZE * 3 + 3 + ATT_PADDING_SIZE * 2
#define ATT_MAC_POS_IN_FINAL_TEXT           0
#define ATT_CIPHER_POS_IN_FINAL_TEXT        AEAD_MAC_SIZE
#define ATT_LOC_POS                         0
#define ATT_PADDING_1_POS                   ATT_DATA_MAX_SIZE
#define ATT_DATE_POS                        ATT_PADDING_1_POS + ATT_PADDING_SIZE
#define ATT_PADDING_2_POS                   ATT_DATE_POS + ATT_DATA_MAX_SIZE
#define ATT_CUSTOMER_POS                    ATT_PADDING_2_POS + ATT_PADDING_SIZE
#define ATT_LOC_LEN_POS                     ATT_CUSTOMER_POS + ATT_DATA_MAX_SIZE
#define ATT_DATE_LEN_POS                    ATT_LOC_LEN_POS + 1
#define ATT_CUSTOMER_LEN_POS                ATT_DATE_LEN_POS + 1

// system mode
typedef enum {
    SYS_MODE_NORMAL,
    SYS_MODE_DEFENSE
} system_modes;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[8];
    uint8_t ap_priv_key[PRIV_KEY_SIZE];
    uint8_t cp_pub_key[PUB_KEY_SIZE];
    uint8_t hash_key[HASH_KEY_LEN];
    uint8_t hash_salt[HASH_SALT_LEN];
    uint8_t pin_hash[HASH_LEN];
    uint8_t token_hash[HASH_LEN];
    uint8_t aead_key[AEAD_KEY_SIZE];
    uint8_t aead_nonce[AEAD_NONCE_SIZE];
    uint32_t mode;   // 0: normal, 1: defense
} flash_entry;

// Datatype for commands sent to components
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

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

/********************************* UTILITIES **********************************/

/**
 * @brief Retrieves AP's private key from flash memory.
 * 
 * This function reads AP's private key from the specified flash address
 * and stores it in the global `flash_status.ap_priv_key` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_ap_priv_key() {
    flash_simple_read(FLASH_ADDR + AP_PRIV_KEY_OFFSET, (uint32_t*)flash_status.ap_priv_key, PRIV_KEY_SIZE);
}

/**
 * @brief Retrieves CP's public key from flash memory.
 * 
 * This function reads CP's public key from the specified flash address
 * and stores it in the global `flash_status.cp_pub_key` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_cp_pub_key() {
    flash_simple_read(FLASH_ADDR + CP_PUB_KEY_OFFSET, (uint32_t*)flash_status.cp_pub_key, PUB_KEY_SIZE);
}

/**
 * @brief Retrieves hash key from flash memory.
 * 
 * This function reads the hash key from the specified flash address
 * and stores it in the global `flash_status.hash_key` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_hash_key() {
    flash_simple_read(FLASH_ADDR + HASH_KEY_OFFSET, (uint32_t*)flash_status.hash_key, HASH_KEY_LEN);
}

/**
 * @brief Retrieves hash salt from flash memory.
 * 
 * This function reads the hash salt from the specified flash address
 * and stores it in the global `flash_status.hash_salt` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_hash_salt() {
    flash_simple_read(FLASH_ADDR + HASH_SALT_OFFSET, (uint32_t*)flash_status.hash_salt, HASH_SALT_LEN);
}

/**
 * @brief Retrieves pin hash value from flash memory.
 * 
 * This function reads the pin hash value from the specified flash address
 * and stores it in the global `flash_status.pin_hash` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_pin_hash() {
    flash_simple_read(FLASH_ADDR + PIN_HASH_OFFSET, (uint32_t*)flash_status.pin_hash, HASH_LEN);
}

/**
 * @brief Retrieves token hash value from flash memory.
 * 
 * This function reads the token hash value from the specified flash address
 * and stores it in the global `flash_status.pin_token` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_token_hash() {
    flash_simple_read(FLASH_ADDR + TOKEN_HASH_OFFSET, (uint32_t*)flash_status.token_hash, HASH_LEN);
}

/**
 * @brief Retrieves AEAD key value from flash memory.
 * 
 * This function reads the AEAD key value from the specified flash address
 * and stores it in the global `flash_status.aead_key` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_aead_key() {
    flash_simple_read(FLASH_ADDR + AEAD_KEY_OFFSET, (uint32_t*)flash_status.aead_key, AEAD_KEY_SIZE);
}

/**
 * @brief Retrieves AEAD nonce value from flash memory.
 * 
 * This function reads the AEAD nonce value from the specified flash address
 * and stores it in the global `flash_status.aead_nonce` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_aead_nonce() {
    flash_simple_read(FLASH_ADDR + AEAD_NONCE_OFFSET, (uint32_t*)flash_status.aead_nonce, AEAD_NONCE_SIZE);
}

#define WRITE_FLASH_MEMORY  \
    retrive_ap_priv_key();  \
    retrive_cp_pub_key();   \
    retrive_hash_key(); \
    retrive_hash_salt();    \
    retrive_pin_hash(); \
    retrive_token_hash();   \
    retrive_aead_key(); \
    retrive_aead_nonce();   \
    flash_simple_erase_page(FLASH_ADDR);    \
    flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));  \
    crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));    \
    crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));  \
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));  \
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));    \
    crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));  \
    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));  \
    crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));  \
    crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));

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
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));
        
        flash_status.mode = SYS_MODE_NORMAL;

        uint8_t ap_private_key[] = {AP_PRIVATE_KEY};
        uint8_t cp_public_key[] = {CP_PUBLIC_KEY};
        uint8_t ap_hash_key[] = {AP_HASH_KEY};
        uint8_t ap_hash_salt[] = {AP_HASH_SALT};
        uint8_t ap_hash_pin[] = {AP_HASH_PIN};
        uint8_t ap_hash_token[] = {AP_HASH_TOKEN};
        uint8_t aead_key[] = {AEAD_KEY};
        uint8_t aead_nonce[] = {AEAD_NONCE};
        memcpy(flash_status.ap_priv_key, ap_private_key, PRIV_KEY_SIZE);
        memcpy(flash_status.cp_pub_key, cp_public_key, PUB_KEY_SIZE);
        memcpy(flash_status.hash_key, ap_hash_key, HASH_KEY_LEN);
        memcpy(flash_status.hash_salt, ap_hash_salt, HASH_SALT_LEN);
        memcpy(flash_status.pin_hash, ap_hash_pin, HASH_LEN);
        memcpy(flash_status.token_hash, ap_hash_token, HASH_LEN);
        memcpy(flash_status.aead_key, aead_key, AEAD_KEY_SIZE);
        memcpy(flash_status.aead_nonce, aead_nonce, AEAD_NONCE_SIZE);


        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

        crypto_wipe(ap_private_key, sizeof(ap_private_key));
        crypto_wipe(cp_public_key, sizeof(cp_public_key));
        crypto_wipe(ap_hash_key, sizeof(ap_hash_key));
        crypto_wipe(ap_hash_salt, sizeof(ap_hash_salt));
        crypto_wipe(ap_hash_pin, sizeof(ap_hash_pin));
        crypto_wipe(ap_hash_token, sizeof(ap_hash_token));
        crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));
        crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
        crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
        crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
        crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
        crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
        crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));
        crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));
    }

    if (flash_status.mode == SYS_MODE_DEFENSE) {
        defense_mode();
    }
    
    if (rng_init() != E_NO_ERROR) {
        panic();
    }

    // Initialize board link interface
    if (board_link_init() != E_NO_ERROR) {
        panic();
    }
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message
    int result = send_packet(addr, sizeof(uint8_t), transmit);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

typedef struct __attribute__((packed)) {
    uint8_t cmd_label;
    uint8_t nonce[NONCE_SIZE];
    uint8_t address;
} packet_plain_with_addr;

// typedef struct {
//     uint8_t cmd_label;
//     uint8_t nonce[NONCE_SIZE];
//     uint32_t id;
// } packet_plain_with_id;

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
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    MXC_Delay(50);

    if (len > MAX_POST_BOOT_MSG_LEN) {
        panic();
    }
    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int send_result = ERROR_RETURN;
    int receive_len = 0;

    // send the `sending` command
    sending_buf[0] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    send_result = send_packet(address, sizeof(uint8_t), sending_buf);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);
    if (send_result == ERROR_RETURN) {
        panic();
        return ERROR_RETURN;
    }

    MXC_Delay(50);

    // receive challenge (nonce)
    receive_len = poll_and_receive_packet(address, receiving_buf);
    cancel_continuous_timer();
    if (receive_len != NONCE_SIZE) {
        defense_mode();
        return ERROR_RETURN;
    }

    MXC_Delay(50);

    // make up plaintext for signature of authentication
    packet_plain_with_addr *plain_auth = (packet_plain_with_addr *) general_buf;
    // memcpy(general_buf, receiving_buf, NONCE_SIZE);
    // general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    // general_buf[NONCE_SIZE + 1] = address;
    plain_auth->cmd_label = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    memcpy(plain_auth->nonce, receiving_buf, NONCE_SIZE);
    plain_auth->address = address;

    // make up plaintext for signature of message
    packet_plain_msg *plain_msg = (packet_plain_msg *) general_buf_2;
    plain_msg->address = address;
    plain_msg->cmd_label = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    memcpy(plain_msg->nonce, receiving_buf, NONCE_SIZE);
    memcpy(plain_msg->msg, buffer, len);

    // the whole sending packet
    packet_sign_sign_msg *pkt_sending = (packet_sign_sign_msg *) sending_buf;
    memcpy(pkt_sending->msg, buffer, len);

    // sign (2 signatures)
    retrive_ap_priv_key();
    crypto_eddsa_sign(pkt_sending->sig_auth, flash_status.ap_priv_key, general_buf, NONCE_SIZE + 2);
    crypto_eddsa_sign(pkt_sending->sig_msg, flash_status.ap_priv_key, general_buf_2, NONCE_SIZE + 2 + len);
    // crypto_eddsa_sign(sending_buf, flash_status.ap_priv_key, general_buf, NONCE_SIZE + 2);
    // crypto_eddsa_sign(sending_buf + SIGNATURE_SIZE, flash_status.ap_priv_key, buffer, len);
    crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));

    // send
    // memcpy(sending_buf + SIGNATURE_SIZE * 2, buffer, len);
    send_result = send_packet(address, SIGNATURE_SIZE * 2 + len, sending_buf);
    if (send_result == ERROR_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    // printf("general_buf\n");
    // print_hex(general_buf, NONCE_SIZE + 2);
    // printf("general_buf_2\n");
    // print_hex(general_buf_2, NONCE_SIZE + 2 + len);
    // printf("sending_buf, len=%d\n", SIGNATURE_SIZE * 2 + len);
    // print_hex(sending_buf, SIGNATURE_SIZE * 2 + len);

    MXC_Delay(500);
    return SUCCESS_RETURN;
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    MXC_Delay(50);

    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf_2[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;
    int receive_len = 0;

    // send the `reading` command, generate nonce
    packet_read_msg *pkt_send = (packet_read_msg *)sending_buf;
    pkt_send->cmd_label = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    rng_get_bytes(pkt_send->nonce, NONCE_SIZE);
    // sending_buf[0] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    // rng_get_bytes(sending_buf + 1, NONCE_SIZE);
    result = send_packet(address, NONCE_SIZE + 1, sending_buf);
    if (result == ERROR_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    start_continuous_timer(TIMER_LIMIT_I2C_MSG_2);

    // receive sign(p, nonce, addr) + sign(p, addr, nonce, msg) + msg
    MXC_Delay(50);
    receive_len = poll_and_receive_packet(address, receiving_buf);
    cancel_continuous_timer();
    if (receive_len <= 0) {
        return receive_len;
    }
    packet_sign_sign_msg *pkt_recv = (packet_sign_sign_msg *) receiving_buf;
    int msg_len = receive_len - SIGNATURE_SIZE * 2;
    
    // construct the plain text for verifying auth (p, nonce, address)
    packet_plain_with_addr *plain_auth = (packet_plain_with_addr *) general_buf;
    plain_auth->address = address;
    plain_auth->cmd_label = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    memcpy(plain_auth->nonce, pkt_send->nonce, NONCE_SIZE);
    // memcpy(general_buf, sending_buf + 1, NONCE_SIZE);
    // general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    // general_buf[NONCE_SIZE + 1] = address;

    // construct the plain text for verifying msg (p, addr, nonce, msg)
    packet_plain_msg *plain_msg = (packet_plain_msg *) general_buf_2;
    plain_msg->address = address;
    plain_msg->cmd_label = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    memcpy(plain_msg->nonce, pkt_send->nonce, NONCE_SIZE);
    memcpy(plain_msg->msg, pkt_recv->msg, msg_len);

    // verify (2 signatures)
    retrive_cp_pub_key();
    // if (crypto_eddsa_check(receiving_buf, flash_status.cp_pub_key, general_buf, NONCE_SIZE + 2)) {
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(pkt_recv->sig_auth, flash_status.cp_pub_key, general_buf, NONCE_SIZE + 2), 0, ERR_VALUE);
    crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
    defense_mode();
    return 0;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // }
    // if (crypto_eddsa_check(receiving_buf + SIGNATURE_SIZE, flash_status.cp_pub_key, receiving_buf + SIGNATURE_SIZE * 2, msg_len)) {
    CONDITION_NEQ_BRANCH(crypto_eddsa_check(pkt_recv->sig_msg, flash_status.cp_pub_key, general_buf_2, NONCE_SIZE + 2 + msg_len), 0, ERR_VALUE);
    crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
    defense_mode();
    return 0;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // }
    crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));

    // save the msg
    memcpy(buffer, pkt_recv->msg, msg_len);

    // printf("general_buf\n");
    // print_hex(general_buf, NONCE_SIZE + 2);
    // printf("general_buf_2\n");
    // print_hex(general_buf_2, NONCE_SIZE + 2 + msg_len);
    // printf("sending_buf\n");
    // print_hex(sending_buf, NONCE_SIZE + 1);
    // printf("receiving_buf\n");
    // print_hex(receiving_buf, receive_len);

    MXC_Delay(500);
    return msg_len;
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/******************************** COMPONENT COMMS ********************************/

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }
    // print_info("ok\n");

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // print_info("addr=0x%x\n", addr);
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }
        // print_info("scan_components 1\n");
        // Create command message 
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        // print_info("scan_components 2\n");
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        // print_info("scan_components 3\n");

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
        // print_info("scan_components 4\n");
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    MXC_Delay(50);

    int r = 0;
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id) {
            r = 1;
            break;
        }
    }
    if (r == 0) {
        return ERROR_RETURN;
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t general_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // send attestation command
    transmit_buffer[0] = COMPONENT_CMD_ATTEST;
    send_packet(addr, NONCE_SIZE + 1, transmit_buffer);
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // receive nonce and sign
    int result = poll_and_receive_packet(addr, receive_buffer);
    cancel_continuous_timer();
    if (result != NONCE_SIZE) {
        return ERROR_RETURN;
    }
    general_buffer[0] = COMPONENT_CMD_ATTEST;
    memcpy(general_buffer + 1, receive_buffer, NONCE_SIZE);
    general_buffer[NONCE_SIZE + 1] = addr;
    retrive_ap_priv_key();
    crypto_eddsa_sign(transmit_buffer, flash_status.ap_priv_key, general_buffer, NONCE_SIZE + 2);
    crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));
    send_packet(addr, SIGNATURE_SIZE, transmit_buffer);
    crypto_wipe(transmit_buffer, sizeof(transmit_buffer));
    start_continuous_timer(TIMER_LIMIT_I2C_MSG);

    // receive the ecnrypted attestation data
    result = poll_and_receive_packet(addr, receive_buffer);
    cancel_continuous_timer();
    if (result != ATT_FINAL_TEXT_SIZE) {
        defense_mode();
        return ERROR_RETURN;
    }
    retrive_aead_key();
    retrive_aead_nonce();
    if (crypto_aead_unlock(general_buffer, receive_buffer, flash_status.aead_key, flash_status.aead_nonce, NULL, 0, receive_buffer + AEAD_MAC_SIZE, ATT_PLAIN_TEXT_SIZE)) {
        crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));
        crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));
        crypto_wipe(receive_buffer, sizeof(receive_buffer));
        // panic();
        defense_mode();
        return ERROR_RETURN;
    }
    crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));
    crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));
    crypto_wipe(receive_buffer, sizeof(receive_buffer));

    // Print out attestation data
    general_buffer[ATT_LOC_POS + general_buffer[ATT_LOC_LEN_POS]] = '\0';
    general_buffer[ATT_DATE_POS + general_buffer[ATT_DATE_LEN_POS]] = '\0';
    general_buffer[ATT_CUSTOMER_POS + general_buffer[ATT_CUSTOMER_LEN_POS]] = '\0';
    print_info("C>0x%08x\n", component_id);
    print_info("LOC>%s\nDATE>%s\nCUST>%s\n", general_buffer + ATT_LOC_POS, general_buffer + ATT_DATE_POS, general_buffer + ATT_CUSTOMER_POS);
    crypto_wipe(general_buffer, sizeof(general_buffer));
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    MXC_Delay(100);
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // test 1
    // uint8_t buffer[] = "abc";
    // secure_send(0x24, buffer, sizeof(buffer));

    // test 2
    // uint8_t buffer[256];
    // int r = secure_receive(0x24, buffer);
    // printf("buffer=");
    // print_hex(buffer, r);

    // test 3
    // uint8_t buffer1[] = "ectf{testing_1afa95d5de6bea59}";
    // uint8_t buffer2[256];
    // printf("1\n");
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // printf("2\n");
    // secure_receive(0x24, buffer2);
    // printf("3\n");

    // test 4
    // uint8_t buffer1[] = "abc";
    // uint8_t buffer2[256];
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // secure_receive(0x24, buffer2);
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // secure_receive(0x24, buffer2);
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // secure_receive(0x24, buffer2);
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // secure_receive(0x24, buffer2);
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // secure_receive(0x24, buffer2);
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // secure_receive(0x24, buffer2);
    
    // Everything after this point is modifiable in your design
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[HOST_INPUT_BUF_SIZE];
    recv_input("Enter pin: ", buf);
    MXC_Delay(50);

    uint8_t hash[HASH_LEN] = {0};
    crypto_argon2_config cac = {CRYPTO_ARGON2_ID, NB_BLOCKS_PIN, NB_PASSES, NB_LANES};
    uint8_t *workarea = malloc(1024 * cac.nb_blocks);
    retrive_hash_salt();
    crypto_argon2_inputs cai = {(const uint8_t *)buf, flash_status.hash_salt, PIN_LEN, sizeof(flash_status.hash_salt)};
    retrive_hash_key();
    crypto_argon2_extras cae = {flash_status.hash_key, NULL, sizeof(flash_status.hash_key), 0};
    crypto_argon2(hash, HASH_LEN, workarea, cac, cai, cae);
    free(workarea);
    // TODO: random delay
    MXC_Delay(100);
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
    retrive_pin_hash();
    // if (!crypto_verify64(hash, flash_status.pin_hash)) {
    CONDITION_EQ_BRANCH(crypto_verify64(hash, flash_status.pin_hash), 0, ERR_VALUE);
    crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
    crypto_wipe(hash, sizeof(hash));
    print_debug("Pin Accepted!\n");
    return SUCCESS_RETURN;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // }
    crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
    crypto_wipe(hash, sizeof(hash));
    print_error("Invalid PIN!\n");
    defense_mode();
    return ERROR_RETURN;
}

// Function to validate the replacement token
// TODO: short panic mode, remove debug info
int validate_token() {
    char buf[HOST_INPUT_BUF_SIZE];
    recv_input("Enter token: ", buf);
    if (strlen(buf) != TOKEN_LEN) {
        // TODO: Defense mode
        print_error("Invalid Token!\n");
        return ERROR_RETURN;
    }
    // print_info("\nInputted Token: \n");
    // print_hex(buf, TOKEN_LEN);
    MXC_Delay(50);

    uint8_t hash[HASH_LEN] = {0};
    crypto_argon2_config cac = {CRYPTO_ARGON2_ID, NB_BLOCKS_TOKEN, NB_PASSES, NB_LANES};
    uint8_t *workarea = malloc(1024 * cac.nb_blocks);
    retrive_hash_salt();
    crypto_argon2_inputs cai = {(const uint8_t *)buf, flash_status.hash_salt, TOKEN_LEN, sizeof(flash_status.hash_salt)};
    retrive_hash_key();
    crypto_argon2_extras cae = {flash_status.hash_key, NULL, sizeof(flash_status.hash_key), 0};
    crypto_argon2(hash, HASH_LEN, workarea, cac, cai, cae);
    free(workarea);
    MXC_Delay(50);
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
    retrive_token_hash();
    // if (!crypto_verify64(hash, flash_status.token_hash)) {
    CONDITION_EQ_BRANCH(crypto_verify64(hash, flash_status.token_hash), 0, ERR_VALUE);
    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
    crypto_wipe(hash, sizeof(hash));
    print_debug("Token Accepted!\n");
    return SUCCESS_RETURN;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    // }
    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
    crypto_wipe(hash, sizeof(hash));
    print_error("Invalid Token!\n");
    defense_mode();
    return ERROR_RETURN;
}

void attempt_boot1() {
    uint8_t sending_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    uint8_t general_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = ERROR_RETURN;
    uint8_t *signatures = malloc(SIGNATURE_SIZE * flash_status.component_cnt);

    // send `boot` command + challenge to each provisioned component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        sending_buf[0] = COMPONENT_CMD_BOOT;
        rng_get_bytes(sending_buf + 1, NONCE_SIZE);
        sending_buf[NONCE_SIZE + 1] = addr;
        result = send_packet(addr, NONCE_SIZE + 2, sending_buf);
        start_continuous_timer(TIMER_LIMIT_I2C_MSG);
        if (result == ERROR_RETURN) {
            free(signatures);
            return;
        }
        MXC_Delay(50);
        // receive response + challenge
        result = poll_and_receive_packet(addr, receiving_buf);
        cancel_continuous_timer();
        if (result != SIGNATURE_SIZE + NONCE_SIZE) {
            free(signatures);
            defense_mode();
            return;
        }
        // verify the signature
        retrive_cp_pub_key();
        // if (crypto_eddsa_check(receiving_buf, flash_status.cp_pub_key, sending_buf, NONCE_SIZE + 2)) {
        CONDITION_NEQ_BRANCH(crypto_eddsa_check(receiving_buf, flash_status.cp_pub_key, sending_buf, NONCE_SIZE + 2), 0, ERR_VALUE);
        crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
        free(signatures);
        // panic();
        defense_mode();
        return;
        CONDITION_BRANCH_ENDING(ERR_VALUE);
        // }
        crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
        // sign CP's challenge
        general_buf[0] = COMPONENT_CMD_BOOT_2;
        memcpy(general_buf + 1, receiving_buf + SIGNATURE_SIZE, NONCE_SIZE);
        general_buf[NONCE_SIZE + 1] = addr;
        retrive_ap_priv_key();
        crypto_eddsa_sign(signatures + SIGNATURE_SIZE * i, flash_status.ap_priv_key, general_buf, NONCE_SIZE + 2);
        crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));
        MXC_Delay(50);
    }

    // boot each provisioned component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        result = send_packet(addr, SIGNATURE_SIZE, signatures + SIGNATURE_SIZE * i);
        start_continuous_timer(TIMER_LIMIT_I2C_MSG);
        if (result == ERROR_RETURN) {
            free(signatures);
            return;
        }
        result = poll_and_receive_packet(addr, receiving_buf);
        cancel_continuous_timer();
        if (result < 0) {
            free(signatures);
            defense_mode();
            return;
        }
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receiving_buf);
        MXC_Delay(50);
    }
    free(signatures);

    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");

    // Boot
    boot();
}

// Replace a component if the PIN is correct
// TODO: can we erase 4 bytes of flash instead of a page?
void attempt_replace() {
    MXC_Delay(200);

    char buf[HOST_INPUT_BUF_SIZE];

    recv_input("Enter token: ", buf);
    if (strlen(buf) != TOKEN_LEN) {
        // TODO: Defense mode
        print_error("Invalid Token!\n");
        defense_mode();
        return;
    }
    // print_info("\nInputted Token: \n");
    // print_hex(buf, TOKEN_LEN);
    MXC_Delay(50);

    uint8_t hash[HASH_LEN] = {0};
    crypto_argon2_config cac = {CRYPTO_ARGON2_ID, NB_BLOCKS_TOKEN, NB_PASSES, NB_LANES};
    uint8_t *workarea = malloc(1024 * cac.nb_blocks);
    retrive_hash_salt();
    crypto_argon2_inputs cai = {(const uint8_t *)buf, flash_status.hash_salt, TOKEN_LEN, sizeof(flash_status.hash_salt)};
    retrive_hash_key();
    crypto_argon2_extras cae = {flash_status.hash_key, NULL, sizeof(flash_status.hash_key), 0};
    crypto_argon2(hash, HASH_LEN, workarea, cac, cai, cae);
    free(workarea);
    MXC_Delay(50);
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
    retrive_token_hash();
    CONDITION_NEQ_BRANCH(crypto_verify64(hash, flash_status.token_hash), 0, ERR_VALUE);
    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
    crypto_wipe(hash, sizeof(hash));
    print_error("Invalid Token!\n");
    defense_mode();
    return;
    CONDITION_BRANCH_ENDING(ERR_VALUE);

    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
    crypto_wipe(hash, sizeof(hash));
    print_debug("Token Accepted!\n");


    // if (validate_token()) {
    //     return;
    // }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;
            
            WRITE_FLASH_MEMORY;
            
            // print replace success information
            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
    defense_mode();
}

// Attest a component if the PIN is correct
void attempt_attest() {
    MXC_Delay(50);

    char buf[HOST_INPUT_BUF_SIZE];

    recv_input("Enter pin: ", buf);
    if (strlen(buf) != 6) {
        print_error("Invalid PIN!\n");
        defense_mode();
        return;
    }
    MXC_Delay(50);

    uint8_t hash[HASH_LEN] = {0};
    crypto_argon2_config cac = {CRYPTO_ARGON2_ID, NB_BLOCKS_PIN, NB_PASSES, NB_LANES};
    uint8_t *workarea = malloc(1024 * NB_BLOCKS_PIN);
    retrive_hash_salt();
    crypto_argon2_inputs cai = {(const uint8_t *)buf, flash_status.hash_salt, PIN_LEN, sizeof(flash_status.hash_salt)};
    retrive_hash_key();
    crypto_argon2_extras cae = {flash_status.hash_key, NULL, sizeof(flash_status.hash_key), 0};
    crypto_argon2(hash, HASH_LEN, workarea, cac, cai, cae);
    // TODO: random delay
    MXC_Delay(100);
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
    free(workarea);
    retrive_pin_hash();
    CONDITION_NEQ_BRANCH(crypto_verify64(hash, flash_status.pin_hash), 0, ERR_VALUE);
    crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
    crypto_wipe(hash, sizeof(hash));
    print_error("Invalid PIN!\n");
    defense_mode();
    return;
    CONDITION_BRANCH_ENDING(ERR_VALUE);
    crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
    crypto_wipe(hash, sizeof(hash));
    print_debug("Pin Accepted!\n");

    // if (validate_pin()) {
    //     return;
    // }

    MXC_Delay(100);
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if(attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    } else {
        print_error("Attest\n");
    }
}

/*********************************** MAIN *************************************/

// TODO: how to use panic? double-if, timeout
// TODO: inline functions? like boot?
int main() {
    // Initialize board
    init();

    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[HOST_INPUT_BUF_SIZE];
    while (1) {
        recv_input("Enter Command: ", buf);

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot1();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
