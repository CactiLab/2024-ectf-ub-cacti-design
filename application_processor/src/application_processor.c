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

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"

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

#define PRIV_KEY_SIZE 64
#define PUB_KEY_SIZE 32
#define COMPONENT_IDS_OFFSET offsetof(flash_entry, component_ids)
#define AP_PRIV_KEY_OFFSET offsetof(flash_entry, ap_priv_key)
#define CP_PUB_KEY_OFFSET offsetof(flash_entry, cp_pub_key)
#define HASH_KEY_OFFSET offsetof(flash_entry, hash_key)
#define HASH_SALT_OFFSET offsetof(flash_entry, hash_salt)
#define PIN_HASH_OFFSET offsetof(flash_entry, pin_hash)
#define TOKEN_HASH_OFFSET offsetof(flash_entry, token_hash)
#define AEAD_KEY_OFFSET offsetof(flash_entry, aead_key)
#define AEAD_NONCE_OFFSET offsetof(flash_entry, aead_nonce)
#define NONCE_SIZE 64
#define SIGNATURE_SIZE 64
#define MAX_POST_BOOT_MSG_LEN 64
#define PIN_LEN 6
#define TOKEN_LEN 16
#define HASH_KEY_LEN 128
#define HASH_SALT_LEN 128
#define NB_BLOCKS_PIN 108
#define NB_BLOCKS_TOKEN 65
#define NB_PASSES 3
#define NB_LANES 1
#define HASH_LEN 64
#define HOST_INPUT_BUF_SIZE 64
// #define CIPHER_ATTESTATION_DATA_LEN 243
#define AEAD_MAC_SIZE 16
#define AEAD_NONCE_SIZE 24
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

} flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST,
    COMPONENT_CMD_MSG_FROM_AP_TO_CP,
    COMPONENT_CMD_MSG_FROM_CP_TO_AP
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
    int result = ERROR_RETURN;

    // sending command
    sending_buf[0] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    result = send_packet(address, sizeof(uint8_t), sending_buf);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    // print_info("secure_send 1, sending_buf=");
    MXC_Delay(20);
    print_hex(sending_buf, 1);

    // receive nonce and sign
    result = poll_and_receive_packet(address, receiving_buf);
    if (result != NONCE_SIZE) {
        return ERROR_RETURN;
    }

    // print_info("secure_send 2, receiving_buf=");
    // print_hex(receiving_buf, result);

    MXC_Delay(20);
    memcpy(general_buf, receiving_buf, NONCE_SIZE);
    general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_AP_TO_CP;
    general_buf[NONCE_SIZE + 1] = address;
    retrive_ap_priv_key();
    crypto_eddsa_sign(sending_buf, flash_status.ap_priv_key, general_buf, NONCE_SIZE + 2);
    crypto_eddsa_sign(sending_buf + SIGNATURE_SIZE, flash_status.ap_priv_key, buffer, len);
    crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));
    memcpy(sending_buf + SIGNATURE_SIZE * 2, buffer, len);
    result = send_packet(address, SIGNATURE_SIZE * 2 + len, sending_buf);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }

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
    uint8_t receiving_buf[MAX_I2C_MESSAGE_LEN + 1] = {0};
    int result = 0;

    // printf("secure_receive 1\n");

    // send reading command, generate nonce
    sending_buf[0] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    rng_get_bytes(sending_buf + 1, NONCE_SIZE);
    // printf("secure_receive 2\n");
    send_packet(address, NONCE_SIZE + 1, sending_buf);
    // printf("secure_receive 3, sending_buf=\n");
    // print_hex(sending_buf, NONCE_SIZE + 1);

    // validate nonce
    MXC_Delay(20);
    result = poll_and_receive_packet(address, receiving_buf);
    if (result <= 0) {
        return result;
    }
    // printf("secure_receive 4, receiving_buf=\n");
    // print_hex(receiving_buf, result);

    int len = result - SIGNATURE_SIZE * 2;
    memcpy(general_buf, sending_buf + 1, NONCE_SIZE);
    general_buf[NONCE_SIZE] = COMPONENT_CMD_MSG_FROM_CP_TO_AP;
    general_buf[NONCE_SIZE + 1] = address;
    retrive_cp_pub_key();
    int r1 = crypto_eddsa_check(receiving_buf, flash_status.cp_pub_key, general_buf, NONCE_SIZE + 2);
    int r2 = crypto_eddsa_check(receiving_buf + SIGNATURE_SIZE, flash_status.cp_pub_key, receiving_buf + SIGNATURE_SIZE * 2, len);
    
    // printf("secure_receive 5, s1=");
    // print_hex(receiving_buf, SIGNATURE_SIZE);

    // printf("secure_receive 6, s2=");
    // print_hex(receiving_buf + SIGNATURE_SIZE, SIGNATURE_SIZE);

    // printf("secure_receive 7, msg=");
    // print_hex(receiving_buf + SIGNATURE_SIZE * 2, len);

    // printf("secure_receive 8, flash_status.cp_pub_key=");
    // print_hex(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));

    // printf("secure_receive 9, r1=%d, r2=%d\n", r1, r2);

    crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
    if (r1 != 0 || r2 != 0) {
        panic();
        return 0;
    }
    memcpy(buffer, receiving_buf + SIGNATURE_SIZE * 2, len);

    MXC_Delay(500);
    return len;
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

int validate_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
    // TODO: Fix the component count to 2
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        validate_message* validate = (validate_message*) receive_buffer;
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    MXC_Delay(50);

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t general_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // send attestation command
    transmit_buffer[0] = COMPONENT_CMD_ATTEST;
    send_packet(addr, NONCE_SIZE + 1, transmit_buffer);

    // receive nonce and sign
    int result = poll_and_receive_packet(addr, receive_buffer);
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

    // receive the ecnrypted attestation data
    result = poll_and_receive_packet(addr, receive_buffer);
    if (result != ATT_FINAL_TEXT_SIZE) {
        return ERROR_RETURN;
    }
    retrive_aead_key();
    retrive_aead_nonce();
    if (crypto_aead_unlock(general_buffer, receive_buffer, flash_status.aead_key, flash_status.aead_nonce, NULL, 0, receive_buffer + AEAD_MAC_SIZE, ATT_PLAIN_TEXT_SIZE)) {
        crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));
        crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));
        crypto_wipe(receive_buffer, sizeof(receive_buffer));
        panic();
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
    MXC_Delay(50);
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
    // uint8_t buffer1[] = "abc";
    // uint8_t buffer2[256];
    // secure_send(0x24, buffer1, sizeof(buffer1));
    // secure_receive(0x24, buffer2);

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
    MXC_Delay(100);
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
    retrive_pin_hash();
    if (!crypto_verify64(hash, flash_status.pin_hash)) {
        crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
        crypto_wipe(hash, sizeof(hash));
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
    crypto_wipe(hash, sizeof(hash));
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
// TODO: short panic mode, remove debug info
int validate_token() {
    char buf[HOST_INPUT_BUF_SIZE];
    recv_input("Enter token: ", buf);
    if (strlen(buf) != TOKEN_LEN) {
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
    // print_info("Key: ");
    // print_hex(flash_status.hash_key, HASH_KEY_LEN);
    // print_info("\nSalt: ");
    // print_hex(flash_status.hash_salt, HASH_SALT_LEN);
    free(workarea);
    MXC_Delay(50);
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
    retrive_token_hash();
    // print_info("\nSaved Token:");
    // print_hex(flash_status.token_hash, sizeof(flash_status.token_hash));
    // print_info("\nCalculated Token:");
    // print_hex(hash, sizeof(hash));
    if (!crypto_verify64(hash, flash_status.token_hash)) {
        crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
        crypto_wipe(hash, sizeof(hash));
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
    crypto_wipe(hash, sizeof(hash));
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    volatile int ret = -1;
    ret = validate_components();
    if (ret != SUCCESS_RETURN) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    ret = boot_components();
    if (ret != SUCCESS_RETURN) {
        print_error("Failed to boot all components\n");
        return;
    }

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
    MXC_Delay(HOST_INPUT_BUF_SIZE);
    char buf[HOST_INPUT_BUF_SIZE];

    if (validate_token()) {
        return;
    }

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

            // write updated component_ids to flash
            retrive_ap_priv_key();
            retrive_cp_pub_key();
            retrive_hash_key();
            retrive_hash_salt();
            retrive_pin_hash();
            retrive_token_hash();
            retrive_aead_key();
            retrive_aead_nonce();
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
            crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));
            crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
            crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
            crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
            crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
            crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
            crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));
            crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));
            
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
}

// Attest a component if the PIN is correct
void attempt_attest() {
    MXC_Delay(50);
    char buf[HOST_INPUT_BUF_SIZE];

    if (validate_pin()) {
        return;
    }

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
// remove
// #define PRIVKEY 0x6f, 0x05, 0xeb, 0xe4, 0xd6, 0x38, 0x35, 0x46, 0x64, 0x73, 0x30, 0xf9, 0xf9, 0x43, 0x0f, 0x6b, 0x5d, 0xdd, 0x56, 0x57, 0xc1, 0xc1, 0x03, 0xb7, 0xfd, 0x35, 0xa7, 0x1d, 0x21, 0x6e, 0x63, 0x25, 0x0a, 0x6e, 0x7d, 0xdd, 0x7e, 0xac, 0x9e, 0x3f, 0xad, 0x0b, 0x74, 0x31, 0xd1, 0x9c, 0x13, 0x9a, 0x4e, 0xda, 0xf1, 0x7c, 0xac, 0xcf, 0x0a, 0xda, 0xf6, 0xce, 0x04, 0xac, 0x88, 0x33, 0x38, 0x99
// #define PUBKEY 0x0a, 0x6e, 0x7d, 0xdd, 0x7e, 0xac, 0x9e, 0x3f, 0xad, 0x0b, 0x74, 0x31, 0xd1, 0x9c, 0x13, 0x9a, 0x4e, 0xda, 0xf1, 0x7c, 0xac, 0xcf, 0x0a, 0xda, 0xf6, 0xce, 0x04, 0xac, 0x88, 0x33, 0x38, 0x99

// TODO: how to use panic? double-if, mode

int main() {
    // Initialize board
    init();
    
    // uint8_t delay_result;
    // RANDOM_DELAY_TINY(delay_result);
    // if (delay_result == 0) {
    //     print_error("TRNG failure\n");
    //     panic();
    // }

    // remove
    // unsigned int cycle1, cycle2;
    // cycle1 = get_current_cpu_cycle();
    // RANDOM_DELAY_TINY_2;
    // cycle2 = get_current_cpu_cycle();
    // print_info("after tiny delay, cycle1=%u, cycle2=%u, cycle difference=%u\n", cycle1, cycle2, cycle2 - cycle1);

    // uint8_t message[64] = "I love you.";
    // uint8_t privkey[] = {PRIVKEY};
    // uint8_t pubkey[] = {PUBKEY};
    // uint8_t signature[64];
    // crypto_eddsa_sign(signature, privkey, message, 12);
    // print_info("private key: ");
    // print_hex(privkey, sizeof(privkey));
    // print_info("\n");
    // print_info("signature: ");
    // print_hex(signature, 64);
    // print_info("\n");
    // int r = crypto_eddsa_check(signature, pubkey, message, 12);
    // print_info("check result 1: =%d\n", r);
    // message[0] = 65;
    // r = crypto_eddsa_check(signature, pubkey, message, 12);
    // print_info("check result 2: =%d\n", r);
    
    // uint8_t pass[] = "123456";
    // uint8_t salt[] = {AP_HASH_SALT};
    // uint8_t kkey[] = {AP_HASH_KEY};
    // uint8_t hash[64];
    // uint8_t *workarea = malloc(1024 * 115);
    // crypto_argon2_config cac = {CRYPTO_ARGON2_ID, 115, 3, 1};
    // crypto_argon2_inputs cai = {pass, salt, 6, sizeof(salt)};
    // crypto_argon2_extras cae = {kkey, NULL, sizeof(kkey), 0};
    // crypto_argon2(hash, 64, workarea, cac, cai, cae);
    // print_info("hash=");
    // print_hex(hash, 64);
    // print_info("\n");
    // uint8_t hash_pin[] = {AP_HASH_PIN};
    // r = crypto_verify64(hash, hash_pin);
    // print_info("r=%d\n", r);
    // print_info("PIN: ");
    // print_hex(pass, 6);
    // print_info("\nKey: ");
    // print_hex(kkey, sizeof(kkey));
    // print_info("\nSalt: ");
    // print_hex(salt, sizeof(salt));


    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf);

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
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
