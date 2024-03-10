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

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "mpu_init.h"
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

#include "monocypher.h"
#include "syscalls.h"

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
// #include "global_secrets.h"

/********************************* CONSTANTS **********************************/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF
#define COMPONENT_IDS_OFFSET    offsetof(flash_entry, component_ids)
#define AP_PRIV_KEY_OFFSET      offsetof(flash_entry, ap_priv_key)
#define CP_PUB_KEY_OFFSET       offsetof(flash_entry, cp_pub_key)
#define HASH_KEY_OFFSET         offsetof(flash_entry, hash_key)
#define HASH_SALT_OFFSET        offsetof(flash_entry, hash_salt)
#define PIN_HASH_OFFSET         offsetof(flash_entry, pin_hash)
#define TOKEN_HASH_OFFSET       offsetof(flash_entry, token_hash)
#define AEAD_KEY_OFFSET         offsetof(flash_entry, aead_key)
#define AEAD_NONCE_OFFSET       offsetof(flash_entry, aead_nonce)
#define AEAD_CP_BOOT_NONCE_OFFSET   offsetof(flash_entry, aead_cp_boot_nonce)
#define AEAD_AP_BOOT_NONCE_OFFSET   offsetof(flash_entry, aead_ap_boot_nonce)
#define AEAD_AP_BOOT_CIPHER_OFFSET  offsetof(flash_entry, aead_ap_boot_cipher)

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
#define ERR_VALUE -15   // an error value that functions will never return

// length and functionality
#define PRIV_KEY_SIZE           64
#define PUB_KEY_SIZE            32
#define COMPONENT_ID_SIZE       4
#define NONCE_SIZE                      64
#define SIGNATURE_SIZE                  64
#define MAX_POST_BOOT_MSG_LEN           64
#define PIN_LEN                         6
#define TOKEN_LEN                       16
#define HASH_KEY_LEN                    128
#define HASH_SALT_LEN                   128
#define NB_BLOCKS_PIN                   108
#define NB_BLOCKS_TOKEN                 108
#define NB_PASSES                       3
#define NB_LANES                        1
#define HASH_LEN                        64
#define HOST_INPUT_BUF_SIZE             64
#define AEAD_MAC_SIZE                   16
#define AEAD_NONCE_SIZE                 24
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
#define BOOT_MSG_PLAIN_TEXT_SIZE        128
#define BOOT_MSG_CIPHER_TEXT_SIZE       BOOT_MSG_PLAIN_TEXT_SIZE + AEAD_MAC_SIZE
#define ENC_ATTESTATION_MAGIC           173
#define ENC_BOOT_MAGIC                  82

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

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
    uint8_t ap_priv_key[PRIV_KEY_SIZE];
    uint8_t cp_pub_key[PUB_KEY_SIZE];
    uint8_t hash_key[HASH_KEY_LEN];
    uint8_t hash_salt[HASH_SALT_LEN];
    uint8_t pin_hash[HASH_LEN];
    uint8_t token_hash[HASH_LEN];
    uint8_t aead_key[AEAD_KEY_SIZE];
    uint8_t aead_nonce[AEAD_NONCE_SIZE];
    uint8_t aead_cp_boot_nonce[AEAD_NONCE_SIZE];
    uint8_t aead_ap_boot_nonce[AEAD_NONCE_SIZE];
    uint8_t aead_ap_boot_cipher[BOOT_MSG_CIPHER_TEXT_SIZE];
    uint32_t mode;   // 0: normal, 1: defense, refers to system_modes
} flash_entry;

// system mode
// when in the defense mode, system will be delayed for 4 seconds
typedef enum {
    SYS_MODE_NORMAL,
    SYS_MODE_DEFENSE
} system_modes;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

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
    return send_packet(address, len, buffer);
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
    return poll_and_receive_packet(address, buffer);
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
 * @brief Retrieves AEAD CP boot nonce value from flash memory.
 * 
 * This function reads the AEAD CP boot nonce value from the specified flash address
 * and stores it in the global `flash_status.aead_cp_boot_nonce` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_aead_cp_boot_nonce() {
    flash_simple_read(FLASH_ADDR + AEAD_CP_BOOT_NONCE_OFFSET, (uint32_t*)flash_status.aead_cp_boot_nonce, AEAD_NONCE_SIZE);
}

/**
 * @brief Retrieves AEAD AP boot nonce value from flash memory.
 * 
 * This function reads the AEAD AP boot nonce value from the specified flash address
 * and stores it in the global `flash_status.aead_ap_boot_nonce` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_aead_ap_boot_nonce() {
    flash_simple_read(FLASH_ADDR + AEAD_AP_BOOT_NONCE_OFFSET, (uint32_t*)flash_status.aead_ap_boot_nonce, AEAD_NONCE_SIZE);
}

/**
 * @brief Retrieves AEAD AP boot cipher text from flash memory.
 * 
 * This function reads the AEAD AP boot nonce value from the specified flash address
 * and stores it in the global `flash_status.aead_ap_boot_nonce` array.
 * 
 * @note Make sure to wipe the key using `crypto_wipe` after use.
 */
void retrive_aead_ap_boot_cipher_text() {
    flash_simple_read(FLASH_ADDR + AEAD_AP_BOOT_CIPHER_OFFSET, (uint32_t*)flash_status.aead_ap_boot_cipher, BOOT_MSG_CIPHER_TEXT_SIZE);
}

// write current value in flast_status to the flash memory
// for defense/normal mode and replace for the current design
#define WRITE_FLASH_MEMORY  \
    retrive_ap_priv_key();  \
    retrive_cp_pub_key();   \
    retrive_hash_key(); \
    retrive_hash_salt();    \
    retrive_pin_hash(); \
    retrive_token_hash();   \
    retrive_aead_key(); \
    retrive_aead_nonce();   \
    retrive_aead_cp_boot_nonce();   \
    retrive_aead_ap_boot_nonce();   \
    retrive_aead_ap_boot_cipher_text(); \
    flash_simple_erase_page(FLASH_ADDR);    \
    flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));  \
    crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));    \
    crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));  \
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));  \
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));    \
    crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));  \
    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));  \
    crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));  \
    crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));  \
    crypto_wipe(flash_status.aead_cp_boot_nonce, sizeof(flash_status.aead_cp_boot_nonce));  \
    crypto_wipe(flash_status.aead_ap_boot_nonce, sizeof(flash_status.aead_ap_boot_nonce));  \
    crypto_wipe(flash_status.aead_ap_boot_cipher, sizeof(flash_status.aead_ap_boot_cipher));

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {
    // Initialize the MPU
    mpu_init();

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // // Write Component IDs from flash if first boot e.g. flash unwritten
    // if (flash_status.flash_magic != FLASH_MAGIC) {
    //     print_debug("First boot, setting flash!\n");

    //     flash_status.flash_magic = FLASH_MAGIC;
    //     flash_status.component_cnt = COMPONENT_CNT;
    //     uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
    //     memcpy(flash_status.component_ids, component_ids, 
    //         COMPONENT_CNT*sizeof(uint32_t));

    //     flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    // }

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
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
        uint8_t aead_cp_nonce[] = {AEAD_NONCE_CP_BOOT};
        uint8_t aead_ap_nonce[] = {AEAD_NONCE_AP_BOOT};
        uint8_t aead_cipher_ap_boot[] = {AEAD_CIPHER_AP_BOOT};

        memcpy(flash_status.ap_priv_key, ap_private_key, PRIV_KEY_SIZE);
        memcpy(flash_status.cp_pub_key, cp_public_key, PUB_KEY_SIZE);
        memcpy(flash_status.hash_key, ap_hash_key, HASH_KEY_LEN);
        memcpy(flash_status.hash_salt, ap_hash_salt, HASH_SALT_LEN);
        memcpy(flash_status.pin_hash, ap_hash_pin, HASH_LEN);
        memcpy(flash_status.token_hash, ap_hash_token, HASH_LEN);
        memcpy(flash_status.aead_key, aead_key, AEAD_KEY_SIZE);
        memcpy(flash_status.aead_nonce, aead_nonce, AEAD_NONCE_SIZE);
        memcpy(flash_status.aead_cp_boot_nonce, aead_cp_nonce, AEAD_NONCE_SIZE);
        memcpy(flash_status.aead_ap_boot_nonce, aead_ap_nonce, AEAD_NONCE_SIZE);
        memcpy(flash_status.aead_ap_boot_cipher, aead_cipher_ap_boot, BOOT_MSG_CIPHER_TEXT_SIZE);


        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

        crypto_wipe(ap_private_key, sizeof(ap_private_key));
        crypto_wipe(cp_public_key, sizeof(cp_public_key));
        crypto_wipe(ap_hash_key, sizeof(ap_hash_key));
        crypto_wipe(ap_hash_salt, sizeof(ap_hash_salt));
        crypto_wipe(ap_hash_pin, sizeof(ap_hash_pin));
        crypto_wipe(ap_hash_token, sizeof(ap_hash_token));
        crypto_wipe(aead_key, sizeof(aead_key));
        crypto_wipe(aead_nonce, sizeof(aead_nonce));
        crypto_wipe(flash_status.ap_priv_key, sizeof(flash_status.ap_priv_key));
        crypto_wipe(flash_status.cp_pub_key, sizeof(flash_status.cp_pub_key));
        crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
        crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
        crypto_wipe(flash_status.pin_hash, sizeof(flash_status.pin_hash));
        crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
        crypto_wipe(flash_status.aead_key, sizeof(flash_status.aead_key));
        crypto_wipe(flash_status.aead_nonce, sizeof(flash_status.aead_nonce));
        crypto_wipe(flash_status.aead_cp_boot_nonce, sizeof(flash_status.aead_cp_boot_nonce));
        crypto_wipe(flash_status.aead_ap_boot_nonce, sizeof(flash_status.aead_ap_boot_nonce));
        crypto_wipe(flash_status.aead_ap_boot_cipher, sizeof(flash_status.aead_ap_boot_cipher));
    }
    
    // Initialize board link interface
    board_link_init();
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

/******************************** COMPONENT COMMS ********************************/

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message 
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
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
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // Example of how to utilize included simple_crypto.h
    #ifdef CRYPTO_EXAMPLE
    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char* data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    
    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext); 
    print_debug("Encrypted data: ");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results 
    uint8_t hash_out[HASH_SIZE];
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: ");
    print_hex_debug(hash_out, HASH_SIZE);
    
    // Decrypt the encrypted message and print out
    uint8_t decrypted[BLOCK_SIZE];
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    print_debug("Decrypted message: %s\r\n", decrypted);
    #endif

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
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
    char buf[50];
    recv_input("Enter pin: ", buf);
    if (!strcmp(buf, AP_PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf);
    if (!strcmp(buf, AP_TOKEN)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) {
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


// Replace a component if the Token is correct
void attempt_replace() {
    MXC_Delay(200);

    // buffer for host input
    char buf[HOST_INPUT_BUF_SIZE] = {0};

    // read host input
    recv_input("Enter token: ", buf);
    // RANDOM_DELAY_TINY;

    // length check
    if (strlen(buf) != TOKEN_LEN) {
        crypto_wipe(buf, HOST_INPUT_BUF_SIZE);
        // defense_mode();
        print_error("len\n");
        return;
    }

    MXC_Delay(50);

    // for hash the inputted token
    uint8_t hash[HASH_LEN] = {0};

    // configuration of Argon2
    crypto_argon2_config cac = {CRYPTO_ARGON2_ID, NB_BLOCKS_TOKEN, NB_PASSES, NB_LANES};
    uint8_t *workarea = malloc(1024 * cac.nb_blocks);
    retrive_hash_salt();
    crypto_argon2_inputs cai = {(const uint8_t *)buf, flash_status.hash_salt, TOKEN_LEN, sizeof(flash_status.hash_salt)};
    retrive_hash_key();
    crypto_argon2_extras cae = {flash_status.hash_key, NULL, sizeof(flash_status.hash_key), 0};

    // hash the inputted token
    crypto_argon2(hash, HASH_LEN, workarea, cac, cai, cae);

    // free and wipe
    free(workarea);
    crypto_wipe(flash_status.hash_salt, sizeof(flash_status.hash_salt));
    crypto_wipe(flash_status.hash_key, sizeof(flash_status.hash_key));
    crypto_wipe(buf, HOST_INPUT_BUF_SIZE);

    // mitigate brute-force
    // random_delay_us(1500000);
    MXC_Delay(50);

    // print_info("replace - 4\n");
    // compare the hash of inputted token with the stored corect token hash
    retrive_token_hash();

    if (crypto_verify64(hash, flash_status.token_hash)) {
        crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
        crypto_wipe(hash, sizeof(hash));
        print_error("Token\n");
        return;
    }

    // print_info("replace - 5\n");
    crypto_wipe(flash_status.token_hash, sizeof(flash_status.token_hash));
    crypto_wipe(hash, sizeof(hash));

    // input IDs from the host
    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;
    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);
    crypto_wipe(buf, HOST_INPUT_BUF_SIZE);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // print_info("replace - 7, id=%x\n", flash_status.component_ids[i]);
        if (flash_status.component_ids[i] == component_id_out) {
            // print_info("replace - 8, id=%x\n", flash_status.component_ids[i]);
            // find it, replace
            flash_status.component_ids[i] = component_id_in;
            WRITE_FLASH_MEMORY;
            // print replace success information
            print_success("Replace\n");
            MXC_Delay(500);
            return;
        }
    }
    print_error("ID\n");
    return;
}

// Replace a component if the PIN is correct
void attempt_replace1() {
    char buf[50];

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
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

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
    char buf[50];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
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
