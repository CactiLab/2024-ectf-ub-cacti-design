#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../../deployment/monocypher.h"

#define USAGE \
    "\n usage: enc_att_data final_cipher_text=%%s key=%%s nonce=%%s nonce_cp_boot=%%s boot_cipher=%%s\n"              \
    "\n acceptable parameters:\n"                      \
    "    final_cipher_text=%%s       e.g.: final_cipher_text.bin\n"   \
    "    key=%%s                     e.g.: key.bin\n"    \
    "    nonce=%%s                   e.g.: nonce.bin\n"    \
    "    nonce_cp_boot=%%s                   e.g.: nonce_cp_boot.bin\n"    \
    "    boot_cipher=%%s              e.g.: boot_cipher.bin\n"    \
    "\n"

#define KEY_SIZE                        32
#define NONCE_SIZE                      24
#define MAC_SIZE                        16
#define ATT_DATA_MAX_SIZE               64
#define CP_BOOT_MSG_MAX_SIZE            64
#define BOOT_MSG_PLAIN_TEXT_SIZE        128
#define BOOT_MSG_CIPHER_TEXT_SIZE       BOOT_MSG_PLAIN_TEXT_SIZE + MAC_SIZE
#define PADDING_SIZE                    16
#define FINAL_TEXT_SIZE                 ATT_DATA_MAX_SIZE * 3 + MAC_SIZE + 3 + PADDING_SIZE * 2
#define PLAIN_TEXT_SIZE                 ATT_DATA_MAX_SIZE * 3 + 3 + PADDING_SIZE * 2
#define MAC_POS_IN_FINAL_TEXT           0
#define CIPHER_POS_IN_FINAL_TEXT        MAC_SIZE
#define LOC_POS                         0
#define PADDING_1_POS                   ATT_DATA_MAX_SIZE
#define DATE_POS                        PADDING_1_POS + PADDING_SIZE
#define PADDING_2_POS                   DATE_POS + ATT_DATA_MAX_SIZE
#define CUSTOMER_POS                    PADDING_2_POS + PADDING_SIZE
#define LOC_LEN_POS                     CUSTOMER_POS + ATT_DATA_MAX_SIZE
#define DATE_LEN_POS                    LOC_LEN_POS + 1
#define CUSTOMER_LEN_POS                DATE_LEN_POS + 1
#define ENC_ATTESTATION_MAGIC           173
#define ENC_BOOT_MAGIC                  82

struct options {
    const char* final_cipher_text_filename;
    const char* key_filename;
    const char* nonce_filename;
    const char* nonce_cp_filename;
    const char* boot_cipher_filename;
};

void get_rand(uint8_t* buffer, int size) {
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom == -1) {
        perror("Failed to open /dev/urandom");
        exit(1);
    }

    ssize_t bytesRead = read(urandom, buffer, size);
    if (bytesRead == -1) {
        perror("Failed to read from /dev/urandom");
        exit(1);
    }

    close(urandom);
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

int main(int argc, char *argv[]) {
    // check args quantity
    if (argc != 6) {
        printf(USAGE);
        exit(1);
    }

    // get file names from args
    char *p, *q;
    struct options opt;
    for (int i = 1; i < argc; ++i) {
        p = argv[i];
        if ((q = strchr(p, '=')) == NULL) {
            printf(USAGE);
            exit(1);
        }
        *q = '\0';
        ++q;
        if (strcmp(p, "key") == 0) {
            opt.key_filename = q;
        } else if (strcmp(p, "nonce") == 0) {
            opt.nonce_filename = q;
        } else if (strcmp(p, "final_cipher_text") == 0) {
            opt.final_cipher_text_filename = q;
        } else if (strcmp(p, "boot_cipher") == 0) {
            opt.boot_cipher_filename = q;
        } else if (strcmp(p, "nonce_cp_boot") == 0) {
            opt.nonce_cp_filename = q;
        } else {
            printf(USAGE);
            exit(1);
        }
    }

    // define variables
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t nonce_cp_boot[NONCE_SIZE];
    uint8_t final_text[FINAL_TEXT_SIZE];
    uint8_t plain_text[PLAIN_TEXT_SIZE];
    uint8_t plain_boot_text[BOOT_MSG_PLAIN_TEXT_SIZE];
    uint8_t cipher_boot_text[BOOT_MSG_CIPHER_TEXT_SIZE];

    // fill plain_boot_text buffer with random value as the boot message won't be so long
    get_rand(plain_boot_text, BOOT_MSG_PLAIN_TEXT_SIZE);

    // load key
    FILE *key_file = fopen(opt.key_filename, "rb");
    if (key_file == NULL) {
        perror("Failed to open the key file");
        exit(1);
    }
    int r = fread(key, sizeof(uint8_t), KEY_SIZE, key_file);
    fclose(key_file);
    if (r != KEY_SIZE) {
        perror("Key size is wrong in the key file");
    }

    // load nonce
    FILE *nonce_file = fopen(opt.nonce_filename, "rb");
    if (nonce_file == NULL) {
        perror("Failed to open the nonce file");
        exit(1);
    }
    r = fread(nonce, sizeof(uint8_t), NONCE_SIZE, nonce_file);
    fclose(nonce_file);
    if (r != NONCE_SIZE) {
        perror("Nonce size is wrong in the nonce file");
    }

    // load nonce_cp
    FILE *nonce_cp_file = fopen(opt.nonce_cp_filename, "rb");
    if (nonce_cp_file == NULL) {
        perror("Failed to open the nonce_cp file");
        exit(1);
    }
    r = fread(nonce_cp_boot, sizeof(uint8_t), NONCE_SIZE, nonce_cp_file);
    fclose(nonce_cp_file);
    if (r != NONCE_SIZE) {
        perror("Nonce size is wrong in the nonce_cp file");
    }

    // contruct plain text (attest data)
    FILE *param_file = fopen("./inc/ectf_params.h", "r");
    if (param_file == NULL) {
        perror("Failed to open the param file");
        exit(1);
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int mark = 0;
    uint32_t comp_id = 0;
    char comp_id_str[64] = {0};
    while ((read = getline(&line, &len, param_file)) != -1) {
        if ((p = strstr(line, "ATTESTATION_LOC")) != NULL) {
            // p += strlen("ATTESTATION_LOC");
            while (*p != '\"') {
                ++p;
            }
            ++p;
            q = p;
            int i = 0;
            while (*p != '\"' && *p != '\n') {
                ++p;
                ++i;
            }
            memcpy(plain_text + LOC_POS, q, i);
            plain_text[LOC_LEN_POS] = i;
            get_rand(plain_text + LOC_POS + i, ATT_DATA_MAX_SIZE - i + PADDING_SIZE);
            mark += 1;
        } else if ((p = strstr(line, "ATTESTATION_DATE")) != NULL) {
            p += strlen("ATTESTATION_DATE");
            while (*p != '\"') {
                ++p;
            }
            ++p;
            q = p;
            int i = 0;
            while (*p != '\"' && *p != '\n') {
                ++p;
                ++i;
            }
            memcpy(plain_text + DATE_POS, q, i);
            plain_text[DATE_LEN_POS] = i;
            get_rand(plain_text + DATE_POS + i, ATT_DATA_MAX_SIZE - i + PADDING_SIZE);
            mark += 2;
        } else if ((p = strstr(line, "ATTESTATION_CUSTOMER")) != NULL) {
            p += strlen("ATTESTATION_CUSTOMER");
            while (*p != '\"') {
                ++p;
            }
            ++p;
            q = p;
            int i = 0;
            while (*p != '\"' && *p != '\n') {
                ++p;
                ++i;
            }
            memcpy(plain_text + CUSTOMER_POS, q, i);
            plain_text[CUSTOMER_LEN_POS] = i;
            get_rand(plain_text + CUSTOMER_POS + i, ATT_DATA_MAX_SIZE - i);
            mark += 4;
        } else if ((p = strstr(line, "COMPONENT_BOOT_MSG")) != NULL) {
            p += strlen("COMPONENT_BOOT_MSG");
            while (*p != '\"') {
                ++p;
            }
            ++p;
            q = p;
            int i = 0;
            while (*p != '\"' && *p != '\n') {
                ++p;
                ++i;
            }
            memcpy(plain_boot_text, q, i);
            plain_boot_text[i] = '\0';
            mark += 8;
        } else if ((p = strstr(line, "COMPONENT_ID")) != NULL) {
            p += strlen("COMPONENT_ID");
            while (*p != '0' && *p != '1' && *p != '2' && *p != '3' && *p != '4' && *p != '5' && *p != '6' && *p != '7' && *p != '8' && *p != '9') {
                ++p;
            }
            q = p;
            int i = 0;
            while (*p != '\0' && *p != '\n') {
                ++p;
                ++i;
            }
            memcpy(comp_id_str, q, i);
            comp_id_str[i] = '\0';
            if (comp_id_str[0] == '0' && (comp_id_str[1] == 'x' || comp_id_str[1] == 'X' )) {
                // hex
                comp_id = strtol(comp_id_str + 2, NULL, 16);
            } else {
                // dec
                comp_id = atoi(comp_id_str);
            }
            mark += 16;
        }
    }
    fclose(param_file);
    if (mark != 31) {
        perror("Wrong macro definitions in the param file");
        exit(1);
    }

    // tweak nonces
    convert_32_to_8(nonce, comp_id);
    nonce[4] = ENC_ATTESTATION_MAGIC;
    crypto_blake2b(nonce, NONCE_SIZE, nonce, NONCE_SIZE);
    convert_32_to_8(nonce_cp_boot, comp_id);
    nonce_cp_boot[4] = ENC_BOOT_MAGIC;
    crypto_blake2b(nonce_cp_boot, NONCE_SIZE, nonce_cp_boot, NONCE_SIZE);
    // encrypt (attest data)
    crypto_aead_lock(final_text + CIPHER_POS_IN_FINAL_TEXT, final_text + MAC_POS_IN_FINAL_TEXT, key, nonce, NULL, 0, plain_text, PLAIN_TEXT_SIZE);

    // encrypt (cp boot message)
    crypto_aead_lock(cipher_boot_text + MAC_SIZE, cipher_boot_text, key, nonce_cp_boot, NULL, 0, plain_boot_text, BOOT_MSG_PLAIN_TEXT_SIZE);
    
    // wipe key and nonces
    crypto_wipe(key, KEY_SIZE);
    crypto_wipe(nonce, NONCE_SIZE);
    crypto_wipe(nonce_cp_boot, NONCE_SIZE);
    crypto_wipe(plain_text, PLAIN_TEXT_SIZE);
    crypto_wipe(plain_boot_text, BOOT_MSG_PLAIN_TEXT_SIZE);


    // write encrypted attestation data
    FILE *final_cipher_file = fopen(opt.final_cipher_text_filename, "wb");
    if (final_cipher_file == NULL) {
        perror("Failed to open the final cipher text file");
        exit(1);
    }
    fwrite(final_text, sizeof(uint8_t), FINAL_TEXT_SIZE, final_cipher_file);
    fclose(final_cipher_file);

    crypto_wipe(final_text, FINAL_TEXT_SIZE);

    // write encrypted attestation data
    FILE *cipher_boot_file = fopen(opt.boot_cipher_filename, "wb");
    if (cipher_boot_file == NULL) {
        perror("Failed to open the boot cipher text file");
        exit(1);
    }
    fwrite(cipher_boot_text, sizeof(uint8_t), BOOT_MSG_CIPHER_TEXT_SIZE, cipher_boot_file);
    fclose(cipher_boot_file);

    crypto_wipe(cipher_boot_text, BOOT_MSG_CIPHER_TEXT_SIZE);

    return 0;
}