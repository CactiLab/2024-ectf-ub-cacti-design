#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "monocypher.h"

#define USAGE \
    "\n usage: enc_att_data final_cipher_text=%%s key=%%s nonce=%%s\n"              \
    "\n acceptable parameters:\n"                      \
    "    final_cipher_text=%%s       e.g.: final_cipher_text.bin\n"   \
    "    key=%%s                     e.g.: key.bin\n"    \
    "    nonce=%%s                   e.g.: nonce.bin\n"    \
    "\n"

#define KEY_SIZE                        32
#define NONCE_SIZE                      24
#define MAC_SIZE                        16
#define ATT_DATA_MAX_SIZE               64
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

struct options {
    const char* final_cipher_text_filename;
    const char* key_filename;
    const char* nonce_filename;
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

void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    // check args quantity
    if (argc != 4) {
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
        } else {
            printf(USAGE);
            exit(1);
        }
    }

    // define variables
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t final_text[FINAL_TEXT_SIZE];
    uint8_t plain_text[PLAIN_TEXT_SIZE];

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

    // contruct plain text
    FILE *param_file = fopen("./inc/ectf_params.h", "r");
    if (param_file == NULL) {
        perror("Failed to open the param file");
        exit(1);
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int mark = 0;
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
        }
    }
    fclose(param_file);
    if (mark != 7) {
        perror("Wrong macro definitions in the param file");
        exit(1);
    }

    // encrypt
    crypto_aead_lock(final_text + CIPHER_POS_IN_FINAL_TEXT, final_text + MAC_POS_IN_FINAL_TEXT, key, nonce, NULL, 0, plain_text, PLAIN_TEXT_SIZE);
    crypto_wipe(key, KEY_SIZE);
    crypto_wipe(nonce, NONCE_SIZE);
    crypto_wipe(plain_text, PLAIN_TEXT_SIZE);

    // write
    FILE *final_cipher_file = fopen(opt.final_cipher_text_filename, "wb");
    if (final_cipher_file == NULL) {
        perror("Failed to open the final cipher text file");
        exit(1);
    }
    fwrite(final_text, sizeof(uint8_t), FINAL_TEXT_SIZE, final_cipher_file);
    fclose(final_cipher_file);

    crypto_wipe(final_text, FINAL_TEXT_SIZE);

    return 0;
}