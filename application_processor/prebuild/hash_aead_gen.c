#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../../deployment/monocypher.h"

#define USAGE \
    "\n usage: hash_gen hash_key=%%s hash_salt=%%s hash_pin=%%s hash_token=%%s nonce_ap=%%s cipher_ap_boot=%%s aead_key=%%s\n"              \
    "\n acceptable parameters:\n"                      \
    "    hash_key=%%s               e.g.: hash_key.bin\n"   \
    "    hash_salt=%%s                e.g.: hash_salt.bin\n"    \
    "    hash_pin=%%s                e.g.: hash_pin.bin\n"    \
    "    hash_token=%%s                e.g.: hash_salt.bin\n"    \
    "    nonce_ap=%%s                e.g.: nonce_ap.bin\n"    \
    "    cipher_ap_boot=%%s                e.g.: cipher_ap_boot.bin\n"    \
    "    aead_key=%%s                e.g.: aead_key.bin\n"    \
    "\n"
#define PIN_LEN 6
#define TOKEN_LEN 16
#define KEY_LEN 128
#define SALT_LEN 128
#define NB_BLOCKS_PIN 108
#define NB_BLOCKS_TOKEN 108
#define HASH_LEN 64
#define AEAD_NONCE_SIZE                      24
#define AEAD_MAC_SIZE                        16
#define AEAD_KEY_SIZE            32
#define AP_BOOT_MSG_MAX_SIZE            64
#define MAC_SIZE                        16
#define BOOT_MSG_PLAIN_TEXT_SIZE        128
#define BOOT_MSG_CIPHER_TEXT_SIZE       BOOT_MSG_PLAIN_TEXT_SIZE + MAC_SIZE

struct options {
    const char* key_filename;
    const char* salt_filename;
    const char* hash_pin_filename;
    const char* hash_token_filename;
    const char* nonce_ap_filename;
    const char* cipher_ap_boot_filename;
    const char* aead_key_filename;
};

void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("0x%02x, ", buf[i]);
    printf("\n");
}

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

int main(int argc, char *argv[]) {
    // param check
    if (argc != 8) {
        printf(USAGE);
        exit(1);
    }

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
        if (strcmp(p, "hash_key") == 0) {
            opt.key_filename = q;
        } else if (strcmp(p, "hash_salt") == 0) {
            opt.salt_filename = q;
        } else if (strcmp(p, "hash_pin") == 0) {
            opt.hash_pin_filename = q;
        } else if (strcmp(p, "hash_token") == 0) {
            opt.hash_token_filename = q;
        } else if (strcmp(p, "nonce_ap") == 0) {
            opt.nonce_ap_filename = q;
        } else if (strcmp(p, "cipher_ap_boot") == 0) {
            opt.cipher_ap_boot_filename = q;
        } else if (strcmp(p, "aead_key") == 0) {
            opt.aead_key_filename = q;
        } else {
            printf(USAGE);
            exit(1);
        }
    }

    // rand
    uint8_t buf[KEY_LEN + SALT_LEN + AEAD_NONCE_SIZE];
    get_rand(buf, sizeof(buf));

    // write key
    FILE *key_file = fopen(opt.key_filename, "wb");
    if (key_file == NULL) {
        perror("Failed to open key file");
        exit(1);
    }
    fwrite(buf, sizeof(uint8_t), KEY_LEN, key_file);
    fclose(key_file);

    // write salt
    FILE *salt_file = fopen(opt.salt_filename, "wb");
    if (salt_file == NULL) {
        perror("Failed to open salt file");
        exit(1);
    }
    fwrite(buf + KEY_LEN, sizeof(uint8_t), SALT_LEN, salt_file);
    fclose(salt_file);

    // write nonce for ap boot message
    FILE *nonce_ap_file = fopen(opt.nonce_ap_filename, "wb");
    if (nonce_ap_file == NULL) {
        perror("Failed to open ap boot nonce file");
        exit(1);
    }
    fwrite(buf + KEY_LEN + SALT_LEN, sizeof(uint8_t), AEAD_NONCE_SIZE, nonce_ap_file);
    fclose(nonce_ap_file);

    // read pin, token, ap_boot_text plaintexts
    FILE *param_file = fopen("./inc/ectf_params.h", "r");
    if (param_file == NULL) {
        perror("Failed to open param file");
        exit(1);
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    uint8_t pin[PIN_LEN] = {0};
    uint8_t token[TOKEN_LEN * 3] = {0};
    uint8_t ap_boot_msg[AP_BOOT_MSG_MAX_SIZE] = {0};
    while ((read = getline(&line, &len, param_file)) != -1) {
        printf("line=%stheend\n", line);
        if ((p = strstr(line, "AP_PIN")) != NULL) {
            memcpy(pin, p + 8, PIN_LEN);
        } else if ((p = strstr(line, "AP_TOKEN")) != NULL) {
            p += strlen("AP_TOKEN");
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
            if (i > 16) {
                i = 16;
            }
            memcpy(token, q, i);
            token[i] = '\0';
            // token[i + 1] = '\0';
            printf("\n\n\n\n\n\n");
            print_hex(token, TOKEN_LEN);
        } else if ((p = strstr(line, "AP_BOOT_MSG")) != NULL) {
            p += strlen("AP_BOOT_MSG");
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
            memcpy(ap_boot_msg, q, i);
            ap_boot_msg[i] = '\0';
        }
    }
    fclose(param_file);

    // hash pin, token
    uint8_t hash_pin[HASH_LEN];
    uint8_t hash_token[HASH_LEN];
    uint8_t *workarea_pin = malloc(1024 * NB_BLOCKS_PIN);
    uint8_t *workarea_token = malloc(1024 * NB_BLOCKS_TOKEN);
    crypto_argon2_config cac_pin = {CRYPTO_ARGON2_ID, NB_BLOCKS_PIN, 3, 1};
    crypto_argon2_config cac_token = {CRYPTO_ARGON2_ID, NB_BLOCKS_TOKEN, 3, 1};
    crypto_argon2_inputs cai_pin = {pin, buf + KEY_LEN, PIN_LEN, SALT_LEN};
    crypto_argon2_inputs cai_token = {token, buf + KEY_LEN, TOKEN_LEN, SALT_LEN};
    crypto_argon2_extras cae = {buf, NULL, KEY_LEN, 0};
    crypto_argon2(hash_pin, HASH_LEN, workarea_pin, cac_pin, cai_pin, cae);
    crypto_argon2(hash_token, HASH_LEN, workarea_token, cac_token, cai_token, cae);

    // write hash pin
    FILE *hash_pin_file = fopen(opt.hash_pin_filename, "wb");
    if (hash_pin_file == NULL) {
        perror("Failed to open hash pin file");
        exit(1);
    }
    fwrite(hash_pin, sizeof(uint8_t), HASH_LEN, hash_pin_file);
    fclose(hash_pin_file);
    crypto_wipe(hash_pin, sizeof(hash_pin));
    crypto_wipe(pin, sizeof(pin));

    // write hash token
    FILE *hash_token_file = fopen(opt.hash_token_filename, "wb");
    if (hash_token_file == NULL) {
        perror("Failed to open hash token file");
        exit(1);
    }
    fwrite(hash_token, sizeof(uint8_t), HASH_LEN, hash_token_file);
    fclose(hash_token_file);
    crypto_wipe(hash_token, sizeof(hash_token));
    crypto_wipe(token, sizeof(token));

    uint8_t aead_key[AEAD_KEY_SIZE];

    // load aead key
    FILE *aead_key_file = fopen(opt.aead_key_filename, "rb");
    if (aead_key_file == NULL) {
        perror("Failed to open the AEAD key file");
        exit(1);
    }
    int r = fread(aead_key, sizeof(uint8_t), AEAD_KEY_SIZE, aead_key_file);
    fclose(aead_key_file);
    if (r != AEAD_KEY_SIZE) {
        perror("AEAD key size is wrong in the AEAD key file");
    }

    uint8_t cipher_ap_boot_text[BOOT_MSG_CIPHER_TEXT_SIZE];

    // encrypt ap boot message
    crypto_aead_lock(cipher_ap_boot_text + MAC_SIZE, cipher_ap_boot_text, aead_key, buf + KEY_LEN + SALT_LEN, NULL, 0, ap_boot_msg, BOOT_MSG_PLAIN_TEXT_SIZE);

    // write encrypted ap boot message
    FILE *cipher_boot_text_file = fopen(opt.cipher_ap_boot_filename, "wb");
    if (cipher_boot_text_file == NULL) {
        perror("Failed to open cipher boot message file");
        exit(1);
    }
    fwrite(cipher_ap_boot_text, sizeof(uint8_t), BOOT_MSG_CIPHER_TEXT_SIZE, cipher_boot_text_file);
    fclose(cipher_boot_text_file);

    crypto_wipe(ap_boot_msg, AP_BOOT_MSG_MAX_SIZE);
    crypto_wipe(aead_key, AEAD_KEY_SIZE);
    crypto_wipe(buf, sizeof(buf));

    return 0;
}