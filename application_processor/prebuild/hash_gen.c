#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "monocypher.h"

#define USAGE \
    "\n usage: hash_gen hash_key=%%s hash_salt=%%s hash_pin=%%s hash_token=%%s\n"              \
    "\n acceptable parameters:\n"                      \
    "    hash_key=%%s               e.g.: hash_key.bin\n"   \
    "    hash_salt=%%s                e.g.: hash_salt.bin\n"    \
    "    hash_pin=%%s                e.g.: hash_pin.bin\n"    \
    "    hash_token=%%s                e.g.: hash_salt.bin\n"    \
    "\n"
#define PIN_LEN 6
#define TOKEN_LEN 16
#define KEY_LEN 128
#define SALT_LEN 128
#define NB_BLOCKS 115
#define HASH_LEN 64

struct options {
    const char* key_filename;
    const char* salt_filename;
    const char* hash_pin_filename;
    const char* hash_token_filename; 
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
    // param check
    if (argc != 5) {
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
        } else {
            printf(USAGE);
            exit(1);
        }
    }

    // rand
    uint8_t buf[KEY_LEN + SALT_LEN];
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

    // read pin, token plintexts
    FILE *param_file = fopen("./inc/ectf_params.h", "r");
    if (param_file == NULL) {
        perror("Failed to open param file");
        exit(1);
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    uint8_t pin[PIN_LEN] = {0};
    uint8_t token[TOKEN_LEN] = {0};
    while ((read = getline(&line, &len, param_file)) != -1) {
        if ((p = strstr(line, "AP_PIN")) != NULL) {
            memcpy(pin, p + 8, PIN_LEN);
        } else if ((p = strstr(line, "AP_TOKEN")) != NULL) {
            memcpy(token, p + 10, TOKEN_LEN);
        }
    }
    fclose(param_file);

    // hash pin, token
    uint8_t hash_pin[HASH_LEN];
    uint8_t hash_token[HASH_LEN];
    uint8_t *workarea = malloc(1024 * NB_BLOCKS);
    crypto_argon2_config cac = {CRYPTO_ARGON2_ID, NB_BLOCKS, 3, 1};
    crypto_argon2_inputs cai_pin = {pin, buf + KEY_LEN, PIN_LEN, SALT_LEN};
    crypto_argon2_inputs cai_token = {token, buf + KEY_LEN, TOKEN_LEN, SALT_LEN};
    crypto_argon2_extras cae = {buf, NULL, KEY_LEN, 0};
    crypto_argon2(hash_pin, HASH_LEN, workarea, cac, cai_pin, cae);
    crypto_argon2(hash_token, HASH_LEN, workarea, cac, cai_token, cae);
    printf("DEBUG:\n");
    printf("PIN: ");
    print_hex(pin, PIN_LEN);
    printf("\nToken: ");
    print_hex(hash_token, TOKEN_LEN);
    printf("\nKey: ");
    print_hex(buf, KEY_LEN);
    printf("\nSalt: ");
    print_hex(buf + KEY_LEN, SALT_LEN);
    printf("\nHash PIN: ");
    print_hex(hash_pin, HASH_LEN);
    printf("\nHash Token: ");
    print_hex(hash_token, HASH_LEN);
    printf("DEBUG END\n");

    // write hash pin
    FILE *hash_pin_file = fopen(opt.hash_pin_filename, "wb");
    if (hash_pin_file == NULL) {
        perror("Failed to open hash pin file");
        exit(1);
    }
    fwrite(hash_pin, sizeof(uint8_t), HASH_LEN, hash_pin_file);
    fclose(hash_pin_file);

    // write hash token
    FILE *hash_token_file = fopen(opt.hash_token_filename, "wb");
    if (hash_token_file == NULL) {
        perror("Failed to open hash token file");
        exit(1);
    }
    fwrite(hash_token, sizeof(uint8_t), HASH_LEN, hash_token_file);
    fclose(hash_token_file);

    return 0;
}