#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "monocypher.h"

#define USAGE \
    "\n usage: aead_key key=%%s nonce=%%s nonce_cp_boot=%%s\n"              \
    "\n acceptable parameters:\n"                      \
    "    key=%%s                e.g.: aead_key.bin\n"    \
    "    nonce=%%s                e.g.: aead_nonce.bin\n"    \
    "    nonce_cp_boot=%%s                e.g.: aead_nonce_cp_boot.bin\n"    \
    "\n"
#define KEY_SIZE 32
#define NONCE_SIZE 24

struct options {
    const char* key_filename;
    const char* nonce_filename;
    const char* nonce_cp_boot_filename;
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
        } else if (strcmp(p, "nonce_cp_boot") == 0) {
            opt.nonce_cp_boot_filename = q;
        } else {
            printf(USAGE);
            exit(1);
        }
    }

    // define variables
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t nonce_cp_boot[NONCE_SIZE];

    // rand
    get_rand(key, KEY_SIZE);
    sleep(1);
    get_rand(nonce, NONCE_SIZE);
    sleep(1);
    get_rand(nonce_cp_boot, NONCE_SIZE);

    // write key into the file
    FILE *key_file = fopen(opt.key_filename, "wb");
    if (key_file == NULL) {
        perror("Failed to open the key file");
        exit(1);
    }
    fwrite(key, sizeof(uint8_t), KEY_SIZE, key_file);
    fclose(key_file);

    // write nonce into the file
    FILE *nonce_file = fopen(opt.nonce_filename, "wb");
    if (nonce_file == NULL) {
        perror("Failed to open the nonce file");
        exit(1);
    }
    fwrite(nonce, sizeof(uint8_t), NONCE_SIZE, nonce_file);
    fclose(nonce_file);

    // write nonce_cp_boot into the file
    FILE *nonce_cp_boot_file = fopen(opt.nonce_cp_boot_filename, "wb");
    if (nonce_cp_boot_file == NULL) {
        perror("Failed to open the nonce_cp_boot file");
        exit(1);
    }
    fwrite(nonce_cp_boot, sizeof(uint8_t), NONCE_SIZE, nonce_cp_boot_file);
    fclose(nonce_cp_boot_file);

    return 0;
}