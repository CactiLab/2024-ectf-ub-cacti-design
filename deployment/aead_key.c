#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "monocypher.h"

#define USAGE \
    "\n usage: aead_key key=%%s nonce=%%s\n"              \
    "\n acceptable parameters:\n"                      \
    "    key=%%s                e.g.: aead_key.bin\n"    \
    "    nonce=%%s                e.g.: aead_nonce.bin\n"    \
    "\n"
#define KEY_SIZE 32
#define NONCE_SIZE 24

struct options {
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
    if (argc != 3) {
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
        } else {
            printf(USAGE);
            exit(1);
        }
    }

    // define variables
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];

    // rand
    get_rand(key, sizeof(key));
    get_rand(nonce, sizeof(nonce));

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

    return 0;
}