#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "monocypher.h"

/*
 * global options
 */
struct options {
    const char* priv_filename; /* filename of the private key file     */
    const char* pub_filename;  /* filename of the public key file      */
};

#define USAGE \
    "\n usage: keygen priv=%%s pub=%%s\n"              \
    "\n acceptable parameters:\n"                      \
    "    priv=%%s               default: priv.bin\n"   \
    "    pub=%%s                default: pub.bin\n"    \
    "\n"

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
    int i;
    char *p, *q;
    struct options opt;

    uint8_t seed[32];              /* Random seed          */
    uint8_t sk[64];                /* secret key           */
    uint8_t pk[32];                /* Matching public key  */

    if (argc != 3) {
usage:
        printf(USAGE);
        return 1;
    }

    for (i = 1; i < argc; i++) {
            p = argv[i];
            if ((q = strchr(p, '=')) == NULL) {
                goto usage;
            }
            *q++ = '\0';
            if (strcmp(p, "priv") == 0) {
                opt.priv_filename = q;
            } else if (strcmp(p, "pub") == 0) {
                opt.pub_filename = q;
            } else {
                goto usage;
            }
    }

    get_rand(seed, sizeof(seed));

    crypto_eddsa_key_pair(sk, pk, seed);
    
    FILE* skFile = fopen(opt.priv_filename, "wb");
    if (skFile == NULL) {
        perror("Failed to open priv");
        exit(1);
    }
    fwrite(sk, sizeof(uint8_t), sizeof(sk), skFile);
    fclose(skFile);
    crypto_wipe(sk, sizeof(sk));

    FILE* pkFile = fopen(opt.pub_filename, "wb");
    if (pkFile == NULL) {
        perror("Failed to open pub");
        exit(1);
    }
    fwrite(pk, sizeof(uint8_t), sizeof(pk), pkFile);
    fclose(pkFile);
    crypto_wipe(pk, sizeof(pk));

    return 0;
}