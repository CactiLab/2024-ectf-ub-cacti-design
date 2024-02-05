#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "monocypher-ed25519.h"
#include "monocypher.h"

void generateRandomNumber(uint8_t* buffer, int size) {
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

void printSignatureHex(const uint8_t* signature, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
}

int main() {
    uint8_t seed[32];                          /* Random seed         */
    uint8_t sk[64];                            /* secret key          */
    uint8_t pk[32];                            /* Matching public key */
    const uint8_t message[11] = "Lorem ipsu";  /* Message to sign */
    const uint8_t msg_fake[11] = "Lorem.ipsu"; /* Fake message to sign */
    uint8_t signature[64];                     /* Signature buffer   */
    generateRandomNumber(seed, sizeof(seed));

    crypto_eddsa_key_pair(sk, pk, seed);

    // Save secret key to sk.bin
    FILE* skFile = fopen("sk.bin", "wb");
    if (skFile == NULL) {
        perror("Failed to open sk.bin");
        exit(1);
    }
    fwrite(sk, sizeof(uint8_t), sizeof(sk), skFile);
    fclose(skFile);

    // Save public key to pk.bin
    FILE* pkFile = fopen("pk.bin", "wb");
    if (pkFile == NULL) {
        perror("Failed to open pk.bin");
        exit(1);
    }
    fwrite(pk, sizeof(uint8_t), sizeof(pk), pkFile);
    fclose(pkFile);

    crypto_eddsa_sign(signature, sk, message, 10);

    printSignatureHex(signature, sizeof(signature));

    if (crypto_eddsa_check(signature, pk, msg_fake, 10)) {
        /* Message is corrupted, do not trust it */
        printf("Message is corrupted, do not trust it\n");
    } else {
        /* Message is genuine */
        printf("Message is genuine\n");
    }

    return 0;
}
