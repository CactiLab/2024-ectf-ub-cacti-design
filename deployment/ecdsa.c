// #include "mbedtls/build_info.h"

// #include "mbedtls/platform.h"

// #include "mbedtls/pk.h"
// #include "mbedtls/entropy.h"
// #include "mbedtls/ctr_drbg.h"
// #include "mbedtls/ecdsa.h"
// #include "mbedtls/sha256.h"

// #include <string.h>
// #include <unistd.h>

// #define DEV_RANDOM_THRESHOLD        32
// #define ECPARAMS MBEDTLS_ECP_DP_SECP256R1

// int dev_random_entropy_poll(void *data, unsigned char *output,
//                             size_t len, size_t *olen)
// {
//     FILE *file;
//     size_t ret, left = len;
//     unsigned char *p = output;
//     ((void) data);

//     *olen = 0;

//     file = fopen("/dev/random", "rb");
//     if (file == NULL) {
//         return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
//     }

//     while (left > 0) {
//         /* /dev/random can return much less than requested. If so, try again */
//         ret = fread(p, 1, left, file);
//         if (ret == 0 && ferror(file)) {
//             fclose(file);
//             return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
//         }

//         p += ret;
//         left -= ret;
//         sleep(1);
//     }
//     fclose(file);
//     *olen = len;

//     return 0;
// }

// static void dump_buf(const char *title, unsigned char *buf, size_t len)
// {
//     size_t i;

//     mbedtls_printf("%s", title);
//     for (i = 0; i < len; i++) {
//         mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
//                        "0123456789ABCDEF" [buf[i] % 16]);
//     }
//     mbedtls_printf("\n");
// }

// void print_key_info(const mbedtls_ecp_keypair *key) {
//     mbedtls_printf("curve: %s\n",
//                     mbedtls_ecp_curve_info_from_grp_id(key->MBEDTLS_PRIVATE(grp).id)->name);
//     mbedtls_mpi_write_file("X_Q:   ", &key->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), 16, NULL);
//     mbedtls_mpi_write_file("Y_Q:   ", &key->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), 16, NULL);
//     mbedtls_mpi_write_file("D:     ", &key->MBEDTLS_PRIVATE(d), 16, NULL);
// }

// static int read_public_key(mbedtls_ecp_keypair *ecp, const char *pub_file)
// {
//     FILE *file;
//     unsigned char key_buf[64 + 1];
//     size_t bytes_read;
//     int ret;

//     if ((file = fopen(pub_file, "rb")) == NULL) {
//         mbedtls_printf("failed\n  ! Could not open %s\n", pub_file);
//         return -1;
//     }

//     // Read the public key
//     bytes_read = fread(key_buf, 1, sizeof(key_buf), file);
//     if (bytes_read < sizeof(key_buf)) {
//         if (feof(file)) {
//             mbedtls_printf("failed\n  ! Premature end of file. Expected 64 + 1 bytes, got %zu.\n", bytes_read);
//         } else {
//             mbedtls_printf("failed\n  ! Failed to read public key file");
//         }
//         fclose(file);
//         return -1;
//     }
//     fclose(file);

//     if ((ret = mbedtls_ecp_point_read_binary(&ecp->MBEDTLS_PRIVATE(grp), 
//                                             &ecp->MBEDTLS_PRIVATE(Q), key_buf, bytes_read)) != 0) {
//         mbedtls_printf("failed\n  ! mbedtls_ecp_point_read_binary returned  -0x%X\n", -ret);
//         return ret;
//     }

//     if ((ret = mbedtls_ecp_check_pubkey(&ecp->MBEDTLS_PRIVATE(grp), &ecp->MBEDTLS_PRIVATE(Q))) != 0) {
//         mbedtls_printf("failed\n  ! mbedtls_ecp_check_pubkey returned  -0x%X\n", -ret);
//         return ret;
//     }

//     return 0;
// }

// static int read_priv_key(mbedtls_ecp_keypair *ecp, const char *priv_file)
// {
//     FILE *file;
//     unsigned char key_buf[32];
//     size_t bytes_read;
//     int ret;

//     if ((file = fopen(priv_file, "rb")) == NULL) {
//         mbedtls_printf("failed\n  ! Could not open %s\n", priv_file);
//         return -1;
//     }

//     // Read the key file
//     bytes_read = fread(key_buf, 1, sizeof(key_buf), file);
//     if (bytes_read  < sizeof(key_buf)) {
//         if (feof(file)) {
//             printf("failed\n  ! Premature end of file. Expected 32 bytes, got %zu.\n", bytes_read);
//         } else {
//             perror("failed\n  ! Failed to read private key file");
//         }
//         fclose(file);
//         return ret;
//     }
//     fclose(file);

//     if ((ret = mbedtls_ecp_read_key(ECPARAMS, ecp, key_buf, sizeof(key_buf))) != 0) {
//         mbedtls_printf("failed\n  ! mbedtls_ecp_read_key returned  -0x%X\n", -ret);
//         return ret;
//     }

//     if ((ret = mbedtls_ecp_check_privkey(&ecp->MBEDTLS_PRIVATE(grp), &ecp->MBEDTLS_PRIVATE(d))) != 0) {
//         mbedtls_printf("failed\n  ! mbedtls_ecp_check_privkey returned  -0x%X\n", -ret);
//         return ret;
//     }

//     return 0;
// }


// int main(int argc, char *argv[])
// {
//     int ret = 1;
//     int exit_code = MBEDTLS_EXIT_FAILURE;
//     mbedtls_ecp_keypair key;
//     mbedtls_ecdsa_context ecdsa_ctx;
//     mbedtls_entropy_context entropy;
//     mbedtls_ctr_drbg_context ctr_drbg;
//     const char *pers = "ecdsa";
//     ((void)argv);

//     unsigned char message[100];
//     unsigned char hash[32];
//     unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
//     size_t sig_len;

//     memset(sig, 0, sizeof(sig));
//     memset(message, 0x25, sizeof(message));

//     mbedtls_ecp_keypair_init(&key);
//     mbedtls_ecp_group_load(&key.MBEDTLS_PRIVATE(grp), ECPARAMS);

//     mbedtls_ecdsa_init(&ecdsa_ctx);
//     mbedtls_ctr_drbg_init(&ctr_drbg);

//     if (argc != 1) {
//         mbedtls_printf("usage: ecdsa\n");
//         goto exit;
//     }

//     mbedtls_ecp_keypair_init(&key);
//     mbedtls_ecp_group_load(&key.MBEDTLS_PRIVATE(grp), ECPARAMS);

//     mbedtls_printf("  . Reading private key...");
//     if (read_priv_key(&key, "priv.bin") != 0) {
//         goto exit;
//     }
//     mbedtls_printf(" ok\n");

//     print_key_info(&key);

//     mbedtls_ecdsa_from_keypair(&ecdsa_ctx, &key);

//     mbedtls_printf("\n  . Seeding the random number generator...");
//     fflush(stdout);

//     mbedtls_entropy_init(&entropy);
//     if ((ret = mbedtls_entropy_add_source(&entropy, dev_random_entropy_poll,
//                                             NULL, DEV_RANDOM_THRESHOLD,
//                                             MBEDTLS_ENTROPY_SOURCE_STRONG)) != 0) {
//         mbedtls_printf(" failed\n  ! mbedtls_entropy_add_source returned -0x%04x\n",
//                         (unsigned int) -ret);
//         goto exit;
//     }

//     mbedtls_printf("\n    Using /dev/random, so can take a long time! ");
//     fflush(stdout);

//     if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
//                                      (const unsigned char *) pers,
//                                      strlen(pers))) != 0) {
//         mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
//                        (unsigned int) -ret);
//         goto exit;
//     }

//     /*
//      * Compute message hash
//      */
//     mbedtls_printf("\n  . Computing message hash...");
//     fflush(stdout);

//     if ((ret = mbedtls_sha256(message, sizeof(message), hash, 0)) != 0) {
//         mbedtls_printf(" failed\n  ! mbedtls_sha256 returned  -0x%X\n", -ret);
//         goto exit;
//     }

//     mbedtls_printf(" ok\n");
//     dump_buf("  + Hash: ", hash, sizeof(hash));

//     /*
//      * Sign message hash
//      */
//     mbedtls_printf("  . Signing message hash...");
//     fflush(stdout);

//     if ((ret = mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256,
//                                              hash, sizeof(hash),
//                                              sig, sizeof(sig), &sig_len,
//                                              mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
//         mbedtls_printf(" failed\n  ! mbedtls_ecdsa_write_signature returned -0x%X\n", -ret);
//         if (!mbedtls_ecdsa_can_do(key.MBEDTLS_PRIVATE(grp).id)) {
//             mbedtls_printf("  ! This curve is not supported for ECDSA\n");
//         }

//         goto exit;
//     }
//     mbedtls_printf(" ok (signature length = %u)\n", (unsigned int) sig_len);

//     dump_buf("  + Signature: ", sig, sig_len);

//     /*
//      * Verify signature
//      */
//     mbedtls_printf("\n  . Reading public key...");
//     mbedtls_ecp_keypair_init(&key);
//     mbedtls_ecp_group_load(&key.MBEDTLS_PRIVATE(grp), ECPARAMS);

//     if (read_public_key(&key, "pub.bin") != 0) {
//         goto exit;
//     }

//     mbedtls_ecdsa_from_keypair(&ecdsa_ctx, &key);
    
//     mbedtls_printf(" ok\n  . Verifying signature...");
//     fflush(stdout);

//     if ((ret = mbedtls_ecdsa_read_signature(&ecdsa_ctx,
//                                             hash, sizeof(hash),
//                                             sig, sig_len)) != 0) {
//         mbedtls_printf(" failed\n  ! mbedtls_ecdsa_read_signature returned  -0x%X\n", -ret);
//         goto exit;
//     }

//     mbedtls_printf(" ok\n");

//     print_key_info(&key);

//     exit_code = MBEDTLS_EXIT_SUCCESS;
// exit:

//     mbedtls_ecdsa_free(&ecdsa_ctx);
//     mbedtls_ctr_drbg_free(&ctr_drbg);
//     mbedtls_entropy_free(&entropy);

//     mbedtls_exit(exit_code);
// }