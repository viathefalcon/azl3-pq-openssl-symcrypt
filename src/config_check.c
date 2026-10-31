#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "symcrypt_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_provider(const char *algorithm, const OSSL_PROVIDER *provider,
                           const char *expected)
{
    const char *actual = provider == NULL ? NULL : OSSL_PROVIDER_get0_name(provider);

    if (actual == NULL || strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s: expected provider %s, got %s\n", algorithm, expected,
                actual == NULL ? "(none)" : actual);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

static int check_symcrypt_sizes(void)
{
    static const struct {
        SYMCRYPT_MLDSA_PARAMS parameters;
        SIZE_T public_size;
    } cases[] = {
        {SYMCRYPT_MLDSA_PARAMS_MLDSA44, SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44},
        {SYMCRYPT_MLDSA_PARAMS_MLDSA65, SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65},
        {SYMCRYPT_MLDSA_PARAMS_MLDSA87, SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        SIZE_T seed_size = 0;
        SIZE_T public_size = 0;
        SYMCRYPT_ERROR seed_error = SymCryptMlDsaSizeofKeyFormatFromParams(
            cases[i].parameters, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, &seed_size);
        SYMCRYPT_ERROR public_error = SymCryptMlDsaSizeofKeyFormatFromParams(
            cases[i].parameters, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &public_size);
        if (seed_error != SYMCRYPT_NO_ERROR || public_error != SYMCRYPT_NO_ERROR ||
            seed_size != SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE ||
            public_size != cases[i].public_size) {
            fprintf(stderr, "SymCrypt ML-DSA parameter %d: size API mismatch "
                    "(errors %d/%d, seed %zu, public %zu)\n",
                    (int)cases[i].parameters, (int)seed_error, (int)public_error,
                    (size_t)seed_size, (size_t)public_size);
            return 0;
        }
    }
    puts("Distro SymCrypt sizing API matches the adapter compatibility constants.");
    return 1;
}

int main(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_KEM *kem = NULL;
    EVP_SIGNATURE *signature = NULL;
    int success = 0;

    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) ||
        !OSSL_PROVIDER_available(NULL, "default") ||
        !OSSL_PROVIDER_available(NULL, "symcryptprovider")) {
        fprintf(stderr, "OpenSSL configuration did not activate both providers\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!check_symcrypt_sizes())
        goto cleanup;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    kem = EVP_KEM_fetch(NULL, "ML-KEM-768", NULL);
    signature = EVP_SIGNATURE_fetch(NULL, "SLH-DSA-SHA2-128s", NULL);
    if (!expect_provider("AES-256-GCM", cipher == NULL ? NULL : EVP_CIPHER_get0_provider(cipher),
                         "symcryptprovider") ||
        !expect_provider("ML-KEM-768", kem == NULL ? NULL : EVP_KEM_get0_provider(kem),
                         "symcryptprovider") ||
        !expect_provider("SLH-DSA-SHA2-128s",
                         signature == NULL ? NULL : EVP_SIGNATURE_get0_provider(signature),
                         "default"))
        goto cleanup;

    puts("OpenSSL configuration activates both providers and prefers SymCrypt.");
    success = 1;

cleanup:
    EVP_CIPHER_free(cipher);
    EVP_KEM_free(kem);
    EVP_SIGNATURE_free(signature);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
