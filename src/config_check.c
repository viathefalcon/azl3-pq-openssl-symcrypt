#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

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
