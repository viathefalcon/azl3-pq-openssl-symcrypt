#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    int expected;

    if (argc != 2 || (strcmp(argv[1], "0") != 0 && strcmp(argv[1], "1") != 0))
        return 2;
    expected = strcmp(argv[1], "1") == 0;
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_default_properties_is_fips_enabled(NULL) != expected) {
        fprintf(stderr, "Unexpected default fips property: expected %d\n", expected);
        return 1;
    }
    return 0;
}
