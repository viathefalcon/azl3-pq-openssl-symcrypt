#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum operation_kind {
    EXCHANGE,
    SIGNATURE,
    KEM
};

enum fetch_kind {
    KEY_MANAGEMENT,
    KEY_EXCHANGE,
    SIGNATURE_METHOD,
    KEM_METHOD
};

struct test_case {
    const char *algorithm;
    const char *parameter;
    const char *key_type;
    const char *method;
    const char *group;
    const char *digest;
    enum operation_kind kind;
};

struct mode {
    const char *name;
    const char *properties;
    int load_symcrypt;
    int allow_unsupported;
};

struct run {
    const struct mode *mode;
    OSSL_LIB_CTX *libctx;
};

static const struct mode modes[] = {
    {"default-only", "provider=default", 0, 0},
    {"symcrypt-only", "provider=symcryptprovider", 1, 1},
    {"symcrypt-preferred", "?provider=symcryptprovider", 1, 0}
};

static const struct test_case cases[] = {
    {"ECDH", "P-256", "EC", "ECDH", "prime256v1", NULL, EXCHANGE},
    {"ECDH", "P-384", "EC", "ECDH", "secp384r1", NULL, EXCHANGE},
    {"ECDH", "P-521", "EC", "ECDH", "secp521r1", NULL, EXCHANGE},
    {"ECDSA", "P-256", "EC", "ECDSA", "prime256v1", "SHA256", SIGNATURE},
    {"ECDSA", "P-384", "EC", "ECDSA", "secp384r1", "SHA384", SIGNATURE},
    {"ECDSA", "P-521", "EC", "ECDSA", "secp521r1", "SHA512", SIGNATURE},
    {"X25519", "", "X25519", "X25519", NULL, NULL, EXCHANGE},
    {"X448", "", "X448", "X448", NULL, NULL, EXCHANGE},
    {"Ed25519", "", "ED25519", "ED25519", NULL, NULL, SIGNATURE},
    {"Ed448", "", "ED448", "ED448", NULL, NULL, SIGNATURE},
    {"ML-KEM", "512", "ML-KEM-512", "ML-KEM-512", NULL, NULL, KEM},
    {"ML-KEM", "768", "ML-KEM-768", "ML-KEM-768", NULL, NULL, KEM},
    {"ML-KEM", "1024", "ML-KEM-1024", "ML-KEM-1024", NULL, NULL, KEM},
    {"ML-DSA", "44", "ML-DSA-44", "ML-DSA-44", NULL, NULL, SIGNATURE},
    {"ML-DSA", "65", "ML-DSA-65", "ML-DSA-65", NULL, NULL, SIGNATURE},
    {"ML-DSA", "87", "ML-DSA-87", "ML-DSA-87", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHA2-128s", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHA2-128f", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHA2-192s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192s", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHA2-192f", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192f", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHA2-256s", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256s", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHA2-256f", "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256f", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHAKE-128s", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHAKE-128f", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHAKE-192s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHAKE-192f", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHAKE-256s", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s", NULL, NULL, SIGNATURE},
    {"SLH-DSA", "SHAKE-256f", "SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f", NULL, NULL, SIGNATURE}
};

static unsigned int ok_count;
static unsigned int unsupported_count;
static unsigned int not_run_count;
static unsigned int error_count;

static void markdown_cell(const char *text)
{
    const unsigned char *p;

    if (text == NULL)
        return;

    for (p = (const unsigned char *)text; *p != '\0'; ++p) {
        switch (*p) {
        case '&':
            fputs("&amp;", stdout);
            break;
        case '<':
            fputs("&lt;", stdout);
            break;
        case '>':
            fputs("&gt;", stdout);
            break;
        case '|':
            fputs("&#124;", stdout);
            break;
        case '\\':
            fputs("&#92;", stdout);
            break;
        default:
            if (*p < 0x20 || *p == 0x7f)
                printf("&#%u;", (unsigned int)*p);
            else
                putchar(*p);
        }
    }
}

static void result(const struct run *run, const struct test_case *test,
                   const char *operation, const char *status,
                   const char *provider, const char *detail)
{
    fputs("| ", stdout);
    markdown_cell(run->mode->name);
    fputs(" | ", stdout);
    markdown_cell(test->algorithm);
    fputs(" | ", stdout);
    markdown_cell(test->parameter);
    fputs(" | ", stdout);
    markdown_cell(operation);
    fputs(" | ", stdout);
    markdown_cell(status);
    fputs(" | ", stdout);
    markdown_cell(provider);
    fputs(" | ", stdout);
    markdown_cell(detail);
    fputs(" |\n", stdout);

    if (strcmp(status, "ok") == 0)
        ++ok_count;
    else if (strcmp(status, "unsupported") == 0)
        ++unsupported_count;
    else if (strcmp(status, "not_run") == 0)
        ++not_run_count;
    else
        ++error_count;
}

static void failure(const struct run *run, const struct test_case *test,
                    const char *operation, const char *provider,
                    const char *detail)
{
    result(run, test, operation, "error", provider, detail);
    fprintf(stderr, "%s %s %s %s: %s\n", run->mode->name, test->algorithm,
            test->parameter, operation, detail);
    ERR_print_errors_fp(stderr);
}

static void skipped(const struct run *run, const struct test_case *test,
                    const char *const *operations, size_t count)
{
    size_t i;

    for (i = 0; i < count; ++i)
        result(run, test, operations[i], "not_run", NULL, "prerequisite did not succeed");
}

static const char *provider_name(const OSSL_PROVIDER *provider)
{
    return provider == NULL ? NULL : OSSL_PROVIDER_get0_name(provider);
}

/* Return 1 when found, 0 only for OpenSSL's unsupported-fetch error, and -1 on other errors. */
static int fetch_provider(OSSL_LIB_CTX *libctx, enum fetch_kind kind,
                          const char *name, const char *properties,
                          const char **provider)
{
    EVP_KEYMGMT *keymgmt = NULL;
    EVP_KEYEXCH *keyexch = NULL;
    EVP_SIGNATURE *signature = NULL;
    EVP_KEM *kem = NULL;
    const OSSL_PROVIDER *selected = NULL;
    unsigned long error;

    ERR_clear_error();
    switch (kind) {
    case KEY_MANAGEMENT:
        keymgmt = EVP_KEYMGMT_fetch(libctx, name, properties);
        if (keymgmt != NULL)
            selected = EVP_KEYMGMT_get0_provider(keymgmt);
        break;
    case KEY_EXCHANGE:
        keyexch = EVP_KEYEXCH_fetch(libctx, name, properties);
        if (keyexch != NULL)
            selected = EVP_KEYEXCH_get0_provider(keyexch);
        break;
    case SIGNATURE_METHOD:
        signature = EVP_SIGNATURE_fetch(libctx, name, properties);
        if (signature != NULL)
            selected = EVP_SIGNATURE_get0_provider(signature);
        break;
    case KEM_METHOD:
        kem = EVP_KEM_fetch(libctx, name, properties);
        if (kem != NULL)
            selected = EVP_KEM_get0_provider(kem);
        break;
    }

    *provider = provider_name(selected);
    EVP_KEYMGMT_free(keymgmt);
    EVP_KEYEXCH_free(keyexch);
    EVP_SIGNATURE_free(signature);
    EVP_KEM_free(kem);
    if (*provider != NULL)
        return 1;

    error = ERR_peek_last_error();
    if (error != 0 && ERR_GET_LIB(error) == ERR_LIB_EVP &&
        ERR_GET_REASON(error) == ERR_R_UNSUPPORTED) {
        ERR_clear_error();
        return 0;
    }
    return -1;
}

static int expected_provider(const struct run *run, enum fetch_kind kind,
                             const char *name, const char **provider)
{
    int found;

    if (run->mode->load_symcrypt) {
        found = fetch_provider(run->libctx, kind, name,
                               "provider=symcryptprovider", provider);
        if (found != 0 || run->mode->allow_unsupported)
            return found;
    }

    return fetch_provider(run->libctx, kind, name, "provider=default", provider);
}

static int symcrypt_expected(const struct test_case *test)
{
    return strcmp(test->algorithm, "ECDH") == 0 ||
           strcmp(test->algorithm, "ECDSA") == 0 ||
           strcmp(test->algorithm, "X25519") == 0 ||
           strcmp(test->algorithm, "ML-KEM") == 0 ||
           strcmp(test->algorithm, "ML-DSA") == 0;
}

static int require_method(const struct run *run, const struct test_case *test,
                          enum fetch_kind kind, const char *name,
                          const char *operation, const char **expected)
{
    int found = expected_provider(run, kind, name, expected);

    if (found == 1)
        return 1;
    if (found == 0 && run->mode->allow_unsupported && !symcrypt_expected(test)) {
        result(run, test, operation, "unsupported", NULL,
               "no matching provider implementation");
        return 0;
    }
    failure(run, test, operation, NULL,
            found == 0 ? "required provider implementation is unavailable" :
                         "provider implementation fetch failed");
    return -1;
}

static int check_operation_provider(const struct run *run,
                                    const struct test_case *test,
                                    const char *operation, EVP_PKEY_CTX *ctx,
                                    const char *expected)
{
    const char *actual = ctx == NULL ? NULL : provider_name(EVP_PKEY_CTX_get0_provider(ctx));

    if (actual == NULL || strcmp(actual, expected) != 0) {
        failure(run, test, operation, actual, "unexpected operation provider");
        return 0;
    }
    return 1;
}

static int generate_key(const struct run *run, const struct test_case *test,
                        const char *operation, EVP_PKEY **key)
{
    const char *expected = NULL;
    const char *actual = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int available;
    int success = 0;

    available = require_method(run, test, KEY_MANAGEMENT, test->key_type,
                               operation, &expected);
    if (available != 1)
        return available;

    ctx = EVP_PKEY_CTX_new_from_name(run->libctx, test->key_type,
                                     run->mode->properties);
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        (test->group != NULL && EVP_PKEY_CTX_set_group_name(ctx, test->group) <= 0) ||
        EVP_PKEY_generate(ctx, key) <= 0) {
        failure(run, test, operation, NULL, "key generation failed");
        goto cleanup;
    }

    actual = provider_name(EVP_PKEY_get0_provider(*key));
    if (actual == NULL || strcmp(actual, expected) != 0) {
        failure(run, test, operation, actual, "unexpected key-management provider");
        goto cleanup;
    }
    result(run, test, operation, "ok", actual, NULL);
    success = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (!success) {
        EVP_PKEY_free(*key);
        *key = NULL;
        return -1;
    }
    return 1;
}

static int derive_once(const struct run *run, const struct test_case *test,
                       const char *operation, const char *expected,
                       EVP_PKEY *key, EVP_PKEY *peer,
                       unsigned char **secret, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(run->libctx, key,
                                                   run->mode->properties);
    size_t capacity = 0;
    int success = 0;

    if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0) {
        failure(run, test, operation, NULL, "key agreement initialization failed");
        goto cleanup;
    }
    if (!check_operation_provider(run, test, operation, ctx, expected))
        goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, NULL, &capacity) <= 0 || capacity == 0 ||
        (*secret = OPENSSL_malloc(capacity)) == NULL) {
        failure(run, test, operation, expected, "key agreement setup failed");
        goto cleanup;
    }
    *secret_len = capacity;
    if (EVP_PKEY_derive(ctx, *secret, secret_len) <= 0 ||
        *secret_len == 0 || *secret_len > capacity) {
        failure(run, test, operation, expected, "key agreement failed");
        goto cleanup;
    }
    result(run, test, operation, "ok", expected, NULL);
    success = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (!success) {
        OPENSSL_clear_free(*secret, capacity);
        *secret = NULL;
    }
    return success;
}

static void exercise_exchange(const struct run *run, const struct test_case *test,
                              EVP_PKEY *key)
{
    static const char *const after_peer[] = {"derive", "peer_derive", "shared_secret_check"};
    static const char *const after_derive[] = {"peer_derive", "shared_secret_check"};
    static const char *const after_peer_derive[] = {"shared_secret_check"};
    const char *expected = NULL;
    EVP_PKEY *peer = NULL;
    unsigned char *first = NULL;
    unsigned char *second = NULL;
    size_t first_len = 0;
    size_t second_len = 0;
    int available;

    if (generate_key(run, test, "peer_keygen", &peer) != 1) {
        skipped(run, test, after_peer, 3);
        goto cleanup;
    }
    available = require_method(run, test, KEY_EXCHANGE, test->method,
                               "derive", &expected);
    if (available != 1) {
        skipped(run, test, after_derive, 2);
        goto cleanup;
    }
    if (!derive_once(run, test, "derive", expected, key, peer, &first, &first_len)) {
        skipped(run, test, after_derive, 2);
        goto cleanup;
    }
    if (!derive_once(run, test, "peer_derive", expected, peer, key, &second, &second_len)) {
        skipped(run, test, after_peer_derive, 1);
        goto cleanup;
    }
    if (first_len != second_len || CRYPTO_memcmp(first, second, first_len) != 0)
        failure(run, test, "shared_secret_check", NULL, "derived secrets differ");
    else
        result(run, test, "shared_secret_check", "ok", NULL, "derived secrets match");

cleanup:
    OPENSSL_clear_free(first, first_len);
    OPENSSL_clear_free(second, second_len);
    EVP_PKEY_free(peer);
}

static void exercise_signature(const struct run *run, const struct test_case *test,
                               EVP_PKEY *key)
{
    static const unsigned char message[] = "OpenSSL provider exercise";
    static const unsigned char changed[] = "openSSL provider exercise";
    static const char *const after_sign[] = {"verify", "verify_invalid"};
    static const char *const after_verify[] = {"verify_invalid"};
    const char *expected = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    size_t signature_capacity = 0;
    int available;
    int verify_result;

    available = require_method(run, test, SIGNATURE_METHOD, test->method,
                               "sign", &expected);
    if (available != 1) {
        skipped(run, test, after_sign, 2);
        return;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestSignInit_ex(ctx, &pctx, test->digest,
                                             run->libctx, run->mode->properties,
                                             key, NULL) <= 0) {
        failure(run, test, "sign", NULL, "signature initialization failed");
        skipped(run, test, after_sign, 2);
        goto cleanup;
    }
    if (!check_operation_provider(run, test, "sign", pctx, expected)) {
        skipped(run, test, after_sign, 2);
        goto cleanup;
    }
    if (EVP_DigestSign(ctx, NULL, &signature_len, message, sizeof(message) - 1) <= 0 ||
        signature_len == 0) {
        failure(run, test, "sign", expected, "signing failed");
        skipped(run, test, after_sign, 2);
        goto cleanup;
    }
    signature_capacity = signature_len;
    signature = OPENSSL_malloc(signature_capacity);
    if (signature == NULL ||
        EVP_DigestSign(ctx, signature, &signature_len, message, sizeof(message) - 1) <= 0 ||
        signature_len == 0 || signature_len > signature_capacity) {
        failure(run, test, "sign", expected, "signing failed");
        skipped(run, test, after_sign, 2);
        goto cleanup;
    }
    result(run, test, "sign", "ok", expected, NULL);
    EVP_MD_CTX_free(ctx);
    ctx = EVP_MD_CTX_new();
    pctx = NULL;
    if (ctx == NULL || EVP_DigestVerifyInit_ex(ctx, &pctx, test->digest,
                                               run->libctx, run->mode->properties,
                                               key, NULL) <= 0) {
        failure(run, test, "verify", NULL, "verification initialization failed");
        skipped(run, test, after_verify, 1);
        goto cleanup;
    }
    if (!check_operation_provider(run, test, "verify", pctx, expected)) {
        skipped(run, test, after_verify, 1);
        goto cleanup;
    }
    if (EVP_DigestVerify(ctx, signature, signature_len, message, sizeof(message) - 1) != 1) {
        failure(run, test, "verify", expected, "valid signature was rejected");
        skipped(run, test, after_verify, 1);
        goto cleanup;
    }
    result(run, test, "verify", "ok", expected, NULL);
    EVP_MD_CTX_free(ctx);
    ctx = EVP_MD_CTX_new();
    pctx = NULL;
    if (ctx == NULL || EVP_DigestVerifyInit_ex(ctx, &pctx, test->digest,
                                               run->libctx, run->mode->properties,
                                               key, NULL) <= 0) {
        failure(run, test, "verify_invalid", NULL, "verification initialization failed");
        goto cleanup;
    }
    if (!check_operation_provider(run, test, "verify_invalid", pctx, expected))
        goto cleanup;
    verify_result = EVP_DigestVerify(ctx, signature, signature_len, changed,
                                     sizeof(changed) - 1);
    if (verify_result != 0)
        failure(run, test, "verify_invalid", expected,
                "modified message was not rejected cleanly");
    else {
        ERR_clear_error();
        result(run, test, "verify_invalid", "ok", expected, "modified message rejected");
    }

cleanup:
    OPENSSL_free(signature);
    EVP_MD_CTX_free(ctx);
}

static void exercise_kem(const struct run *run, const struct test_case *test,
                         EVP_PKEY *key)
{
    static const char *const after_encapsulate[] = {"decapsulate", "shared_secret_check"};
    static const char *const after_decapsulate[] = {"shared_secret_check"};
    const char *expected = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *first = NULL;
    unsigned char *second = NULL;
    size_t ciphertext_len = 0;
    size_t ciphertext_capacity = 0;
    size_t first_len = 0;
    size_t first_capacity = 0;
    size_t second_len = 0;
    size_t second_capacity = 0;
    int available;

    available = require_method(run, test, KEM_METHOD, test->method,
                               "encapsulate", &expected);
    if (available != 1) {
        skipped(run, test, after_encapsulate, 2);
        return;
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(run->libctx, key, run->mode->properties);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        failure(run, test, "encapsulate", NULL, "encapsulation initialization failed");
        skipped(run, test, after_encapsulate, 2);
        goto cleanup;
    }
    if (!check_operation_provider(run, test, "encapsulate", ctx, expected)) {
        skipped(run, test, after_encapsulate, 2);
        goto cleanup;
    }
    if (EVP_PKEY_encapsulate(ctx, NULL, &ciphertext_len, NULL, &first_len) <= 0 ||
        ciphertext_len == 0 || first_len == 0) {
        failure(run, test, "encapsulate", expected, "encapsulation setup failed");
        skipped(run, test, after_encapsulate, 2);
        goto cleanup;
    }
    ciphertext_capacity = ciphertext_len;
    first_capacity = first_len;
    ciphertext = OPENSSL_malloc(ciphertext_capacity);
    first = OPENSSL_malloc(first_capacity);
    if (ciphertext == NULL || first == NULL ||
        EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, first, &first_len) <= 0 ||
        ciphertext_len == 0 || ciphertext_len > ciphertext_capacity ||
        first_len == 0 || first_len > first_capacity) {
        failure(run, test, "encapsulate", expected, "encapsulation failed");
        skipped(run, test, after_encapsulate, 2);
        goto cleanup;
    }
    result(run, test, "encapsulate", "ok", expected, NULL);
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(run->libctx, key, run->mode->properties);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        failure(run, test, "decapsulate", NULL, "decapsulation initialization failed");
        skipped(run, test, after_decapsulate, 1);
        goto cleanup;
    }
    if (!check_operation_provider(run, test, "decapsulate", ctx, expected)) {
        skipped(run, test, after_decapsulate, 1);
        goto cleanup;
    }
    if (EVP_PKEY_decapsulate(ctx, NULL, &second_len, ciphertext, ciphertext_len) <= 0 ||
        second_len == 0) {
        failure(run, test, "decapsulate", expected, "decapsulation setup failed");
        skipped(run, test, after_decapsulate, 1);
        goto cleanup;
    }
    second_capacity = second_len;
    second = OPENSSL_malloc(second_capacity);
    if (second == NULL ||
        EVP_PKEY_decapsulate(ctx, second, &second_len, ciphertext, ciphertext_len) <= 0 ||
        second_len == 0 || second_len > second_capacity) {
        failure(run, test, "decapsulate", expected, "decapsulation failed");
        skipped(run, test, after_decapsulate, 1);
        goto cleanup;
    }
    result(run, test, "decapsulate", "ok", expected, NULL);
    if (first_len != second_len || CRYPTO_memcmp(first, second, first_len) != 0)
        failure(run, test, "shared_secret_check", NULL, "KEM secrets differ");
    else
        result(run, test, "shared_secret_check", "ok", NULL, "KEM secrets match");

cleanup:
    OPENSSL_free(ciphertext);
    OPENSSL_clear_free(first, first_capacity);
    OPENSSL_clear_free(second, second_capacity);
    EVP_PKEY_CTX_free(ctx);
}

static void exercise_case(const struct run *run, const struct test_case *test)
{
    static const char *const exchange_remaining[] = {
        "peer_keygen", "derive", "peer_derive", "shared_secret_check"
    };
    static const char *const signature_remaining[] = {"sign", "verify", "verify_invalid"};
    static const char *const kem_remaining[] = {"encapsulate", "decapsulate", "shared_secret_check"};
    EVP_PKEY *key = NULL;

    if (generate_key(run, test, "keygen", &key) != 1) {
        switch (test->kind) {
        case EXCHANGE:
            skipped(run, test, exchange_remaining, 4);
            break;
        case SIGNATURE:
            skipped(run, test, signature_remaining, 3);
            break;
        case KEM:
            skipped(run, test, kem_remaining, 3);
            break;
        }
        return;
    }
    switch (test->kind) {
    case EXCHANGE:
        exercise_exchange(run, test, key);
        break;
    case SIGNATURE:
        exercise_signature(run, test, key);
        break;
    case KEM:
        exercise_kem(run, test, key);
        break;
    }
    EVP_PKEY_free(key);
}

static int exercise_mode(const struct mode *mode)
{
    struct run run = {mode, NULL};
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *symcrypt_provider = NULL;
    size_t i;
    int success = 0;

    run.libctx = OSSL_LIB_CTX_new();
    if (run.libctx == NULL ||
        (default_provider = OSSL_PROVIDER_load(run.libctx, "default")) == NULL ||
        (mode->load_symcrypt &&
         (symcrypt_provider = OSSL_PROVIDER_load(run.libctx, "symcryptprovider")) == NULL)) {
        fprintf(stderr, "%s: could not initialize required providers\n", mode->name);
        ERR_print_errors_fp(stderr);
        ++error_count;
        goto cleanup;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        exercise_case(&run, &cases[i]);
    success = 1;

cleanup:
    if (symcrypt_provider != NULL)
        OSSL_PROVIDER_unload(symcrypt_provider);
    if (default_provider != NULL)
        OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(run.libctx);
    return success;
}

int main(void)
{
    size_t i;

    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)) {
        fprintf(stderr, "OpenSSL initialization failed\n");
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    if (OPENSSL_version_major() != 3 || OPENSSL_version_minor() != 6 ||
        OPENSSL_version_patch() != 5) {
        fprintf(stderr, "Expected OpenSSL 3.6.5, but loaded %s\n",
                OpenSSL_version(OPENSSL_VERSION));
        return EXIT_FAILURE;
    }

    fputs("OpenSSL: ", stdout);
    markdown_cell(OpenSSL_version(OPENSSL_VERSION));
    fputs("\n\n| Mode | Algorithm | Parameter | Operation | Status | Provider | Detail |\n"
          "| --- | --- | --- | --- | --- | --- | --- |\n", stdout);

    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        if (!exercise_mode(&modes[i]))
            break;
    }

    printf("\nSummary: %u ok, %u unsupported, %u not_run, %u errors.\n",
           ok_count, unsupported_count, not_run_count, error_count);
    if (fflush(stdout) != 0) {
        fprintf(stderr, "Could not write probe results to stdout\n");
        return EXIT_FAILURE;
    }
    return error_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
