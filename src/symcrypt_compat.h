#ifndef SYMCRYPT_COMPAT_H
#define SYMCRYPT_COMPAT_H

#include <stddef.h>
#include <symcrypt.h>

/* SymCrypt 103.8 documents these external sizes but does not name the constants.
 * config-check verifies them against the installed module's sizing API. */
#ifndef SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE
#define SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE 32
#endif
#ifndef SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44
#define SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44 1312
#endif
#ifndef SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65
#define SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65 1952
#endif
#ifndef SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87
#define SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87 2592
#endif

#endif
