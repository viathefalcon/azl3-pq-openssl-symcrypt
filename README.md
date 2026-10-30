# Azure Linux 3 OpenSSL and SymCrypt provider probe

This image builds OpenSSL 3.6.5, SymCrypt 103.13.0, and the SymCrypt-OpenSSL
1.11.2 provider from source on Azure Linux 3 x86-64. The source archives are
downloaded **on Windows** with vcpkg before WSLC builds the image; no source is
downloaded during the image build.

## Prerequisites

- Windows PowerShell 5.1 or later, WSL containers (`wslc.exe`), and an x86-64
  WSL container backend.
- Python 3 on Windows for the optional result-validation tests.
- Network access to the Azure Linux package repositories and the relevant
  source-asset locations.

The fetch script bootstraps the pinned upstream `vcpkg.exe` into this project's
`.vcpkg` directory and checks its SHA-256 and version before running it. No
separate vcpkg installation or neighboring project is required. Source
acquisition uses `vcpkg x-download`, not a vcpkg binary package or a port build.

## Fetch, build, and run

From this directory in PowerShell:

```powershell
.\fetch-sources.ps1

wslc build --progress plain -t azl3-openssl365:local .
wslc run --rm azl3-openssl365:local
```

The fetch script downloads each archive directly from its pinned upstream URL,
clearing vcpkg asset-source configuration so external caches are not used.
The local vcpkg executable and existing source archives are rehashed before
use. To download fresh copies of the tool and archives:

```powershell
.\fetch-sources.ps1 -Refresh
```

Refresh verifies each new download before replacing its cached copy. The image
build independently verifies all three source SHA-512 hashes. Commit IDs, URLs,
versions and hashes are pinned in the lock file. The base image is pinned by
digest; Azure Linux build packages are installed from the current configured
package repositories and are not individually pinned.

To save and validate the output, including the complete case matrix and
provider-selection expectations:

```powershell
wslc run --rm azl3-openssl365:local | Set-Content -Encoding utf8 .\results.md
if ($LASTEXITCODE -ne 0) { throw "The provider probe failed." }
python .\tests\validate_results.py .\results.md
python -m unittest discover -s .\tests -v
```

`wslc build --build-arg BUILD_JOBS=8 ...` can change the default of four build
jobs. Docker is not used.

## Layout and configuration

- Source trees remain at `/usr/src/app/openssl`, `/usr/src/app/symcrypt`, and
  `/usr/src/app/symcrypt-openssl`.
- Private binaries and libraries are under `/usr/src/app/runtime`; the Azure
  Linux system OpenSSL files are not replaced.
- The private OpenSSL configuration loads both the default and SymCrypt
  providers and prefers SymCrypt with `?provider=symcryptprovider`.
- `/usr/src/app/provider-probe` creates separate OpenSSL library contexts for
  the test modes instead of relying on the process-wide configuration.

SymCrypt itself is built independently; SymCrypt-OpenSSL is the adapter built
against both libraries. Its release supports ML-KEM and ML-DSA, as well as
classical algorithms. SymCrypt is built **without FIPS self-tests or FIPS
postprocessing** here. This experiment makes no FIPS validation or production
readiness claim. OpenSSL 3.6 reaches end of support on 1 November 2026.

## Test semantics and output

Stdout is Markdown: the OpenSSL version, a table with one row per operation,
and a summary of result counts. The table columns are `Mode`, `Algorithm`,
`Parameter`, `Operation`, `Status`, `Provider`, and `Detail`. An empty
parameter, provider, or detail cell means it is not applicable or not
available. Characters that could disrupt table cells are encoded as HTML
entities. Diagnostics and OpenSSL error stacks go to stderr.

Status is `ok`, `unsupported`, `not_run`, or `error`. An unavailable
implementation is `unsupported` only in strict SymCrypt mode; subsequent
dependent operations are `not_run`. Other unexpected failures or provider
selections make the program exit nonzero. The pinned provider is expected to
implement the listed ECDH, ECDSA, X25519, ML-KEM, and ML-DSA cases; their
absence is an error, not an expected unsupported result.

The modes are:

1. `default-only`: only the default provider is loaded, and operations require
   `provider=default`.
2. `symcrypt-only`: both providers are loaded for supporting dependencies, but
   each tested key/operation must match `provider=symcryptprovider`. This is a
   strict operation-provider query, not a claim that internal dependencies use
   no other provider.
3. `symcrypt-preferred`: both providers are loaded and the tested operation
   prefers `?provider=symcryptprovider`, falling back to default when no
   SymCrypt implementation is available.

The probe exercises ECDH and ECDSA on P-256/P-384/P-521, X25519/X448,
Ed25519/Ed448, all ML-KEM and ML-DSA parameter sets, and all 12 SLH-DSA
parameter sets. It compares derived or encapsulated secrets and verifies both
valid signatures and rejection of modified messages. This is an EVP algorithm
probe, not a TLS handshake or negotiated-cipher-suite test.

For key generation, attribution comes from the resulting key's key-management
provider. For agreement, signing, verification, encapsulation, and
decapsulation, attribution comes from `EVP_PKEY_CTX_get0_provider` **after the
operation is initialized**. Local secret comparisons have no provider.
Attribution does not trace the provider's internal digest, RNG, helper calls,
or individual machine instructions. Loading multiple providers does not
guarantee fallback for an algorithm whose selected implementation rejects a
particular parameter.
