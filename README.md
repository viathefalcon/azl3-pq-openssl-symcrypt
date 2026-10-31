# Azure Linux 3 OpenSSL and SymCrypt provider probe

This image builds OpenSSL 3.6.5 and the SymCrypt-OpenSSL 1.11.2 adapter
from source on Azure Linux 3 x86-64. The adapter uses the pinned base image's
SymCrypt 103.8.0 headers and library; SymCrypt itself is not rebuilt.
The source archives are downloaded **on Windows** with vcpkg before WSLC builds
the image; no source is
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
build independently verifies both source SHA-512 hashes. Commit IDs, URLs,
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
jobs. Use `wslc.exe` for container construction and execution.

## Layout and configuration

- Source trees remain at `/usr/src/app/openssl` and
  `/usr/src/app/symcrypt-openssl`.
- Private binaries and libraries are under `/usr/src/app/runtime`; the Azure
  Linux system OpenSSL files are not replaced.
- The private adapter (`symcryptprovider.so`) is compiled against private
  OpenSSL and `/usr/include/symcrypt.h`, and links to `/usr/lib/libsymcrypt.so`.
  The base image's `libsymcrypt.so.103.8.0` is not rebuilt or postprocessed.
  The distro's existing `symcryptprovider.so` is not used by private OpenSSL.
- The private OpenSSL configuration loads both the default and SymCrypt
  providers and prefers SymCrypt with `?provider=symcryptprovider`.
- `/usr/src/app/provider-probe` creates separate OpenSSL library contexts for
  the test modes instead of relying on the process-wide configuration.

SymCrypt-OpenSSL is the adapter between OpenSSL's provider interface and
SymCrypt's API. Its release supports ML-KEM and ML-DSA, as well as classical
algorithms. Reusing the distro module preserves its existing FIPS mechanisms,
but does not establish approved-mode operation or certificate coverage for
this integration. Optional fallback to OpenSSL's default provider remains
intentional. This experiment makes no FIPS validation or production readiness
claim. OpenSSL 3.6 reaches end of support on 1 November 2026.

## Build-time compatibility gate

The build records the base crypto package versions and hashes all installed
SymCrypt headers and the module before installing build dependencies. It
rechecks those hashes after installation and before running the probes, failing
if those base artifacts changed.

Adapter 1.11.2 references four ML-DSA size constants absent from the 103.8
headers. `src/symcrypt_compat.h` supplies their values from the external formats
documented in those headers; it does not change the module or its function
declarations. The configuration check verifies all four values against the
installed module's `SymCryptMlDsaSizeofKeyFormatFromParams` API.

The adapter compiles using the distro headers with implicit function
declarations, incompatible pointer types, and integer/pointer conversions
treated as errors. Linking rejects undefined symbols and enables eager binding.
The ELF check runs `ldd -r` on private OpenSSL, the adapter, the configuration
check, and the probe; missing libraries, unresolved symbols/version requirements, or
resolution to a different OpenSSL/SymCrypt library fail the build.
Package identities and checked library paths are saved in
`/usr/src/app/runtime/compatibility.txt`.

With `LD_BIND_NOW=1`, the build then checks configuration/provider selection
and runs the complete operation matrix, validating the resulting Markdown
against `tests/validate_results.py`. Thus a successful build establishes
source API compatibility, ELF relocation compatibility, intended library
selection, and behavior for the tested operations. It is not proof of every
API interaction or FIPS compliance. Build tools remain sourced from unpinned
repositories, so this is a repeatable gate for the selected artifacts, not a
bit-for-bit reproducible build.

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
