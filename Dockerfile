FROM mcr.microsoft.com/azurelinux/base/core:3.0.20261005-amd64@sha256:a66ca12ae8c8c464e00cc6cc7f9deff5d2dfcd0f1314ba5dac22034ef171d3ae AS crypto-deps

ARG BUILD_JOBS=4
ARG OPENSSL_ARCHIVE=openssl-3.6.5.tar.gz
ARG SCOSSL_ARCHIVE=symcrypt-openssl-1.11.2.tar.gz
RUN mkdir -p /build \
    && rpm -q SymCrypt SymCrypt-OpenSSL openssl-libs > /build/base-crypto-packages.txt \
    && sha256sum /usr/include/symcrypt* /usr/lib/libsymcrypt.so.103.8.0 > /build/base-symcrypt.sha256
RUN tdnf install -y gcc gcc-c++ make perl cmake python3 tar gzip binutils glibc-devel patch \
    && tdnf clean all
RUN tdnf install -y kernel-headers && tdnf clean all \
    && sha256sum -c /build/base-symcrypt.sha256

WORKDIR /usr/src/app
COPY sources.lock.json /build/sources.lock.json
COPY src/verify_sources.py /build/verify_sources.py
COPY downloads/ /build/downloads/
RUN python3 /build/verify_sources.py /build/sources.lock.json /build/downloads \
        "${OPENSSL_ARCHIVE}" "${SCOSSL_ARCHIVE}" \
    && mkdir -p openssl symcrypt-openssl \
    && tar -xzf "/build/downloads/${OPENSSL_ARCHIVE}" -C openssl --strip-components=1 \
    && tar -xzf "/build/downloads/${SCOSSL_ARCHIVE}" -C symcrypt-openssl --strip-components=1

WORKDIR /usr/src/app/openssl
COPY patches/ /build/patches/
RUN patch --batch --fuzz=0 -p1 < /build/patches/0001-azurelinux-kernel-fips.patch \
    && patch --batch --fuzz=0 -p1 < /build/patches/0002-azurelinux-provider-selection.patch \
    && ./Configure linux-x86_64 \
        --prefix=/usr/src/app/runtime/openssl \
        --openssldir=/usr/src/app/runtime/openssl/ssl \
        --libdir=lib shared no-tests \
    && make -j"${BUILD_JOBS}" \
    && make install_sw

ENV LD_LIBRARY_PATH=/usr/src/app/runtime/openssl/lib

WORKDIR /usr/src/app/symcrypt-openssl
COPY src/symcrypt_compat.h /build/symcrypt_compat.h
RUN cmake -S . -B /build/symcrypt-openssl \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-include /build/symcrypt_compat.h -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Werror=int-conversion" \
        -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,defs,-z,now" \
        -DCMAKE_TOOLCHAIN_FILE=/usr/src/app/symcrypt-openssl/cmake-toolchain/LinuxUserMode-AMD64.cmake \
        -DOPENSSL_ROOT_DIR=/usr/src/app/runtime/openssl \
        -DOPENSSL_INCLUDE_DIR=/usr/src/app/runtime/openssl/include \
        -DOPENSSL_CRYPTO_LIBRARY=/usr/src/app/runtime/openssl/lib/libcrypto.so \
        -DOPENSSL_SSL_LIBRARY=/usr/src/app/runtime/openssl/lib/libssl.so \
        -DSYMCRYPT_HEADER=/usr/include/symcrypt.h \
        -DSYMCRYPT_LIBRARY=/usr/lib/libsymcrypt.so \
    && cmake --build /build/symcrypt-openssl --target scossl_provider -j"${BUILD_JOBS}" \
    && cp /build/symcrypt-openssl/SymCryptProvider/symcryptprovider.so \
        /usr/src/app/runtime/openssl/lib/ossl-modules/

FROM crypto-deps AS probe
ENV OPENSSL_CONF=/usr/src/app/runtime/openssl/ssl/openssl.cnf \
    OPENSSL_MODULES=/usr/src/app/runtime/openssl/lib/ossl-modules
COPY openssl.cnf /usr/src/app/runtime/openssl/ssl/openssl.cnf
COPY symcrypt_prov.cnf /usr/src/app/runtime/openssl/ssl/symcrypt_prov.cnf
COPY src/provider_probe.c /build/provider_probe.c
COPY src/config_check.c /build/config_check.c
COPY src/validate_compatibility.py /build/validate_compatibility.py
COPY tests/validate_results.py /build/validate_results.py
COPY tests/test_fips_integration.py /build/test_fips_integration.py
COPY tests/fips_host_flag.c /build/fips_host_flag.c
COPY tests/fips_properties.c /build/fips_properties.c
RUN cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -D_AMD64_ \
        -I/usr/src/app/runtime/openssl/include \
        -L/usr/src/app/runtime/openssl/lib \
        -o /build/config-check /build/config_check.c -lcrypto /usr/lib/libsymcrypt.so \
    && cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
        -I/usr/src/app/runtime/openssl/include \
        -L/usr/src/app/runtime/openssl/lib \
        -o /usr/src/app/provider-probe /build/provider_probe.c -lcrypto \
    && sha256sum -c /build/base-symcrypt.sha256 \
    && python3 /build/validate_compatibility.py > /usr/src/app/runtime/compatibility.txt \
    && cat /usr/src/app/runtime/compatibility.txt \
    && LD_BIND_NOW=1 /build/config-check \
    && LD_BIND_NOW=1 /usr/src/app/runtime/openssl/bin/openssl list -providers -provider default -provider symcryptprovider \
    && cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -shared -fPIC \
        -o /build/fips-host-flag.so /build/fips_host_flag.c -ldl \
    && cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
        -I/usr/src/app/runtime/openssl/include \
        -L/usr/src/app/runtime/openssl/lib \
        -o /build/fips-properties /build/fips_properties.c -lcrypto \
    && python3 /build/test_fips_integration.py \
    && LD_BIND_NOW=1 /usr/src/app/provider-probe > /build/results.md \
    && python3 /build/validate_results.py /build/results.md
WORKDIR /usr/src/app
CMD ["/usr/src/app/provider-probe"]
