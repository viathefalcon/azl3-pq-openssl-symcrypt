FROM mcr.microsoft.com/azurelinux/base/core:3.0.20261005-amd64@sha256:a66ca12ae8c8c464e00cc6cc7f9deff5d2dfcd0f1314ba5dac22034ef171d3ae AS crypto-deps

ARG BUILD_JOBS=4
ARG OPENSSL_ARCHIVE=openssl-3.6.5.tar.gz
ARG SYMCRYPT_ARCHIVE=symcrypt-103.13.0.tar.gz
ARG SCOSSL_ARCHIVE=symcrypt-openssl-1.11.2.tar.gz
RUN tdnf install -y gcc gcc-c++ make perl cmake python3 tar gzip binutils glibc-devel \
    && tdnf clean all
RUN tdnf install -y kernel-headers && tdnf clean all

WORKDIR /usr/src/app
COPY sources.lock.json /build/sources.lock.json
COPY src/verify_sources.py /build/verify_sources.py
COPY downloads/ /build/downloads/
RUN python3 /build/verify_sources.py /build/sources.lock.json /build/downloads \
        "${OPENSSL_ARCHIVE}" "${SYMCRYPT_ARCHIVE}" "${SCOSSL_ARCHIVE}" \
    && mkdir -p openssl symcrypt symcrypt-openssl \
    && tar -xzf "/build/downloads/${OPENSSL_ARCHIVE}" -C openssl --strip-components=1 \
    && tar -xzf "/build/downloads/${SYMCRYPT_ARCHIVE}" -C symcrypt --strip-components=1 \
    && tar -xzf "/build/downloads/${SCOSSL_ARCHIVE}" -C symcrypt-openssl --strip-components=1

WORKDIR /usr/src/app/openssl
RUN ./Configure linux-x86_64 \
        --prefix=/usr/src/app/runtime/openssl \
        --openssldir=/usr/src/app/runtime/openssl/ssl \
        --libdir=lib shared no-tests \
    && make -j"${BUILD_JOBS}" \
    && make install_sw

ENV LD_LIBRARY_PATH=/usr/src/app/runtime/openssl/lib:/usr/src/app/runtime/symcrypt/lib
ENV SYMCRYPT_BRANCH=v103.13.0 \
    SYMCRYPT_COMMIT_HASH=286762b7730e2b780678f5ab11fef2b1bad639e0 \
    SYMCRYPT_COMMIT_TIMESTAMP=2026-08-05T21:48:57+00:00
WORKDIR /usr/src/app/symcrypt
RUN cmake -S . -B /build/symcrypt \
        -DCMAKE_BUILD_TYPE=Release \
        -DSYMCRYPT_FIPS_BUILD=OFF \
        -DSYMCRYPT_FIPS_POSTPROCESS=OFF \
        -DSYMCRYPT_UNIT_TESTS=OFF \
    && cmake --build /build/symcrypt --target symcrypt_generic_posix -j"${BUILD_JOBS}" \
    && mkdir -p /usr/src/app/runtime/symcrypt/lib \
    && cp -a /build/symcrypt/module/generic/libsymcrypt.so* /usr/src/app/runtime/symcrypt/lib/

WORKDIR /usr/src/app/symcrypt-openssl
RUN cmake -S . -B /build/symcrypt-openssl \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=/usr/src/app/symcrypt-openssl/cmake-toolchain/LinuxUserMode-AMD64.cmake \
        -DOPENSSL_ROOT_DIR=/usr/src/app/runtime/openssl \
        -DOPENSSL_INCLUDE_DIR=/usr/src/app/runtime/openssl/include \
        -DOPENSSL_CRYPTO_LIBRARY=/usr/src/app/runtime/openssl/lib/libcrypto.so \
        -DOPENSSL_SSL_LIBRARY=/usr/src/app/runtime/openssl/lib/libssl.so \
        -DSYMCRYPT_ROOT_DIR=/usr/src/app/symcrypt \
        -DSYMCRYPT_LIBRARY=/usr/src/app/runtime/symcrypt/lib/libsymcrypt.so \
    && cmake --build /build/symcrypt-openssl --target scossl_provider -j"${BUILD_JOBS}" \
    && cp /build/symcrypt-openssl/SymCryptProvider/symcryptprovider.so \
        /usr/src/app/runtime/openssl/lib/ossl-modules/

FROM crypto-deps AS probe
ENV OPENSSL_CONF=/usr/src/app/runtime/openssl/ssl/openssl.cnf \
    OPENSSL_MODULES=/usr/src/app/runtime/openssl/lib/ossl-modules
COPY openssl.cnf /usr/src/app/runtime/openssl/ssl/openssl.cnf
COPY src/provider_probe.c /build/provider_probe.c
COPY src/config_check.c /build/config_check.c
RUN cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
        -I/usr/src/app/runtime/openssl/include \
        -L/usr/src/app/runtime/openssl/lib \
        -o /build/config-check /build/config_check.c -lcrypto \
    && /build/config-check \
    && cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
        -I/usr/src/app/runtime/openssl/include \
        -L/usr/src/app/runtime/openssl/lib \
        -o /usr/src/app/provider-probe /build/provider_probe.c -lcrypto \
    && /usr/src/app/runtime/openssl/bin/openssl list -providers -provider default -provider symcryptprovider
WORKDIR /usr/src/app
CMD ["/usr/src/app/provider-probe"]
