# Bolt API server endpoint for the QUIC interop runner
# (github.com/quic-interop/quic-interop-runner). Build from the repo root:
#   docker build -f testing/quic-interop/Dockerfile -t boltapi-qns .
# Serves /www over HTTP/3 on UDP 443. See testing/quic-interop/README.md.
# Multi-stage: the build stage's apt lists and OpenSSL sources never ship.
FROM ubuntu:24.04 AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang lld llvm cmake ninja-build make libstdc++-14-dev \
        ca-certificates curl perl zlib1g-dev
ENV CC=clang CXX=clang++
ARG OPENSSL_VERSION=3.6.1
RUN curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o /tmp/openssl.tar.gz \
    && tar -xzf /tmp/openssl.tar.gz -C /tmp \
    && cd "/tmp/openssl-${OPENSSL_VERSION}" \
    && ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl --libdir=lib no-docs \
    && make -j"$(nproc)" && make install_sw
WORKDIR /src
COPY . .
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" -DOPENSSL_ROOT_DIR=/opt/openssl \
        -DBOLTAPI_WITH_HTTP3=ON -DBOLTAPI_BUILD_EXAMPLES=ON -DBOLTAPI_BUILD_TESTS=OFF \
        -DBOLTAPI_INSTALL=OFF -DBOLT_INSTALL=OFF -DBOLT_BUILD_VULKAN=OFF \
        -DBOLTAPI_WARNINGS_AS_ERRORS=OFF \
    && cmake --build /build --target boltapi_quic_interop_server

FROM martenseemann/quic-network-simulator-endpoint:latest
COPY --from=build /opt/openssl/lib /opt/openssl/lib
COPY --from=build /build/boltapi_quic_interop_server /usr/local/bin/
COPY testing/quic-interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENV LD_LIBRARY_PATH=/opt/openssl/lib
ENTRYPOINT ["/run_endpoint.sh"]
