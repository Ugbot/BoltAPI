# Bolt API — Linux build + demo server (HTTP/1.1 + HTTP/2 + HTTP/3 + WebRTC).
#
# This is the first time the Linux (epoll/io_uring) async-I/O backend is built
# and exercised — Bolt API is otherwise developed on Windows/MSVC.
#
#   docker build -t boltapi .
#   docker run --rm -p 8080:8080/tcp -p 8443:8443/tcp -p 8443:8443/udp \
#              -p 9000:9000/udp boltapi
#
# Then open http://localhost:8080/ in a browser. See RUNNING.md for the HTTP/2 +
# HTTP/3 (TLS) instructions and the Chrome flags for self-signed local certs.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS build

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates pkg-config \
        perl curl wget \
    && rm -rf /var/lib/apt/lists/*

# HTTP/3 needs OpenSSL's 3.5+ QUIC-TLS API (SSL_set_quic_tls_cbs / OSSL_DISPATCH);
# Ubuntu 24.04 ships 3.0, so build a matching OpenSSL from source into /opt/openssl.
ARG OPENSSL_VERSION=3.6.1
RUN curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o /tmp/openssl.tar.gz \
    && tar -xzf /tmp/openssl.tar.gz -C /tmp \
    && cd "/tmp/openssl-${OPENSSL_VERSION}" \
    && ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl \
                   --libdir=lib linux-x86_64 \
    && make -j"$(nproc)" && make install_sw \
    && rm -rf /tmp/openssl*

WORKDIR /src
# The Bolt submodule is expected checked out in the build context (extern/bolt).
COPY . .

# Configure + build against the freshly-built OpenSSL. HTTP/3 + WebRTC on,
# examples on, tests off (the Linux test lane is a separate target).
RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
        -DBOLTAPI_WITH_HTTP3=ON \
        -DBOLTAPI_WITH_WEBRTC=ON \
        -DBOLTAPI_BUILD_EXAMPLES=ON \
        -DBOLTAPI_BUILD_TESTS=OFF \
    && cmake --build build -j"$(nproc)"

# Self-signed cert for localhost so the browser can do HTTP/2 + HTTP/3 over TLS.
RUN mkdir -p /certs && LD_LIBRARY_PATH=/opt/openssl/lib OPENSSL_CONF=/dev/null \
    /opt/openssl/bin/openssl req -x509 -newkey ec \
        -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout /certs/key.pem -out /certs/cert.pem -days 365 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Ship the OpenSSL 3.6 runtime we built (the system libssl is 3.0).
COPY --from=build /opt/openssl/lib /opt/openssl/lib
COPY --from=build /src/build/ /app/bin/
COPY --from=build /src/testing/web /app/web
COPY --from=build /certs /app/certs

ENV LD_LIBRARY_PATH=/opt/openssl/lib \
    BOLTAPI_WEB_ROOT=/app/web \
    BOLTAPI_CERT=/app/certs/cert.pem \
    BOLTAPI_KEY=/app/certs/key.pem

# H1 (TCP 8080) · H2+H3 over TLS (TCP+UDP 8443) · WebRTC media/data (UDP 9000)
EXPOSE 8080/tcp 8443/tcp 8443/udp 9000/udp
ENTRYPOINT ["/app/bin/boltapi_docker_demo"]
