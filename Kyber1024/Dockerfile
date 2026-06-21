# ─────────────────────────────────────────
# Stage 1: Build OpenSSL from source
# ─────────────────────────────────────────
FROM ubuntu:22.04 AS openssl-builder

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/openssl

RUN wget https://www.openssl.org/source/openssl-3.6.1.tar.gz && \
    tar -xzf openssl-3.6.1.tar.gz && \
    cd openssl-3.6.1 && \
    ./config --prefix=/opt/openssl --openssldir=/opt/openssl/ssl no-shared && \
    make -j$(nproc) && \
    make install_sw


# ─────────────────────────────────────────
# Stage 2: Build the main program
# ─────────────────────────────────────────
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled OpenSSL from stage 1
COPY --from=openssl-builder /opt/openssl /opt/openssl

WORKDIR /app

# Expected directory layout on host before building:
#
# /app
# ├── main.cpp
# ├── kem/                        ← from PQClean/crypto_kem/ml-kem-1024/clean/
# │   ├── api.h
# │   ├── kem.c
# │   └── ... (all *.c and *.h)
# ├── sign/                       ← from PQClean/crypto_sign/ml-dsa-87/clean/
# │   ├── api.h
# │   ├── sign.c
# │   └── ... (all *.c and *.h)
# └── common/                     ← from PQClean/common/
#     ├── fips202.h
#     ├── fips202.c
#     ├── compat.h
#     ├── randombytes.h
#     ├── randombytes.c
#     ├── sha2.h
#     └── sha2.c

# Copy source tree into container
# Install git (needed to fetch PQClean)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone PQClean
RUN git clone https://github.com/PQClean/PQClean.git

# Copy only the needed parts into expected layout
RUN mkdir kem sign common && \
    cp -r PQClean/crypto_kem/ml-kem-1024/clean/* kem/ && \
    cp -r PQClean/crypto_sign/ml-dsa-87/clean/* sign/ && \
    cp -r PQClean/common/* common/

# Copy your main.cpp
COPY main.cpp .

# ── Collect all PQClean C sources ──────────────────────────────────────────────
# Compile each *.c in kem/, sign/, common/ into object files, then
# compile main.cpp and link everything together with static OpenSSL.
RUN set -e; \
    \
    KEM_SRCS=$(find kem/ -name "*.c"); \
    SIGN_SRCS=$(find sign/ -name "*.c"); \
    COMMON_SRCS=$(find common/ -name "*.c" \
        ! -path "*/keccak2x/*" \
        ! -path "*/keccak4x/*"); \
    \
    for src in $KEM_SRCS $SIGN_SRCS $COMMON_SRCS; do \
        obj="${src%.c}.o"; \
        gcc -O2 -c "$src" \
            -I. \
            -Ikem -Isign -Icommon \
            -I/opt/openssl/include \
            -o "$obj"; \
    done; \
    \
    OBJS=$(find kem/ sign/ common/ -name "*.o"); \
    \
    g++ -O2 -std=c++17 \
        main.cpp \
        $OBJS \
        -I. \
        -Ikem -Isign -Icommon \
        -I/opt/openssl/include \
        -L/opt/openssl/lib64 \
        -lssl -lcrypto \
        -lpthread -ldl \
        -o app


# ─────────────────────────────────────────
# Stage 3: Minimal runtime image
# ─────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/app .

CMD ["./app"]
