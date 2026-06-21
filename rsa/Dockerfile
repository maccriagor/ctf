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
# └── main.cpp      ← your rsa15360_benchmark.cpp renamed to main.cpp

# Copy your main.cpp
COPY main.cpp .

# Compile and link against static OpenSSL
RUN g++ -O2 -std=c++17 \
        main.cpp \
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
