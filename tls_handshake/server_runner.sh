#!/bin/bash
# --- Environment Setup ---
export LIBOQS_DIR="/home/maccriagor/Documents/liboqs/build-opt"
OPENSSL_BIN="$(pwd)/openssl-build/bin/openssl"
export OPENSSL_CONF="$(pwd)/openssl-build/ssl/openssl.cnf"
export LD_LIBRARY_PATH="$(pwd)/openssl-build/lib64:$(pwd)/openssl-build/lib:$LIBOQS_DIR/lib:$LD_LIBRARY_PATH"
CERT_DIR="/home/maccriagor/Documents/step1_pqc_harness/certs"
PORT=44333

# NOTE: client script does 5 warmup + 500 benchmark connections, plus however
# many fit in its 3-second flood window. The accept cap here MUST exceed that
# total or the server will exit mid-benchmark and silently corrupt the
# flood-throughput numbers (and possibly the tail of the latency samples).
# 5 (warmup) + 500 (benchmark) + 2000 (flood headroom) = 2505, rounded up.
NUM_HANDSHAKES=3000  # Automatically shuts down after this many tests

if [ ! -x "$OPENSSL_BIN" ]; then
    echo "ERROR: openssl binary not found or not executable at: $OPENSSL_BIN"
    echo "Make sure you're running this script from the directory containing openssl-build/"
    exit 1
fi

if [ ! -d "$CERT_DIR" ]; then
    echo "ERROR: cert directory not found: $CERT_DIR"
    exit 1
fi

echo "Checking for trapped processes on port $PORT..."
PID_ON_PORT=$(lsof -t -i:$PORT)
if [ ! -z "$PID_ON_PORT" ]; then
    echo "--> Killing lingering server process ($PID_ON_PORT) occupying port $PORT..."
    kill -9 $PID_ON_PORT >/dev/null 2>&1
    sleep 1
fi

# --- Suite selection: use $1 if provided, otherwise prompt interactively ---
choice="$1"
if [ -z "$choice" ]; then
    echo "======================================================"
    echo " Select the Cipher Suite to host on this Server:"
    echo " --- LEVEL 1 Variants ---"
    echo " 1) RSA2048_X25519"
    echo " 2) ECDSA_P256"
    echo " 3) MLDSA44_MLKEM512"
    echo " 4) Hybrid_P256_MLKEM512"
    echo " --- LEVEL 3 Variants ---"
    echo " 5) RSA3072_X25519"
    echo " 6) ECDSA_P384"
    echo " 7) MLDSA65_MLKEM768"
    echo " 9) Hybrid_P384_MLKEM768"
    echo " --- LEVEL 5 Variants ---"
    echo " 10) RSA7680_X25519"
    echo " 11) ECDSA_P521"
    echo " 12) MLDSA87_MLKEM1024"
    echo " 13) Hybrid_P521_MLKEM1024"
    echo "======================================================"
    echo -n "Enter target suite number: "
    read choice
else
    echo "--> Suite number supplied as argument: $choice"
fi

case $choice in
    1) name="RSA2048_X25519"; sig="rsa2048"; kem="x25519" ;;
    2) name="ECDSA_P256"; sig="ecdsa"; kem="prime256v1" ;;
    3) name="MLDSA44_MLKEM512"; sig="mldsa44"; kem="mlkem512" ;;
    4) name="Hybrid_P256_MLKEM512"; sig="p256_mldsa44"; kem="p256_mlkem512" ;;
    5) name="RSA3072_X25519"; sig="rsa3072"; kem="x25519" ;;
    6) name="ECDSA_P384"; sig="ecdsa384"; kem="secp384r1" ;;
    7) name="MLDSA65_MLKEM768"; sig="mldsa65"; kem="mlkem768" ;;
    9) name="Hybrid_P384_MLKEM768"; sig="p384_mldsa65"; kem="p384_mlkem768" ;;
    10) name="RSA7680_X25519"; sig="rsa7680"; kem="x25519" ;;
    11) name="ECDSA_P521"; sig="ecdsa521"; kem="secp521r1" ;;
    12) name="MLDSA87_MLKEM1024"; sig="mldsa87"; kem="mlkem1024" ;;
    13) name="Hybrid_P521_MLKEM1024"; sig="p521_mldsa87"; kem="p521_mlkem1024" ;;
    *) echo "Invalid choice"; exit 1 ;;
esac

CERT_FILE="$CERT_DIR/server_${sig}.crt"
KEY_FILE="$CERT_DIR/server_${sig}.key"
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "ERROR: missing cert/key for sig=$sig"
    echo "  expected: $CERT_FILE"
    echo "  expected: $KEY_FILE"
    exit 1
fi

echo "======================================================"
echo " Launching Non-Blocking Async Server Engine: $name"
echo " sig=$sig  kem=$kem"
echo " Target testing cap: $NUM_HANDSHAKES connections"
echo " Listening on port: $PORT"
echo "======================================================"
# Executing s_server with your optimized high-concurrency parameters
"$OPENSSL_BIN" s_server -provider oqs -provider default \
                        -cert "$CERT_FILE" \
                        -key "$KEY_FILE" \
                        -accept $PORT \
                        -www \
                        -naccept $NUM_HANDSHAKES \
                        -groups "$kem" \
                        -tls1_3
echo ""
