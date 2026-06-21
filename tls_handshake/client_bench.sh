#!/bin/bash
# --- Environment Setup ---
export LIBOQS_DIR="/home/maccriagor/Documents/liboqs/build-opt"
OPENSSL_BIN="$(pwd)/openssl-build/bin/openssl"
export OPENSSL_CONF="$(pwd)/openssl-build/ssl/openssl.cnf"
export LD_LIBRARY_PATH="$(pwd)/openssl-build/lib64:$(pwd)/openssl-build/lib:$LIBOQS_DIR/lib:$LD_LIBRARY_PATH"

CERT_DIR="$(pwd)/certs"
RESULTS_DIR="$(pwd)/results"
mkdir -p "$RESULTS_DIR"

PORT=44333
NUM_HANDSHAKES=500

if [ ! -x "$OPENSSL_BIN" ]; then
    echo "ERROR: openssl binary not found or not executable at: $OPENSSL_BIN"
    exit 1
fi

if [ ! -d "$CERT_DIR" ]; then
    echo "ERROR: cert directory not found: $CERT_DIR"
    exit 1
fi

# --- Suite selection: use $1 if provided, otherwise prompt interactively ---
choice="$1"
if [ -z "$choice" ]; then
    echo "======================================================"
    echo " Match the Suite currently running on your Server:"
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
    echo -n "Select the matching suite number: "
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

CA_FILE="$CERT_DIR/ca_${sig}.crt"
if [ ! -f "$CA_FILE" ]; then
    echo "ERROR: CA file not found: $CA_FILE"
    exit 1
fi

echo "--> Resolved: name=$name sig=$sig kem=$kem"

CSV_OUT="$RESULTS_DIR/handshake_benchmarks2.csv"
if [ ! -f "$CSV_OUT" ]; then
    echo "Suite,Min(ms),Mean(ms),P50(ms),P95(ms),P99(ms),Max(ms),Successful_Samples,Failed_Samples,Throughput_Conn_Sec" > "$CSV_OUT"
fi

calculate_stats() {
    local raw_data=("$@")
    local count=${#raw_data[@]}
    if [ "$count" -eq 0 ]; then
        echo "0 0 0 0 0 0"
        return
    fi

    printf "%s\n" "${raw_data[@]}" | sort -n | awk -v count="$count" '
    BEGIN { sum = 0; }
    {
        idx++;
        val[idx] = $1;
        sum += $1;
    }
    END {
        min = val[1];
        max = val[count];
        mean = sum / count;

        p50_idx = int(count * 0.50) + 1; if (p50_idx > count) p50_idx = count;
        p95_idx = int(count * 0.95) + 1; if (p95_idx > count) p95_idx = count;
        p99_idx = int(count * 0.99) + 1; if (p99_idx > count) p99_idx = count;

        printf "%.3f %.3f %.3f %.3f %.3f %.3f\n", min, mean, val[p50_idx], val[p95_idx], val[p99_idx], max;
    }'
}

# --- 1. Warmup Loop (Unmasked to diagnose connection errors) ---
echo "--> Running warmup handshakes..."
for ((w=1; w<=5; w++)); do
    "$OPENSSL_BIN" s_client -provider oqs -provider default \
                            -connect localhost:$PORT \
                            -groups "$kem" \
                            -CAfile "$CA_FILE" \
                            -tls1_3 </dev/null
done

# --- 2. Benchmark Sample Loop ---
echo "--> Gathering $NUM_HANDSHAKES Handshake Samples..."
latencies=()
failed_count=0
for ((i=1; i<=NUM_HANDSHAKES; i++)); do
    start_time=$EPOCHREALTIME

    "$OPENSSL_BIN" s_client -provider oqs -provider default \
                            -connect localhost:$PORT \
                            -groups "$kem" \
                            -CAfile "$CA_FILE" \
                            -tls1_3 </dev/null >/dev/null 2>&1
    status=$?
    end_time=$EPOCHREALTIME

    if [ $status -eq 0 ]; then
        delta_ms=$(awk -v start="$start_time" -v end="$end_time" 'BEGIN { print (end - start) * 1000 }')
        latencies+=("$delta_ms")
    else
        ((failed_count++))
        echo "Warning: Connection $i failed with exit code $status"
    fi
done

success_count=${#latencies[@]}
echo "--> Benchmark loop complete: $success_count succeeded, $failed_count failed out of $NUM_HANDSHAKES"

if [ "$success_count" -eq 0 ]; then
    echo "ERROR: All client handshake attempts failed. Verify server state above."
    exit 1
fi

if [ "$failed_count" -gt 0 ]; then
    echo "WARNING: $failed_count/$NUM_HANDSHAKES samples failed. Stats below are computed"
    echo "         over the $success_count successful samples only. If this number is large,"
    echo "         check whether the server's -naccept budget was exhausted mid-run."
fi

stats=$(calculate_stats "${latencies[@]}")
read -r min mean p50 p95 p99 max <<< "$stats"

# --- 3. Throughput Capacity Calculation ---
echo "--> Computing Throughput Capacity (Unthrottled 3-second flood window)..."
t_start=$(date +%s)
t_end=$((t_start + 3))
conn_count=0

while [ $(date +%s) -lt $t_end ]; do
    "$OPENSSL_BIN" s_client -provider oqs -provider default \
                            -connect localhost:$PORT \
                            -groups "$kem" \
                            -CAfile "$CA_FILE" \
                            -tls1_3 </dev/null >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        conn_count=$((conn_count + 1))
    fi
done
connections_per_sec=$(awk -v count="$conn_count" 'BEGIN { printf "%.2f", count / 3 }')

echo "--> Flood phase: $conn_count successful connections in 3s window"

echo "$name,$min,$mean,$p50,$p95,$p99,$max,$success_count,$failed_count,$connections_per_sec" >> "$CSV_OUT"

echo "======================================================"
echo " Done! Benchmark metrics updated in results/handshake_benchmarks2.csv"
echo "======================================================"
tail -n 2 "$CSV_OUT"
