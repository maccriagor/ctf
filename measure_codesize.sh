#!/usr/bin/env bash
# =============================================================================
# measure_codesize.sh - WP5 code size of the built crypto libraries, via `size`
# (text/data/bss/total bytes). Output: data/codesize_<arch>.csv
# Defaults to the custom OpenSSL libcrypto and liboqs (if present); override:
#    CODESIZE_LIBS="/path/libcrypto.so /path/liboqs.so" scripts/measure_codesize.sh
# =============================================================================
# DESIGN NOTES
#   - Tool = binutils `size` (brief 7.4: "size utility, readelf -S"):
#     text = machine code, data = initialized globals (tables), bss =
#     zero-filled; total = their sum. Storage-side metric (vs RSS = runtime).
#   - libcrypto.so/liboqs.so aggregate MANY algorithms - per-algorithm
#     numbers are only possible via PQClean's per-scheme .a files:
#     CODESIZE_LIBS="path/libml-kem-768_clean.a ..." scripts/measure_codesize.sh
#   - clean-vs-avx2 (.a) quantifies the size cost of SIMD speed (Analysis).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck disable=SC1091
[ -f "$HERE/versions.env" ] && source "$HERE/versions.env" >/dev/null 2>&1 || true

ARCH="$(uname -m)"
OUT="$ROOT/data/codesize_${ARCH}.csv"
mkdir -p "$ROOT/data"

LIBS="${CODESIZE_LIBS:-}"
if [ -z "$LIBS" ]; then
  # Automatically look up per-algorithm static archives for requested PQ algorithms
  # Targets include standard naming patterns and variations (e.g., _clean, _avx2, _ref)
  SEARCH_ROOTS=""
  for r in "${LIBOQS_PREFIX_OPT:-}" "${LIBOQS_PREFIX_REF:-}" "$ROOT/build" "$ROOT"; do
    [ -d "$r" ] && SEARCH_ROOTS="$SEARCH_ROOTS $r"
  done

  # Target algorithm basenames to dynamically scan for
  ALGS="ml-kem-512 ml-kem-768 ml-kem-1024 ml-dsa-44 ml-dsa-65 ml-dsa-87"
  
  if [ -n "$SEARCH_ROOTS" ]; then
    for alg in $ALGS; do
      # Locate filenames matching variations like libml-kem-512_clean.a, libml-kem-512_avx2.a, etc.
      # using a broad wildcard format to catch unforeseen suffix types natively.
      while IFS= read -r found_lib; do
        [ -f "$found_lib" ] && LIBS="$LIBS $found_lib"
      done < <(find $SEARCH_ROOTS -type f -name "lib${alg}*.a" 2>/dev/null)
    done
  fi

  # Fallback warning if no per-algorithm static archives could be discovered
  if [ -z "$LIBS" ]; then
    echo "=============================================================================" >&2
    echo "WARNING: Per-algorithm static archives (*.a) were not found within the" >&2
    echo "         configured installation or build directories." >&2
    echo "         The liboqs build likely only produced the aggregate libraries" >&2
    echo "         (liboqs.a/liboqs.so). Per-algorithm code-size measurements are" >&2
    echo "         therefore unavailable." >&2
    echo "=============================================================================" >&2
    
    # Maintain legacy global fallback path behavior if per-algorithm discovery fails
    for d in "${OSSL_PREFIX:-}/lib64" "${OSSL_PREFIX:-}/lib" \
             "${LIBOQS_PREFIX_OPT:-}/lib" "${LIBOQS_PREFIX_REF:-}/lib"; do
      for f in "$d"/libcrypto.so "$d"/libcrypto.a "$d"/liboqs.so "$d"/liboqs.a; do
        [ -f "$f" ] && LIBS="$LIBS $f"
      done
    done
  fi
fi
[ -z "$LIBS" ] && LIBS="$ROOT/build/bench_evp"     # fallback: the bench binary

echo "file,text_bytes,total_bytes" > "$OUT"
for f in $LIBS; do
  [ -f "$f" ] || continue
  # Use `size -t` and read the (TOTALS) line (last row): for a .so it equals the
  # single object row, but for a .a (archive = MANY object rows) it is the true
  # SUM. Plain `size | awk NR==2` took only the FIRST object of an archive
  # (so libcrypto.a / per-scheme .a came out far too small). text data bss dec.
  read -r text data bss dec < <(size -t "$f" 2>/dev/null | tail -1 | awk '{print $1,$2,$3,$4}')
  if [ -n "${text:-}" ]; then
    echo "$(basename "$f"),${text},${dec}" >> "$OUT"
    echo "==> $(basename "$f"): text=${text} total=${dec} bytes"
  fi
done
echo "Code-size CSV: $OUT"
