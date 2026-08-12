#!/bin/sh
# Finding 9 -- observing MDB_NOLOCK effects against a live explorer.
# The mechanism is proven in poc/micro/f09_nolock.cpp (751206 torn reads without a
# reader lock vs 0 with). This looks for the symptom in a real deployment: with
# monerod actively writing, walk the tip repeatedly and count parse/lookup failures.
HOST="${1:-http://127.0.0.1:8081}"
N="${2:-200}"
echo "polling $HOST for $N iterations while monerod syncs; counting anomalies"
fail=0
for i in $(seq "$N"); do
  h=$(curl -sS -m 10 "$HOST/api/networkinfo" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')
  [ -z "$h" ] && { fail=$((fail+1)); continue; }
  body=$(curl -sS -m 10 "$HOST/api/block/$((h-1))")
  echo "$body" | grep -q '"status": *"success"' || fail=$((fail+1))
done
echo "anomalous responses: $fail / $N"
echo
echo "Also watch stderr for the messages these paths emit on a torn read:"
echo "  'Block of height ... not found in the blockchain!'   (src/MicroCore.cpp:108)"
echo "  'Cant get block: '                                   (src/page.h:6435)"
echo "Those are finding 30's branches, which then render fabricated metadata."
