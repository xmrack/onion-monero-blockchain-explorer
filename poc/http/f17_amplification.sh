#!/bin/sh
# Finding 17 -- no request body limit and no cap on deserialised element counts.
# Each tx_source.outputs entry costs a DB output lookup + a tx fetch + a block fetch
# (src/page.h:2965-3040), so one request fans out into unbounded random DB reads.
# This measures response time against payload size; a linear-or-worse curve with no
# ceiling is the finding.
HOST="${1:-http://127.0.0.1:8081}"
for kb in 1 16 256 1024 4096; do
  payload=$(head -c $((kb*1024)) /dev/zero | tr '\0' 'A')
  t=$( { /usr/bin/time -f %e curl -sS -m 120 -o /dev/null \
        --data-urlencode "rawtxdata=$payload" --data "action=check" \
        "$HOST/checkandpush" ; } 2>&1 | tail -1 )
  echo "payload=${kb}KiB elapsed=${t}s"
done
echo
echo "Crow sets no max body size; compare against a documented limit (there is none)."
