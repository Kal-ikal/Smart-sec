#!/bin/bash
# Simulates one worker instance polling claim_next_scan_job() until the
# queue is drained. Each claim is its own psql invocation (its own DB
# connection), mirroring how the real Node worker issues one RPC call per
# claim over its own HTTP/Postgres connection to Supabase.
#
# Usage: ./verify_concurrency_claim.sh <worker_id> <out_file>
# Env vars: PSQL_DB (default smartsec_test), PSQL_CMD (default "psql")
WORKER_ID="$1"
OUT_FILE="$2"
PSQL_DB="${PSQL_DB:-smartsec_test}"
PSQL_CMD="${PSQL_CMD:-psql}"
: > "$OUT_FILE"

while true; do
  ROW=$($PSQL_CMD -d "$PSQL_DB" -tA -c "select id from public.claim_next_scan_job('${WORKER_ID}');" 2>/dev/null)
  if [ -z "$ROW" ]; then
    break
  fi
  echo "$ROW" >> "$OUT_FILE"
done
