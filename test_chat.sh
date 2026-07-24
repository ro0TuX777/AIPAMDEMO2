#!/bin/bash
echo "=== Testing /chat/stream — capturing timing of each event ==="
START=$(date +%s)
# Use --no-buffer / -N and write timestamps after each line
curl -sN --max-time 240 -X POST \
  http://localhost:8000/api/v1/jobs/a03621e4-b4dd-4bab-989c-062dadb26dcb/chat/stream \
  -H "Authorization: Bearer test-token-v2" \
  -H "Content-Type: application/json" \
  -d '{"message":"Hi"}' 2>&1 | while IFS= read -r line; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START))
    echo "[t=${ELAPSED}s] ${line:0:200}"
  done > /tmp/stream_output.txt 2>&1
END=$(date +%s)
echo "Total time: $((END-START))s"
echo "Output size: $(wc -c < /tmp/stream_output.txt) bytes"
echo "=== Output (first 40 lines): ==="
head -40 /tmp/stream_output.txt
echo "=== Output (last 10 lines): ==="
tail -10 /tmp/stream_output.txt
