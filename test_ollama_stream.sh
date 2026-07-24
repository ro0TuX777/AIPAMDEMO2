#!/bin/bash
# Test Ollama streaming directly with the same payload-style chat.py uses
# Use a small ctx first, then large
echo "=== Test 1: Small prompt, default ctx ==="
START=$(date +%s)
timeout 60 curl -sN -X POST http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"aipam-trafficllm-v10","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":20}' \
  > /tmp/ollama_test1.txt 2>&1
END=$(date +%s)
echo "Total time: $((END-START))s"
echo "Lines received: $(wc -l < /tmp/ollama_test1.txt)"
head -3 /tmp/ollama_test1.txt
echo ""
echo "=== Test 2: Large num_ctx (matches chat.py) ==="
START=$(date +%s)
timeout 90 curl -sN -X POST http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"aipam-trafficllm-v10","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":20,"options":{"num_ctx":16384}}' \
  > /tmp/ollama_test2.txt 2>&1
END=$(date +%s)
echo "Total time: $((END-START))s"
echo "Lines received: $(wc -l < /tmp/ollama_test2.txt)"
head -3 /tmp/ollama_test2.txt
