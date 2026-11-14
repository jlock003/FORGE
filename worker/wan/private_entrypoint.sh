#!/bin/bash
set -Eeuo pipefail
umask 077
python /ComfyUI/main.py --listen 127.0.0.1 --use-sage-attention > /tmp/wan-comfy-internal.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for attempt in $(seq 1 180); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:8188/ >/dev/null; then
    exec python -u /secure_handler.py
  fi
  sleep 2
done
echo "Wan ComfyUI worker failed to initialize" >&2
exit 1
