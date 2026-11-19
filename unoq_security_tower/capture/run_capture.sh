#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IFACE=${CAPTURE_IFACE:-wlan0}
TARGET_IP=${1:-${UNOQ_TARGET_IP:-}}
if [ -z "$TARGET_IP" ]; then
  TARGET_IP=$(ip -4 -o addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)
fi
if [ -z "$TARGET_IP" ]; then
  echo "Could not determine target IP. Pass it as the first argument." >&2
  exit 1
fi
exec docker run --rm --network host --user 0 --cap-add NET_RAW \
  -v "$SCRIPT_DIR:/capture:ro" \
  --entrypoint python \
  ghcr.io/arduino/app-bricks/python-apps-base:0.13.2 \
  /capture/capture_agent.py \
  --iface "$IFACE" --target-ip "$TARGET_IP" \
  --event-url "${SENTINEL_EVENT_URL:-http://127.0.0.1:7000/event}"

