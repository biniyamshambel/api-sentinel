#!/usr/bin/env bash
# Start API Sentinel and the intentionally insecure demo target for a local demo.
# Both servers bind to loopback and are stopped when this script exits.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -x .venv/bin/uvicorn ]]; then
  echo "Missing .venv/bin/uvicorn. Install dependencies first:" >&2
  echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

APP_PORT="${API_SENTINEL_PORT:-8000}"
DEMO_PORT=8001

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  kill "$APP_PID" "$DEMO_PID" 2>/dev/null || true
  wait "$APP_PID" "$DEMO_PID" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT INT TERM

echo "Starting demo target on http://127.0.0.1:${DEMO_PORT} ..."
.venv/bin/uvicorn demo_target:app --host 127.0.0.1 --port "$DEMO_PORT" &
DEMO_PID=$!

echo "Starting API Sentinel on http://127.0.0.1:${APP_PORT} (loopback demo mode) ..."
API_SENTINEL_ALLOW_LOOPBACK=1 \
  .venv/bin/uvicorn main:app --host 127.0.0.1 --port "$APP_PORT" &
APP_PID=$!

READY=0
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${APP_PORT}/api/health" >/dev/null 2>&1 \
    && curl -fsS "http://127.0.0.1:${DEMO_PORT}/" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.25
done

if [[ "$READY" -ne 1 ]]; then
  echo "Servers did not become ready. Check for port conflicts on ${APP_PORT}/${DEMO_PORT}." >&2
  exit 1
fi

cat <<EOF

API Sentinel is ready.

  Dashboard:    http://127.0.0.1:${APP_PORT}
  API docs:     http://127.0.0.1:${APP_PORT}/api/docs
  Demo target:  http://127.0.0.1:${DEMO_PORT}/api/orders

Try scanning:  http://127.0.0.1:${DEMO_PORT}/api/orders

Press Ctrl+C to stop both servers.
EOF

wait -n "$APP_PID" "$DEMO_PID"
