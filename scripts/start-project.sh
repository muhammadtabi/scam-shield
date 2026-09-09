#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_PORT=8000
FRONTEND_PORT=5173

port_in_use() {
  local port="$1"
  ss -ltn 2>/dev/null | grep -q ":${port} "
}

started_pids=()

cleanup() {
  for pid in "${started_pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}

trap cleanup INT TERM

if port_in_use "$BACKEND_PORT"; then
  echo "Backend already running on http://127.0.0.1:${BACKEND_PORT}" >&2
else
  echo "Starting backend on http://127.0.0.1:${BACKEND_PORT}" >&2
  (cd "$ROOT_DIR" && ./scripts/start-backend-dev.sh) &
  started_pids+=("$!")
fi

if port_in_use "$FRONTEND_PORT"; then
  echo "Frontend already running on http://127.0.0.1:${FRONTEND_PORT}" >&2
else
  echo "Starting frontend on http://127.0.0.1:${FRONTEND_PORT}" >&2
  (cd "$ROOT_DIR/frontend" && npm run dev -- --host 127.0.0.1 --port "$FRONTEND_PORT") &
  started_pids+=("$!")
fi

if [ "${#started_pids[@]}" -eq 0 ]; then
  echo "Project is already running." >&2
  exit 0
fi

wait "${started_pids[@]}"
