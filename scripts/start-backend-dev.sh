#!/usr/bin/env bash
set -euo pipefail
# Start backend in dev reload mode using the appropriate venv.
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$ROOT_DIR/backend/venv/bin/python" ]; then
  PY="$ROOT_DIR/backend/venv/bin/python"
elif [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PY="$ROOT_DIR/.venv/bin/python"
else
  echo "No Python virtualenv found. Create one in backend/venv or .venv" >&2
  exit 1
fi
echo "Using venv: $PY" >&2
cd "$ROOT_DIR/backend"
exec "$PY" -m uvicorn main:app --reload --reload-dir app --host 127.0.0.1 --port 8000
