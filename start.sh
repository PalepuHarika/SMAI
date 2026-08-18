#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/venv"

echo "=== Smart Contract Vulnerability Scanner ==="
echo ""

# Start FastAPI backend
echo "[1/2] Starting backend on http://localhost:8000 ..."
PYTHONPATH="$ROOT" "$VENV/bin/uvicorn" backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

sleep 1

# Start React frontend
echo "[2/2] Starting frontend on http://localhost:5173 ..."
cd "$ROOT/frontend" && npm run dev &
FRONTEND_PID=$!

echo ""
echo "✓ Backend  → http://localhost:8000"
echo "✓ Frontend → http://localhost:5173"
echo "✓ API Docs → http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all services."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" SIGINT SIGTERM
wait
