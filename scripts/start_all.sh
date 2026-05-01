#!/usr/bin/env bash
# Linux/macOS equivalent of start_all.ps1 - launches the full local stack.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p logs

NODE_ID=node_a NODE_PORT=5311 python3 -m node_server >logs/node_a.log 2>&1 &
NODE_ID=node_b NODE_PORT=5312 python3 -m node_server >logs/node_b.log 2>&1 &
NODE_ID=node_c NODE_PORT=5313 python3 -m node_server >logs/node_c.log 2>&1 &
sleep 1
python3 -m gateway >logs/gateway.log 2>&1 &

echo "Services started.  Tail logs: tail -F logs/*.log"
echo "Web UI: http://127.0.0.1:5310/"
