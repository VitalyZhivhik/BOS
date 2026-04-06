#!/bin/bash
# Script to run the server API

cd "$(dirname "$0")"

export PYTHONPATH="$(pwd):$PYTHONPATH"

echo "Starting Security Analyzer Server API..."
echo "Server will listen on http://0.0.0.0:8000"
echo ""
echo "Available endpoints:"
echo "  GET  /health              - Health check"
echo "  POST /api/scan-results    - Receive scan results from client"
echo "  POST /api/vulnerability-db - Receive vulnerability database"
echo "  POST /api/analyze         - Trigger full analysis"
echo "  GET  /api/report          - Get latest report"
echo "  GET  /api/status          - Get server status"
echo ""

python server/api_server.py --host 0.0.0.0 --port 8000
