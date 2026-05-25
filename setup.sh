#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════╗"
echo "║     SOC Platform v2.0 — Setup Script         ║"
echo "╚══════════════════════════════════════════════╝"

# Check dependencies
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose not found"; exit 1; }

echo ""
echo "Building and starting SOC Platform..."
echo "This will:"
echo "  1. Build the React frontend (Vite + TypeScript)"
echo "  2. Build the FastAPI backend"
echo "  3. Start PostgreSQL"
echo "  4. Start all services"
echo ""

cd "$(dirname "$0")/docker"

# Pull, build, start
docker compose down --remove-orphans 2>/dev/null || true
docker compose build --no-cache
docker compose up -d

echo ""
echo "Waiting for services to start..."
sleep 10

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║           SOC Platform is running!           ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Frontend:  http://localhost:3000            ║"
echo "║  Backend:   http://localhost:8000            ║"
echo "║  API Docs:  http://localhost:8000/docs       ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Login:  admin / admin123                    ║"
echo "║          analyst / analyst123                ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "To view logs:  docker compose -f docker/docker-compose.yml logs -f"
echo "To stop:       docker compose -f docker/docker-compose.yml down"
