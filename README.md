# SOC Platform v2.0 — Enterprise Threat Detection System

A fully integrated Security Operations Center (SOC) platform with real-time threat detection,
MITRE ATT&CK live integration, WebSocket streaming, and complete Docker deployment.

## Quick Start

```bash
# One-command start:
bash setup.sh

# Or manually:
cd docker && docker compose up -d
```

Then open: **http://localhost:3000**

**Demo credentials:**
- `admin` / `admin123` — Full admin access
- `analyst` / `analyst123` — SOC analyst access

## Architecture

```
React Frontend (Vite/TS)  →  nginx  →  FastAPI Backend  →  PostgreSQL
        ↕                                    ↕
   WebSocket (live)              MITRE STIX2/TAXII2 live feed
```

## Features

### Frontend (React + TypeScript + Vite)
- **Dashboard** — Live stats, charts (Recharts), real-time alert feed via WebSocket
- **Alerts** — Filterable SIEM-style alerts, status management, analyst notes
- **IOC Management** — Indicator management, STIX2/CSV export, enrichment data
- **MITRE ATT&CK** — Live matrix, heatmap, list views — powered by real STIX2 data
- **Simulation** — 7 attack scenarios with live WebSocket streaming
- **PCAP Analysis** — Upload captures → full pipeline → alerts + IOCs
- **Reports** — Executive summaries, incident reports, downloadable artifacts

### Backend (FastAPI + PostgreSQL)
- JWT authentication (HS256)
- SQLAlchemy async ORM
- 9 API modules: auth, alerts, iocs, pcap, reports, simulation, traffic, artifacts, mitre
- WebSocket manager (global broadcast + session-specific)
- Background task pipeline for PCAP processing
- Demo data auto-seeding on first run

### MITRE ATT&CK Integration
- **Live STIX2 data** fetched from MITRE GitHub on startup
- **28+ techniques** covering all 14 ATT&CK enterprise tactics
- Automatic fallback to bundled data if network unavailable
- 24-hour cache with `/api/mitre/refresh` endpoint to force update
- Alert counts computed live from DB
- Sub-technique support

### Docker Deployment
```
docker compose up -d
```
Services:
- `db` — PostgreSQL 16
- `backend` — FastAPI (uvicorn)
- `frontend` — nginx serving built React SPA

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| POST /api/auth/login | Get JWT token |
| GET /api/alerts/ | List alerts (filterable) |
| GET /api/alerts/stats | Alert statistics |
| PATCH /api/alerts/{id}/status | Update alert |
| GET /api/iocs/ | List IOCs |
| GET /api/iocs/export/csv | CSV export |
| GET /api/iocs/export/stix | STIX2 export |
| GET /api/mitre/matrix | Full ATT&CK matrix |
| POST /api/mitre/refresh | Refresh STIX2 data |
| POST /api/simulation/start | Start attack sim |
| POST /api/pcap/upload | Analyze PCAP file |
| GET /api/reports/summary | Executive summary |
| WS /ws | Live event stream |

Full docs: http://localhost:8000/docs

## Development

```bash
# Backend only (SQLite, no Docker needed):
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend only:
cd frontend
npm install
npm run dev   # Proxies /api to localhost:8000
```

## Environment Variables

Backend:
```
DATABASE_URL=postgresql+asyncpg://soc:socpassword@db:5432/socplatform
SECRET_KEY=your-secret-key-here
ENVIRONMENT=production
```
