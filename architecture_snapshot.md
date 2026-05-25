# Architecture Snapshot — SOC Platform v3.0

## Project Structure
```
soc-final/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, router mounts, lifespan
│   │   ├── api/
│   │   │   ├── auth.py          # /api/auth/*
│   │   │   ├── alerts.py        # /api/alerts/*
│   │   │   ├── iocs.py          # /api/iocs/*
│   │   │   ├── mitre.py         # /api/mitre/*
│   │   │   ├── pcap.py          # /api/pcap/*
│   │   │   ├── simulation.py    # /api/simulation/*
│   │   │   ├── reports.py       # /api/reports/*
│   │   │   ├── artifacts.py     # /api/artifacts/*
│   │   │   └── traffic.py       # /api/traffic/*
│   │   ├── core/
│   │   │   ├── config.py        # Pydantic Settings
│   │   │   ├── database.py      # SQLAlchemy async engine
│   │   │   └── security.py      # JWT auth
│   │   ├── models/
│   │   │   ├── alert_model.py
│   │   │   ├── ioc_model.py
│   │   │   ├── analysis_model.py
│   │   │   └── user_model.py
│   │   ├── services/
│   │   │   └── demo_data.py     # Seeds demo data on first run
│   │   └── websocket/
│   │       ├── manager.py       # ConnectionManager
│   │       └── router.py        # /ws WebSocket endpoint
│   ├── scripts/                 # Cybersecurity engine
│   │   ├── traffic_analyzer.py
│   │   ├── threat_detector.py
│   │   ├── ioc_extractor.py
│   │   ├── packet_parser.py
│   │   ├── report_generator.py
│   │   ├── attack_simulator.py
│   │   └── visualizer.py
│   ├── configs/
│   │   └── detection_rules.json
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── main.tsx             # React 18 entry
│   │   ├── App.tsx              # Router, protected routes
│   │   ├── index.css            # Cyberpunk theme CSS
│   │   ├── api/
│   │   │   └── client.ts        # Axios + all API methods
│   │   ├── types/
│   │   │   └── index.ts         # TypeScript interfaces
│   │   ├── context/
│   │   │   └── AuthContext.tsx  # Auth state provider
│   │   ├── hooks/
│   │   │   └── useWebSocket.ts  # WS hook with reconnect
│   │   ├── components/
│   │   │   ├── Layout.tsx       # Sidebar + topbar + WS status
│   │   │   └── ui.tsx           # Shared UI components
│   │   └── pages/
│   │       ├── LoginPage.tsx
│   │       ├── DashboardPage.tsx
│   │       ├── AlertsPage.tsx
│   │       ├── IOCsPage.tsx
│   │       ├── MitrePage.tsx
│   │       ├── SimulationPage.tsx
│   │       ├── PCAPPage.tsx
│   │       └── ReportsPage.tsx
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── Dockerfile
├── docker/
│   ├── docker-compose.yml
│   └── nginx.conf
└── docs/
    ├── continuation.md
    ├── completed_features.md
    ├── remaining_tasks.md
    ├── architecture_snapshot.md
    └── resume_prompt.md
```

## API Map
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/auth/login | No | Get JWT token |
| GET | /api/auth/me | Yes | Current user |
| GET | /api/alerts/ | Yes | List alerts (filterable) |
| GET | /api/alerts/stats | Yes | Alert statistics |
| GET | /api/alerts/{id} | Yes | Alert detail |
| PATCH | /api/alerts/{id}/status | Yes | Update alert status |
| GET | /api/iocs/ | Yes | List IOCs (filterable) |
| GET | /api/iocs/stats | Yes | IOC statistics |
| GET | /api/iocs/export/csv | Yes | CSV export |
| GET | /api/iocs/export/stix | Yes | STIX2 export |
| GET | /api/mitre/matrix | Yes | Full ATT&CK matrix |
| GET | /api/mitre/techniques | Yes | Technique list |
| GET | /api/mitre/technique/{id} | Yes | Technique drilldown |
| POST | /api/pcap/upload | Yes | Upload PCAP for analysis |
| GET | /api/pcap/sessions | Yes | Analysis sessions |
| GET | /api/simulation/scenarios | Yes | Available scenarios |
| POST | /api/simulation/start | Yes | Start simulation |
| GET | /api/reports/summary | Yes | Executive summary |
| GET | /api/reports/incidents | Yes | Incident list |
| GET | /api/artifacts/ | Yes | List artifacts |
| GET | /api/traffic/overview | Yes | Traffic overview |
| WS | /ws?token=JWT | Yes | Live event stream |

## WebSocket Architecture
```
Backend ConnectionManager (ws_manager singleton)
  ↓ broadcast() → all connected clients
  ↓ send_to_session() → PCAP analysis clients
  
Message Types:
  new_alert    → { type, data: Alert }
  new_ioc      → { type, data: IOC }
  stats_update → { type, data: Stats }
  pipeline_update → { type, session_id, stage, progress, message }

Frontend useWebSocket hook:
  - Connects to ws://host/ws?token=JWT
  - Auto-reconnects every 5s on disconnect
  - Dispatches messages to registered handlers
  - Used in: Layout, DashboardPage, AlertsPage, SimulationPage, PCAPPage
```

## Docker Architecture
```
docker-compose.yml:
  db (postgres:16) → port 5432, healthcheck
  backend (FastAPI) → port 8000, waits for db healthy
  frontend (nginx) → port 3000, proxies /api/ and /ws to backend

nginx.conf:
  / → serves React SPA (try_files → /index.html for client-side routing)
  /api/ → proxy_pass http://backend:8000
  /ws → proxy_pass http://backend:8000 with upgrade headers

Environment:
  DATABASE_URL=postgresql+asyncpg://soc:socpassword@db:5432/socplatform
  SECRET_KEY=enterprise-soc-secret-key-change-in-production
```
