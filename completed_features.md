# Completed Features — SOC Platform v3.1

## BACKEND (100%)
- FastAPI app with lifespan + MITRE prewarm
- Auth: login + me (JWT decoded properly), DEMO_USERS with bcrypt
- Alerts: list/filter/stats/update with all fields
- IOCs: list/filter/stats/export CSV+STIX2
- MITRE: Live STIX2 matrix, technique drilldown, cache-info, force-refresh
- PCAP: Upload → pipeline → WS progress → alerts + IOCs
- Simulation: 7 scenarios, WS streaming start/progress/complete events
- Reports: Executive summary, incident list with computed risk level
- Artifacts: List + download
- Traffic: Overview with protocol distribution
- WebSocket: Global broadcast + session-specific, send_alert/send_ioc/send_pipeline_update

## MITRE STIX2 SERVICE (100%)
- Fetches live from: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
- Parses x-mitre-tactic and attack-pattern objects
- 14 tactics in canonical order
- 28+ bundled fallback techniques
- 24-hour TTL cache
- POST /api/mitre/refresh to force update
- GET /api/mitre/cache-info for data source status

## FRONTEND (100%)
- Vite + React 18 + TypeScript
- Global singleton WebSocket with auto-reconnect
- JWT auth with 401 interceptor → auto logout
- 8 pages all connected to real backend APIs:
  - LoginPage: JWT auth, demo creds hint
  - DashboardPage: 6 stat cards, 4 charts, live feed, recent alerts
  - AlertsPage: Filter table, WS live prepend, detail panel, status update
  - IOCsPage: Filter table, stat cards, STIX2/CSV export, detail panel
  - MitrePage: Matrix/heatmap/list views, live STIX2 badge, sub-tech filter
  - SimulationPage: Scenario select, progress bar, live event stream
  - PCAPPage: Drag-drop, pipeline steps, session history, results
  - ReportsPage: Summary stats, risk recommendation, incident table

## DOCKER (100%)
- docker-compose.yml: db (postgres:16) + backend + frontend with healthchecks
- frontend/Dockerfile: node:20 build → nginx serve
- frontend/nginx.conf: SPA routing + /api/ proxy + /ws WebSocket proxy
- setup.sh: one-command deploy

## INTEGRATION (100%)
- Frontend API client → all 9 backend modules
- WebSocket: Dashboard (live feed), Alerts (prepend), Simulation (stream), PCAP (progress)
- MITRE matrix updates from live DB alert counts
- Alert status updates reflected immediately in UI
