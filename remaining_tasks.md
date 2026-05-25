# Remaining Tasks — SOC Platform v3.0

## PRIORITY 1 — CRITICAL (Do First)

### 1. Fix Docker Compose Frontend Service
**File**: `docker/docker-compose.yml`
**Issue**: Frontend service still uses `image: nginx:alpine` with static volume mount
**Fix**: Replace frontend service with:
```yaml
frontend:
  build:
    context: ../frontend
    dockerfile: Dockerfile
  restart: unless-stopped
  ports:
    - "3000:80"
  depends_on:
    - backend
```
**Impact**: Without this fix, `docker compose up -d` will not serve the new React app

### 2. Verify Auth Register Endpoint
**File**: `backend/app/api/auth.py`
**Issue**: Only login + me endpoints exist. No self-registration.
**Fix**: Add POST /api/auth/register for new user creation
**Impact**: Medium — demo users (admin/analyst) work via seeding

### 3. Test Full Stack Integration
**Steps**:
1. `cd docker && docker compose up -d`
2. Wait for DB health check
3. Open http://localhost:3000
4. Login with admin/admin123
5. Verify all 8 pages load and fetch data
6. Start a simulation, verify WS alerts stream
**Files to check**: All API endpoints respond, CORS headers correct

## PRIORITY 2 — HIGH

### 4. Add nginx.conf to Frontend Dockerfile Build
**File**: `frontend/Dockerfile`
**Issue**: The Dockerfile copies `nginx.conf` but that file is in `docker/nginx.conf`, not `frontend/nginx.conf`
**Fix**: Either copy docker/nginx.conf into frontend/, OR update docker-compose to mount it:
```yaml
volumes:
  - ../docker/nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

### 5. Backend User Registration
**File**: `backend/app/api/auth.py`  
**Task**: Add POST /api/auth/register endpoint
**API**: `authApi.register(username, password, full_name, role)` in `frontend/src/api/client.ts`

### 6. STIX2/TAXII2 Live MITRE Data
**File**: `backend/app/api/mitre.py`
**Issue**: MITRE techniques are hardcoded (11 techniques). Requirements ask for live STIX2/TAXII2 feed.
**Fix**: Add `stix2` and `taxii2client` to requirements.txt, fetch from https://cti-taxii.mitre.org/
**Code location**: `backend/app/api/mitre.py` — replace TECHNIQUE_DETAILS dict with TAXII fetch
**Frontend impact**: None (same API shape, more techniques returned)

### 7. Alert Count in Sidebar
**File**: `frontend/src/components/Layout.tsx`
**Issue**: Live alert count badge shows in nav but resets on page refresh
**Fix**: Persist count in state, clear on visiting /alerts page

## PRIORITY 3 — MEDIUM

### 8. Network Traffic Charts on Dashboard
**File**: `frontend/src/pages/DashboardPage.tsx`
**Task**: Add AreaChart showing packet/byte volume over time from `/api/traffic/overview`
**API**: `trafficApi.overview()` — already called but chart not built

### 9. IOC Enrichment Actions
**File**: `frontend/src/pages/IOCsPage.tsx`
**Task**: Add "Enrich" button per IOC to trigger VirusTotal/AbuseIPDB lookup
**Backend**: Would need new POST /api/iocs/{id}/enrich endpoint

### 10. Alert Export
**Task**: Add CSV/JSON export button to AlertsPage
**Frontend**: Download button calling `/api/alerts/?limit=10000` + client-side CSV conversion

### 11. Pagination
**Files**: `AlertsPage.tsx`, `IOCsPage.tsx`
**Task**: Add pagination controls (currently fetches limit=100/200)
**API**: offset + limit params already exist in backend

## PRIORITY 4 — LOW

### 12. Dark/Light Theme Toggle
### 13. Network Graph D3 visualization (IP relationship graph)
### 14. Geolocation world map for attack origins
### 15. Email notifications for critical alerts
### 16. User management page (admin-only)
### 17. Multi-tenancy / org isolation

## KNOWN ISSUES / GOTCHAS

1. **nginx.conf path**: `frontend/Dockerfile` has `COPY nginx.conf /etc/nginx/conf.d/default.conf` but the nginx.conf is at `docker/nginx.conf`. Either copy it to `frontend/nginx.conf` or use a volume mount.

2. **CORS in production**: `backend/app/main.py` uses `allow_origins=["*"]` — fine for dev, should be restricted in prod.

3. **WS token auth**: `frontend/src/hooks/useWebSocket.ts` sends token as query param `?token=...`. Verify `backend/app/websocket/router.py` reads `token` query param.

4. **SQLite in dev**: Demo data seeds automatically. On first run, expect ~30 alerts + ~50 IOCs created.

5. **Scapy**: Requires root/admin on some systems for raw packet capture. PCAP upload analysis (file-based) should work without root.
