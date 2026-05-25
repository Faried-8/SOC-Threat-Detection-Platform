"""
SOC Platform - FastAPI Application
Enterprise Network Traffic Analysis & Threat Detection System
"""
import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.api import alerts, iocs, pcap, reports, simulation, traffic, auth, artifacts, mitre
from app.core.database import init_db
from app.websocket.manager import ws_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)-20s :: %(message)s",
)
logger = logging.getLogger("SOCPlatform")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 SOC Platform starting up...")
    await init_db()
    logger.info("✅ Database initialized")
    # Pre-warm MITRE ATT&CK data
    try:
        from app.services.mitre_stix import prewarm
        await prewarm()
        logger.info("✅ MITRE ATT&CK data loaded")
    except Exception as e:
        logger.warning(f"MITRE prewarm failed (will retry on first request): {e}")
    yield
    logger.info("🔴 SOC Platform shutting down...")


app = FastAPI(
    title="SOC Platform API",
    description="Enterprise Network Traffic Analysis & Threat Detection System",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(iocs.router, prefix="/api/iocs", tags=["IOCs"])
app.include_router(pcap.router, prefix="/api/pcap", tags=["PCAP Analysis"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(simulation.router, prefix="/api/simulation", tags=["Simulation"])
app.include_router(traffic.router, prefix="/api/traffic", tags=["Traffic"])
app.include_router(artifacts.router, prefix="/api/artifacts", tags=["Artifacts"])
app.include_router(mitre.router, prefix="/api/mitre", tags=["MITRE ATT&CK"])

from app.websocket.router import ws_router
app.include_router(ws_router)

# Static files
os.makedirs("outputs", exist_ok=True)
os.makedirs("reports", exist_ok=True)
app.mount("/outputs", StaticFiles(directory="outputs"), name="outputs")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")


@app.get("/api/health")
async def health():
    return {"status": "operational", "version": "2.0.0", "platform": "SOC Platform"}


@app.get("/")
async def root():
    return {"message": "SOC Platform API - Enterprise Threat Detection System"}
