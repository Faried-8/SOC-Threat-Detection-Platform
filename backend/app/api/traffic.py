"""Traffic Statistics API"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.analysis_model import AnalysisSessionModel
from app.services.demo_data import get_or_seed_demo_data, DEMO_TRAFFIC_PROFILE

router = APIRouter()
logger = logging.getLogger("TrafficAPI")


@router.get("/profile")
async def get_traffic_profile(db: AsyncSession = Depends(get_db)):
    """Get most recent traffic analysis profile"""
    await get_or_seed_demo_data(db)
    
    result = await db.execute(
        select(AnalysisSessionModel)
        .where(AnalysisSessionModel.status == "COMPLETED")
        .order_by(AnalysisSessionModel.created_at.desc())
    )
    session = result.scalars().first()
    
    if session and session.traffic_profile:
        return session.traffic_profile
    
    return DEMO_TRAFFIC_PROFILE


@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)):
    """SOC overview statistics"""
    await get_or_seed_demo_data(db)
    
    from app.models.alert_model import AlertModel
    from app.models.ioc_model import IOCModel
    
    alerts_result = await db.execute(select(AlertModel))
    alerts = alerts_result.scalars().all()
    
    iocs_result = await db.execute(select(IOCModel))
    iocs = iocs_result.scalars().all()
    
    severity_map = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}
    risk_score = 0
    if alerts:
        risk_score = min(100, sum(severity_map.get(a.severity, 1) * 4 for a in alerts) / max(len(alerts), 1) * 10)
    
    return {
        "total_packets_analyzed": DEMO_TRAFFIC_PROFILE["total_packets"],
        "total_alerts": len(alerts),
        "total_iocs": len(iocs),
        "risk_score": round(risk_score, 1),
        "severity_distribution": {
            "CRITICAL": sum(1 for a in alerts if a.severity == "CRITICAL"),
            "HIGH": sum(1 for a in alerts if a.severity == "HIGH"),
            "MEDIUM": sum(1 for a in alerts if a.severity == "MEDIUM"),
            "LOW": sum(1 for a in alerts if a.severity == "LOW"),
            "INFORMATIONAL": sum(1 for a in alerts if a.severity == "INFORMATIONAL"),
        },
        "protocol_distribution": DEMO_TRAFFIC_PROFILE["protocol_distribution"],
        "top_src_ips": DEMO_TRAFFIC_PROFILE["top_src_ips"][:10],
        "top_dst_ips": DEMO_TRAFFIC_PROFILE["top_dst_ips"][:10],
        "packets_per_second": DEMO_TRAFFIC_PROFILE["packets_per_second"],
        "capture_duration": DEMO_TRAFFIC_PROFILE["capture_duration_seconds"],
        "suspicious_ratio": DEMO_TRAFFIC_PROFILE.get("suspicious_traffic_ratio", 0.18),
    }
