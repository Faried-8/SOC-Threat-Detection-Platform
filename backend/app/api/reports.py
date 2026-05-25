"""Reports API"""
import logging
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.alert_model import AlertModel
from app.models.ioc_model import IOCModel
from app.services.demo_data import get_or_seed_demo_data

router = APIRouter()
logger = logging.getLogger("ReportsAPI")


@router.get("/summary")
async def get_summary(db: AsyncSession = Depends(get_db)):
    await get_or_seed_demo_data(db)

    total_alerts = (await db.execute(select(func.count(AlertModel.id)))).scalar()
    critical = (await db.execute(select(func.count(AlertModel.id)).where(AlertModel.severity == "CRITICAL"))).scalar()
    high = (await db.execute(select(func.count(AlertModel.id)).where(AlertModel.severity == "HIGH"))).scalar()
    open_alerts = (await db.execute(select(func.count(AlertModel.id)).where(AlertModel.investigation_status == "OPEN"))).scalar()
    total_iocs = (await db.execute(select(func.count(IOCModel.id)))).scalar()

    # Top MITRE technique
    result = await db.execute(select(AlertModel.mitre_technique))
    tech_counts: dict = {}
    for row in result.scalars():
        if row:
            for t in row.split(","):
                t = t.strip()
                if t:
                    tech_counts[t] = tech_counts.get(t, 0) + 1
    top_technique = max(tech_counts, key=lambda k: tech_counts[k]) if tech_counts else "N/A"

    risk_level = "CRITICAL" if critical > 5 else "HIGH" if critical > 0 or high > 10 else "MEDIUM" if total_alerts > 5 else "LOW"

    return {
        "period": f"{datetime.utcnow().strftime('%Y-%m')} (current month)",
        "generated_at": datetime.utcnow().isoformat(),
        "total_alerts": total_alerts,
        "critical_alerts": critical,
        "high_alerts": high,
        "open_alerts": open_alerts,
        "total_iocs": total_iocs,
        "top_technique": top_technique,
        "risk_level": risk_level,
        "recommendation": {
            "CRITICAL": "Immediate incident response required. Isolate affected systems.",
            "HIGH": "Escalate to senior analysts. Review and contain active threats.",
            "MEDIUM": "Monitor closely. Implement additional detection rules.",
            "LOW": "Standard monitoring. Review weekly.",
        }.get(risk_level, "Review as needed."),
    }


@router.get("/incidents")
async def get_incidents(db: AsyncSession = Depends(get_db)):
    await get_or_seed_demo_data(db)

    result = await db.execute(
        select(AlertModel)
        .where(AlertModel.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(AlertModel.created_at.desc())
        .limit(20)
    )
    alerts = result.scalars().all()

    incidents = []
    for a in alerts:
        incidents.append({
            "incident_id": f"INC-{a.alert_id[:8].upper()}",
            "title": a.title,
            "severity": a.severity,
            "date": str(a.timestamp)[:10] if a.timestamp else "N/A",
            "alert_count": 1,
            "src_ip": a.src_ip,
            "category": a.category,
            "mitre_technique": a.mitre_technique,
            "status": a.investigation_status,
        })

    return {"incidents": incidents, "total": len(incidents)}
