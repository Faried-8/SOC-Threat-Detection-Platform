"""Alerts API - SIEM-style alert management"""
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, update

from app.core.database import get_db
from app.models.alert_model import AlertModel
from app.services.demo_data import get_or_seed_demo_data

router = APIRouter()
logger = logging.getLogger("AlertsAPI")


@router.get("/")
async def get_alerts(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    mitre_technique: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    await get_or_seed_demo_data(db)
    
    query = select(AlertModel).order_by(desc(AlertModel.created_at))
    
    if severity:
        query = query.where(AlertModel.severity == severity.upper())
    if category:
        query = query.where(AlertModel.category == category.upper())
    if mitre_technique:
        query = query.where(AlertModel.mitre_technique.contains(mitre_technique))
    if status:
        query = query.where(AlertModel.investigation_status == status.upper())
    if search:
        query = query.where(
            AlertModel.title.contains(search) |
            AlertModel.src_ip.contains(search) |
            AlertModel.dst_ip.contains(search) |
            AlertModel.description.contains(search)
        )
    
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar()
    
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    alerts = result.scalars().all()
    
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


@router.get("/stats")
async def get_alert_stats(db: AsyncSession = Depends(get_db)):
    await get_or_seed_demo_data(db)
    
    result = await db.execute(select(AlertModel))
    alerts = result.scalars().all()
    
    severity_counts = {}
    category_counts = {}
    mitre_counts = {}
    
    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1
        category_counts[a.category] = category_counts.get(a.category, 0) + 1
        if a.mitre_technique:
            for t in a.mitre_technique.split(","):
                t = t.strip()
                mitre_counts[t] = mitre_counts.get(t, 0) + 1
    
    return {
        "total": len(alerts),
        "severity_distribution": severity_counts,
        "category_distribution": category_counts,
        "mitre_technique_counts": mitre_counts,
        "open": sum(1 for a in alerts if a.investigation_status == "OPEN"),
        "in_progress": sum(1 for a in alerts if a.investigation_status == "IN_PROGRESS"),
        "closed": sum(1 for a in alerts if a.investigation_status == "CLOSED"),
        "false_positives": sum(1 for a in alerts if a.is_false_positive),
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AlertModel).where(AlertModel.alert_id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_dict(alert)


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AlertModel).where(AlertModel.alert_id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if "status" in body:
        alert.investigation_status = body["status"].upper()
    if "analyst_notes" in body:
        alert.analyst_notes = body["analyst_notes"]
    if "is_false_positive" in body:
        alert.is_false_positive = body["is_false_positive"]
    
    await db.commit()
    return {"success": True, "alert": _alert_to_dict(alert)}


def _alert_to_dict(a: AlertModel) -> dict:
    return {
        "alert_id": a.alert_id,
        "timestamp": a.timestamp,
        "severity": a.severity,
        "category": a.category,
        "title": a.title,
        "description": a.description,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "src_port": a.src_port,
        "dst_port": a.dst_port,
        "protocol": a.protocol,
        "mitre_technique": a.mitre_technique,
        "mitre_tactic": a.mitre_tactic,
        "evidence": a.evidence or [],
        "iocs": a.iocs or [],
        "analyst_notes": a.analyst_notes or "",
        "false_positive_likelihood": a.false_positive_likelihood,
        "recommended_action": a.recommended_action or "",
        "investigation_status": a.investigation_status,
        "is_false_positive": a.is_false_positive,
        "risk_score": a.risk_score,
    }
