"""IOC Management API"""
import json
import csv
import io
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.models.ioc_model import IOCModel
from app.services.demo_data import get_or_seed_demo_data

router = APIRouter()
logger = logging.getLogger("IOCsAPI")


@router.get("/")
async def get_iocs(
    ioc_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    await get_or_seed_demo_data(db)
    
    query = select(IOCModel).order_by(desc(IOCModel.occurrence_count))
    
    if ioc_type:
        query = query.where(IOCModel.ioc_type == ioc_type.upper())
    if severity:
        query = query.where(IOCModel.severity == severity.upper())
    if confidence:
        query = query.where(IOCModel.confidence == confidence.upper())
    if search:
        query = query.where(IOCModel.value.contains(search))
    
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar()
    
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    iocs = result.scalars().all()
    
    return {
        "total": total,
        "iocs": [_ioc_to_dict(i) for i in iocs],
    }


@router.get("/stats")
async def get_ioc_stats(db: AsyncSession = Depends(get_db)):
    await get_or_seed_demo_data(db)
    result = await db.execute(select(IOCModel))
    iocs = result.scalars().all()
    
    type_counts = {}
    severity_counts = {}
    
    for i in iocs:
        type_counts[i.ioc_type] = type_counts.get(i.ioc_type, 0) + 1
        severity_counts[i.severity] = severity_counts.get(i.severity, 0) + 1
    
    return {
        "total": len(iocs),
        "type_distribution": type_counts,
        "severity_distribution": severity_counts,
        "high_confidence": sum(1 for i in iocs if i.confidence == "HIGH"),
    }


@router.get("/export/csv")
async def export_iocs_csv(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IOCModel))
    iocs = result.scalars().all()
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "ioc_id", "ioc_type", "value", "confidence", "severity",
        "first_seen", "last_seen", "occurrence_count", "tags"
    ])
    writer.writeheader()
    for i in iocs:
        writer.writerow({
            "ioc_id": i.ioc_id,
            "ioc_type": i.ioc_type,
            "value": i.value,
            "confidence": i.confidence,
            "severity": i.severity,
            "first_seen": i.first_seen,
            "last_seen": i.last_seen,
            "occurrence_count": i.occurrence_count,
            "tags": ",".join(i.tags or []),
        })
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=iocs.csv"},
    )


@router.get("/export/stix")
async def export_iocs_stix(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IOCModel))
    iocs = result.scalars().all()
    
    from datetime import datetime
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--soc-platform-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "spec_version": "2.1",
        "objects": [],
    }
    
    for i in iocs:
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{i.ioc_id}",
            "name": f"{i.ioc_type}: {i.value}",
            "description": f"IOC extracted by SOC Platform. Confidence: {i.confidence}",
            "created": i.first_seen,
            "modified": i.last_seen,
            "confidence": 85 if i.confidence == "HIGH" else 50 if i.confidence == "MEDIUM" else 25,
            "labels": i.tags or [],
        }
        stix_bundle["objects"].append(obj)
    
    return stix_bundle


def _ioc_to_dict(i: IOCModel) -> dict:
    return {
        "ioc_id": i.ioc_id,
        "ioc_type": i.ioc_type,
        "value": i.value,
        "confidence": i.confidence,
        "severity": i.severity,
        "first_seen": i.first_seen,
        "last_seen": i.last_seen,
        "occurrence_count": i.occurrence_count,
        "associated_alerts": i.associated_alerts or [],
        "tags": i.tags or [],
        "vt_malicious_count": i.vt_malicious_count,
        "abuseipdb_score": i.abuseipdb_score,
        "geo_country": i.geo_country,
        "is_private": i.is_private,
        "enrichment_status": i.enrichment_status,
    }
