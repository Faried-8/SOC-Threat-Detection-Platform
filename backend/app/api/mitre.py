"""MITRE ATT&CK API — Live STIX2/TAXII2 integration"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.alert_model import AlertModel
from app.services.demo_data import get_or_seed_demo_data
from app.services.mitre_stix import get_techniques, get_tactics, get_cache_info

router = APIRouter()
logger = logging.getLogger("MitreAPI")


async def _build_technique_alert_map(db: AsyncSession):
    result = await db.execute(select(AlertModel))
    alerts = result.scalars().all()
    tech_map = {}
    for alert in alerts:
        if not alert.mitre_technique:
            continue
        for tech in alert.mitre_technique.split(","):
            tech = tech.strip()
            if not tech:
                continue
            if tech not in tech_map:
                tech_map[tech] = {"count": 0, "severities": {}, "alerts": []}
            tech_map[tech]["count"] += 1
            sev = alert.severity
            tech_map[tech]["severities"][sev] = tech_map[tech]["severities"].get(sev, 0) + 1
            tech_map[tech]["alerts"].append(alert.alert_id)
    return tech_map


@router.get("/matrix")
async def get_mitre_matrix(db: AsyncSession = Depends(get_db)):
    """Full MITRE ATT&CK matrix with live alert counts per technique."""
    await get_or_seed_demo_data(db)

    techniques = await get_techniques()
    tactics = await get_tactics()
    tech_alert_map = await _build_technique_alert_map(db)

    # Group techniques by tactic_id
    tactic_order = [
        "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
        "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
        "TA0009", "TA0010", "TA0011", "TA0040",
    ]

    # Build tactic → techniques mapping
    tactic_tech_map: dict = {}
    for tech_id, tech in techniques.items():
        tid = tech.get("tactic_id", "")
        if not tid:
            continue
        if tid not in tactic_tech_map:
            tactic_tech_map[tid] = []
        alert_data = tech_alert_map.get(tech_id, {"count": 0, "severities": {}, "alerts": []})
        tactic_tech_map[tid].append({
            "technique_id": tech_id,
            "name": tech["name"],
            "description": tech.get("description", ""),
            "tactic": tech.get("tactic", ""),
            "tactic_id": tid,
            "alert_count": alert_data["count"],
            "severity_distribution": alert_data["severities"],
            "alert_ids": alert_data["alerts"],
            "is_triggered": alert_data["count"] > 0,
            "is_subtechnique": tech.get("is_subtechnique", False),
            "platforms": tech.get("platforms", []),
        })

    # Build tactic list in canonical order
    tactic_name_map = {v["tactic_id"]: v for v in tactics.values()}
    tactics_list = []
    seen_tids = set()

    for tid in tactic_order:
        if tid in seen_tids:
            continue
        seen_tids.add(tid)
        tinfo = tactic_name_map.get(tid, {})
        techs = sorted(tactic_tech_map.get(tid, []),
                       key=lambda t: (-t["alert_count"], t["technique_id"]))
        if not tinfo and not techs:
            continue
        tactics_list.append({
            "tactic_id": tid,
            "tactic_name": tinfo.get("tactic_name", tid),
            "techniques": techs,
            "triggered_count": sum(1 for t in techs if t["is_triggered"]),
        })

    total_triggered = sum(
        1 for t in tech_alert_map if tech_alert_map[t]["count"] > 0
    )

    return {
        "tactics": tactics_list,
        "total_techniques": len(techniques),
        "triggered_techniques": total_triggered,
        "technique_alert_map": tech_alert_map,
        "data_source": get_cache_info(),
    }


@router.get("/techniques")
async def list_techniques(db: AsyncSession = Depends(get_db)):
    """All ATT&CK techniques with alert counts, sorted by detections."""
    await get_or_seed_demo_data(db)
    techniques = await get_techniques()
    tech_alert_map = await _build_technique_alert_map(db)

    result = []
    for tech_id, tech in techniques.items():
        alert_data = tech_alert_map.get(tech_id, {"count": 0, "severities": {}, "alerts": []})
        result.append({
            **tech,
            "alert_count": alert_data["count"],
            "is_triggered": alert_data["count"] > 0,
            "severity_distribution": alert_data["severities"],
        })

    return sorted(result, key=lambda x: (-x["alert_count"], x["technique_id"]))


@router.get("/technique/{technique_id}")
async def get_technique_detail(technique_id: str, db: AsyncSession = Depends(get_db)):
    """Drilldown for a specific technique including related alerts."""
    await get_or_seed_demo_data(db)
    techniques = await get_techniques()

    if technique_id not in techniques:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")

    result = await db.execute(select(AlertModel))
    alerts = result.scalars().all()
    related = [a for a in alerts if a.mitre_technique and technique_id in a.mitre_technique]

    tech = techniques[technique_id]
    return {
        **tech,
        "alert_count": len(related),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "timestamp": str(a.timestamp),
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "category": a.category,
            }
            for a in related[:20]
        ],
    }


@router.get("/cache-info")
async def cache_info():
    """MITRE data source and cache status."""
    return get_cache_info()


@router.post("/refresh")
async def refresh_mitre_data():
    """Force-refresh MITRE ATT&CK data from STIX2 source."""
    from app.services.mitre_stix import fetch_attack_data, _load_fallback_data, _cache
    _cache["last_fetched"] = None  # Invalidate cache
    success = await fetch_attack_data()
    if not success:
        _load_fallback_data()
    return get_cache_info()
