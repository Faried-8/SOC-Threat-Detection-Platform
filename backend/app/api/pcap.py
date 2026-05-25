"""PCAP Analysis Pipeline API"""
import asyncio
import logging
import os
import sys
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Depends, BackgroundTasks, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.analysis_model import AnalysisSessionModel
from app.models.alert_model import AlertModel
from app.models.ioc_model import IOCModel
from app.websocket.manager import ws_manager

router = APIRouter()
logger = logging.getLogger("PCAPApi")

# Ensure scripts are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))


@router.post("/upload")
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analyst_name: Optional[str] = "SOC Analyst",
    db: AsyncSession = Depends(get_db),
):
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only PCAP files are supported")
    
    session_id = str(uuid.uuid4())
    pcap_dir = "pcaps"
    os.makedirs(pcap_dir, exist_ok=True)
    pcap_path = os.path.join(pcap_dir, f"{session_id}_{file.filename}")
    
    content = await file.read()
    with open(pcap_path, "wb") as f:
        f.write(content)
    
    session = AnalysisSessionModel(
        id=session_id,
        session_id=session_id,
        pcap_filename=file.filename,
        analyst_name=analyst_name,
        status="PENDING",
        stage="UPLOAD",
        progress=0,
    )
    db.add(session)
    await db.commit()
    
    background_tasks.add_task(run_analysis_pipeline, session_id, pcap_path, analyst_name)
    
    return {
        "session_id": session_id,
        "filename": file.filename,
        "status": "PENDING",
        "message": "Analysis pipeline started. Connect to WebSocket /ws/session/{session_id} for live updates.",
    }


@router.get("/sessions")
async def get_sessions(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AnalysisSessionModel).order_by(AnalysisSessionModel.created_at.desc())
    )
    sessions = result.scalars().all()
    return [_session_to_dict(s) for s in sessions]


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AnalysisSessionModel).where(AnalysisSessionModel.session_id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_to_dict(session)


async def run_analysis_pipeline(session_id: str, pcap_path: str, analyst_name: str):
    """Full SOC analysis pipeline - runs in background"""
    from app.core.database import AsyncSessionLocal
    
    async with AsyncSessionLocal() as db:
        async def update_session(stage: str, progress: int, message: str, status: str = "RUNNING"):
            result = await db.execute(
                select(AnalysisSessionModel).where(AnalysisSessionModel.session_id == session_id)
            )
            session = result.scalar_one_or_none()
            if session:
                session.stage = stage
                session.progress = progress
                session.status = status
                log_entry = {"time": datetime.utcnow().isoformat(), "stage": stage, "message": message}
                if session.pipeline_log is None:
                    session.pipeline_log = []
                session.pipeline_log = session.pipeline_log + [log_entry]
                await db.commit()
            await ws_manager.send_pipeline_update(session_id, stage, progress, message)
            logger.info(f"[{session_id}] [{stage}] {message}")
        
        try:
            await update_session("PARSING", 10, "Parsing PCAP file...")
            await asyncio.sleep(0.5)
            
            # Stage 1: Parse
            from scripts.packet_parser import PacketParser
            parser = PacketParser(pcap_path)
            packets = parser.parse()
            
            await update_session("PARSING", 25, f"Parsed {len(packets)} packets")
            await asyncio.sleep(0.3)
            
            # Export parsed packets
            os.makedirs("outputs", exist_ok=True)
            parser.export_to_json(packets, f"outputs/{session_id}_parsed_packets.json")
            parser.export_to_csv(packets, f"outputs/{session_id}_parsed_packets.csv")
            
            # Stage 2: Traffic Analysis
            await update_session("ANALYSIS", 40, "Running traffic analysis...")
            await asyncio.sleep(0.3)
            
            from scripts.traffic_analyzer import TrafficAnalyzer
            analyzer = TrafficAnalyzer()
            profile = analyzer.analyze(packets)
            
            import json
            with open(f"outputs/{session_id}_traffic_analysis.json", "w") as f:
                json.dump(profile.__dict__ if hasattr(profile, '__dict__') else profile, f, indent=2, default=str)
            
            await update_session("ANALYSIS", 55, "Traffic analysis complete")
            await asyncio.sleep(0.3)
            
            # Stage 3: Threat Detection
            await update_session("DETECTION", 65, "Running threat detection...")
            
            from scripts.threat_detector import ThreatDetector
            detector = ThreatDetector()
            alerts = detector.detect(packets)
            
            await update_session("DETECTION", 75, f"Detected {len(alerts)} alerts")
            
            # Save alerts to DB
            alert_dicts = []
            for a in alerts:
                a_dict = a.to_dict() if hasattr(a, 'to_dict') else vars(a)
                alert_dicts.append(a_dict)
                db_alert = AlertModel(
                    id=a_dict.get("alert_id", str(uuid.uuid4())),
                    alert_id=a_dict.get("alert_id", str(uuid.uuid4())),
                    timestamp=a_dict.get("timestamp", datetime.utcnow().isoformat()),
                    severity=a_dict.get("severity", "MEDIUM"),
                    category=a_dict.get("category", "UNKNOWN"),
                    title=a_dict.get("title", ""),
                    description=a_dict.get("description", ""),
                    src_ip=a_dict.get("src_ip", ""),
                    dst_ip=a_dict.get("dst_ip", ""),
                    src_port=a_dict.get("src_port"),
                    dst_port=a_dict.get("dst_port"),
                    protocol=a_dict.get("protocol", ""),
                    mitre_technique=a_dict.get("mitre_technique", ""),
                    mitre_tactic=a_dict.get("mitre_tactic", ""),
                    evidence=a_dict.get("evidence", []),
                    iocs=a_dict.get("iocs", []),
                    analyst_notes=a_dict.get("analyst_notes", ""),
                    false_positive_likelihood=a_dict.get("false_positive_likelihood", "LOW"),
                    recommended_action=a_dict.get("recommended_action", ""),
                    analysis_session_id=session_id,
                )
                db.add(db_alert)
                await ws_manager.send_alert(a_dict)
            
            with open(f"outputs/{session_id}_threat_alerts.json", "w") as f:
                json.dump(alert_dicts, f, indent=2, default=str)
            
            # Stage 4: IOC Extraction
            await update_session("IOC_EXTRACTION", 82, "Extracting IOCs...")
            
            from scripts.ioc_extractor import IOCExtractor
            extractor = IOCExtractor()
            iocs = extractor.extract(packets, alerts)
            
            ioc_dicts = []
            for ioc in iocs:
                i_dict = ioc.to_dict() if hasattr(ioc, 'to_dict') else vars(ioc)
                ioc_dicts.append(i_dict)
                db_ioc = IOCModel(
                    ioc_id=i_dict.get("ioc_id", str(uuid.uuid4())),
                    ioc_type=i_dict.get("ioc_type", "IP"),
                    value=i_dict.get("value", ""),
                    confidence=i_dict.get("confidence", "MEDIUM"),
                    severity=i_dict.get("severity", "MEDIUM"),
                    first_seen=i_dict.get("first_seen", datetime.utcnow().isoformat()),
                    last_seen=i_dict.get("last_seen", datetime.utcnow().isoformat()),
                    occurrence_count=i_dict.get("occurrence_count", 1),
                    associated_alerts=i_dict.get("associated_alerts", []),
                    tags=i_dict.get("tags", []),
                    is_private=i_dict.get("is_private", False),
                    analysis_session_id=session_id,
                )
                db.add(db_ioc)
            
            with open(f"outputs/{session_id}_iocs.json", "w") as f:
                json.dump(ioc_dicts, f, indent=2, default=str)
            
            await update_session("IOC_EXTRACTION", 88, f"Extracted {len(iocs)} IOCs")
            
            # Stage 5: Report
            await update_session("REPORTING", 92, "Generating incident report...")
            
            from scripts.report_generator import ReportGenerator
            reporter = ReportGenerator(
                analyst_name=analyst_name,
                output_dir=f"reports/{session_id}"
            )
            os.makedirs(f"reports/{session_id}", exist_ok=True)
            reporter.generate_full_report(alerts, iocs, profile, pcap_file=pcap_path)
            
            # Update session with results
            result = await db.execute(
                select(AnalysisSessionModel).where(AnalysisSessionModel.session_id == session_id)
            )
            session = result.scalar_one_or_none()
            if session:
                session.total_packets = len(packets)
                session.total_alerts = len(alerts)
                session.total_iocs = len(iocs)
                session.status = "COMPLETED"
                session.stage = "COMPLETE"
                session.progress = 100
                session.completed_at = datetime.utcnow()
                session.artifacts = {
                    "parsed_packets_json": f"outputs/{session_id}_parsed_packets.json",
                    "parsed_packets_csv": f"outputs/{session_id}_parsed_packets.csv",
                    "traffic_analysis": f"outputs/{session_id}_traffic_analysis.json",
                    "threat_alerts": f"outputs/{session_id}_threat_alerts.json",
                    "iocs_json": f"outputs/{session_id}_iocs.json",
                }
                await db.commit()
            
            await update_session("COMPLETE", 100, f"Analysis complete! {len(alerts)} alerts, {len(iocs)} IOCs", "COMPLETED")
            await ws_manager.send_stats_update({
                "total_packets": len(packets),
                "total_alerts": len(alerts),
                "total_iocs": len(iocs),
            })
            
        except Exception as e:
            logger.error(f"Pipeline error for {session_id}: {e}", exc_info=True)
            result = await db.execute(
                select(AnalysisSessionModel).where(AnalysisSessionModel.session_id == session_id)
            )
            session = result.scalar_one_or_none()
            if session:
                session.status = "FAILED"
                session.error_message = str(e)
                await db.commit()
            await ws_manager.send_pipeline_update(session_id, "FAILED", -1, f"Pipeline failed: {str(e)}")


def _session_to_dict(s: AnalysisSessionModel) -> dict:
    return {
        "session_id": s.session_id,
        "pcap_filename": s.pcap_filename,
        "analyst_name": s.analyst_name,
        "status": s.status,
        "stage": s.stage,
        "progress": s.progress,
        "total_packets": s.total_packets,
        "total_alerts": s.total_alerts,
        "total_iocs": s.total_iocs,
        "risk_score": s.risk_score,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "artifacts": s.artifacts or {},
        "pipeline_log": s.pipeline_log or [],
        "error_message": s.error_message,
    }
