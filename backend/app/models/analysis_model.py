"""Analysis session and user models"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON, Boolean
from app.core.database import Base


class AnalysisSessionModel(Base):
    __tablename__ = "analysis_sessions"

    id = Column(String, primary_key=True)
    session_id = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    pcap_filename = Column(String)
    analyst_name = Column(String, default="SOC Analyst")
    status = Column(String, default="PENDING")  # PENDING|RUNNING|COMPLETED|FAILED
    stage = Column(String, default="UPLOAD")
    progress = Column(Integer, default=0)
    total_packets = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)
    total_iocs = Column(Integer, default=0)
    risk_score = Column(Float, nullable=True)
    artifacts = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    traffic_profile = Column(JSON, nullable=True)
    pipeline_log = Column(JSON, default=list)
