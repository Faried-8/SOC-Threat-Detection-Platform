"""Alert database models"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON, Boolean
from app.core.database import Base


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    severity = Column(String, index=True)  # CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL
    category = Column(String, index=True)
    title = Column(String)
    description = Column(Text)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String)
    mitre_technique = Column(String, index=True)
    mitre_tactic = Column(String)
    evidence = Column(JSON, default=list)
    iocs = Column(JSON, default=list)
    packet_ids = Column(JSON, default=list)
    analyst_notes = Column(Text, default="")
    false_positive_likelihood = Column(String, default="LOW")
    recommended_action = Column(Text)
    investigation_status = Column(String, default="OPEN")  # OPEN|IN_PROGRESS|CLOSED|FALSE_POSITIVE
    is_false_positive = Column(Boolean, default=False)
    analysis_session_id = Column(String, index=True, nullable=True)
    risk_score = Column(Float, nullable=True)
