"""IOC database models"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON, Boolean
from app.core.database import Base


class IOCModel(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(String, unique=True, index=True)
    ioc_type = Column(String, index=True)  # IP|DOMAIN|URL|USER_AGENT|PORT|HASH
    value = Column(String, index=True)
    confidence = Column(String)
    severity = Column(String, index=True)
    first_seen = Column(String)
    last_seen = Column(String)
    occurrence_count = Column(Integer, default=1)
    associated_alerts = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    vt_malicious_count = Column(Integer, nullable=True)
    vt_detection_names = Column(JSON, default=list)
    abuseipdb_score = Column(Integer, nullable=True)
    abuseipdb_country = Column(String, nullable=True)
    geo_country = Column(String, nullable=True)
    geo_city = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    is_private = Column(Boolean, default=False)
    enrichment_status = Column(String, default="PENDING")
    analysis_session_id = Column(String, index=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
