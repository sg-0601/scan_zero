import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, Float, JSON
from sqlalchemy.dialects.postgresql import UUID
from app.models.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_url = Column(String, nullable=False)
    domain = Column(String, nullable=False, index=True)
    status = Column(String, default="pending")  # pending, running, completed, failed
    score = Column(Float, nullable=True)
    grade = Column(String, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    cached = Column(Boolean, default=False)
    results_json = Column(JSON, nullable=True)
    
    findings_count = Column(Float, default=0)
    critical_count = Column(Float, default=0)
    high_count = Column(Float, default=0)
    medium_count = Column(Float, default=0)
    low_count = Column(Float, default=0)
