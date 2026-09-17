import uuid
from sqlalchemy import Column, String, Boolean, Float, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.models.database import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_results.id"), nullable=False)
    
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # critical, high, medium, low, info
    category = Column(String, nullable=False)  # osint, tls, headers, dns, dast, honeypot
    tool_source = Column(String, nullable=False)
    
    evidence = Column(JSON, nullable=True)
    
    remediation_text = Column(String, nullable=True)
    remediation_code = Column(String, nullable=True)
    
    is_false_positive = Column(Boolean, default=False)
    epss_score = Column(Float, nullable=True)
    
    scan = relationship("ScanResult", foreign_keys=[scan_id])
