from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from database import Base

class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id = Column(Integer, primary_key=True, index=True)
    threat_text = Column(String, nullable=False)
    cvss_score = Column(Float, nullable=False)
    core_vector = Column(String, nullable=False)
    subcategory = Column(String, nullable=False)
    framework_alignment = Column(String, nullable=False)
    playbook_actions = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
  
