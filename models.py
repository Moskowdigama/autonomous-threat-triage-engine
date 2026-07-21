from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from database import Base

class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id = Column(Integer, primary_key=True, index=True)
    threat_text = Column(String, nullable=False)
        # ADD THESE COLUMNS SO MAIN.PY DOESN'T CRASH:
    status = Column(String, default="PENDING", nullable=True)
    
    # OTHER EXISTING COLUMNS:
    cvss_score = Column(Float, nullable=True)
    core_vector = Column(String, nullable=True)
    subcategory = Column(String, nullable=True)
    framework_alignment = Column(String, nullable=True)
    playbook_actions = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
