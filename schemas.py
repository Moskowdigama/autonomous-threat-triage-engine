from pydantic import BaseModel
from datetime import datetime
from typing import Optional

# What the frontend must send us when submitting a log
class IncidentCreate(BaseModel):
    threat_text: str

# What our API safely sends back, allowing pending fields to be Optional/None
class IncidentResponse(BaseModel):
    id: int
    threat_text: str
    status: str
    severity: str
    category: str
    summary: str
    cvss_score: Optional[float] = None
    core_vector: Optional[str] = None
    subcategory: Optional[str] = None
    framework_alignment: Optional[str] = None
    playbook_actions: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
        
