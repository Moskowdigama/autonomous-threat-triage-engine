from pydantic import BaseModel
from datetime import datetime

# What the frontend must send us when submitting a log
class IncidentCreate(BaseModel):
    threat_text: str

# What our API safely sends back after the AI processes it
class IncidentResponse(BaseModel):
    id: int
    threat_text: str
    cvss_score: float
    core_vector: str
    subcategory: str
    framework_alignment: str
    playbook_actions: str
    created_at: datetime

    class Config:
        from_attributes = True
      
