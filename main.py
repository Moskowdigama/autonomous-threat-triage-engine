import os
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from google import genai
from google.genai import types
from pydantic import BaseModel

import models, schemas, database

app = FastAPI(title="SOAR AI Triage Engine")

# Initialize the official Google GenAI Client
# The SDK automatically draws the key securely from os.environ["GEMINI_API_KEY"]
ai_client = genai.Client()

# Auto-build database tables on boot
models.Base.metadata.create_all(bind=database.engine)

# Deep Pydantic Structure instructing Gemini exactly how to format the security alert
class AutomatedTriageReport(BaseModel):
    severity: str  # Must be LOW, MEDIUM, HIGH, or CRITICAL
    category: str  # Phishing, Ransomware, Brute Force, etc.
    summary: str   # Clean, executive-friendly summary of the attack vector

@app.get("/")
def read_root():
    return {"status": "online", "engine": "SOAR Live AI Triage Active"}

def process_incident_with_ai(db_record_id: int, raw_payload: str, db: Session):
    try:
        # Prompt telling Gemini to act as a Tier-3 SOC Analyst
        prompt = f"""
        You are an enterprise Incident Response SOAR Automation agent. 
        Analyze the following raw security alert data and extract the triage details.
        
        CRITICAL RULE: Severity MUST be strictly classified as one of these: LOW, MEDIUM, HIGH, CRITICAL.
        
        Raw Alert Data:
        {raw_payload}
        """

        # Call Gemini requesting structured JSON output matching our schema
        response = ai_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AutomatedTriageReport,
                temperature=0.1 # Low temp = highly deterministic, accurate triage
            ),
        )

        # Parse Gemini's structured JSON directly into our schema format
        ai_data = AutomatedTriageReport.model_validate_json(response.text)

        # Update the pending database log with the AI's conclusions
        incident = db.query(models.IncidentReport).filter(models.IncidentReport.id == db_record_id).first()
        if incident:
            incident.severity = ai_data.severity
            incident.category = ai_data.category
            incident.summary = ai_data.summary
            incident.status = "TRIAGED"
            db.commit()

    except Exception as e:
        # Fallback safety handler if the AI call hits a rate limit or network glitch
        db.rollback()
        incident = db.query(models.IncidentReport).filter(models.IncidentReport.id == db_record_id).first()
        if incident:
            incident.summary = f"AI Triage Failed: {str(e)}"
            incident.status = "FAILED_RETRY"
            db.commit()

@app.post("/alerts/") 
def receive_alert(alert: schemas.IncidentCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Instantly log the raw alert
    db_incident = models.IncidentReport(
        raw_text=alert.threat_text,  # 🐛 FIXED: Swapped 'alert.raw_text' to 'alert.threat_text' 
        status="PROCESSING",
        severity="PENDING",
        category="PENDING",
        summary="Awaiting AI Analysis"
    )
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)

    # 2. Hand off the heavy AI lifting...
    # This keeps our API blazing fast
    # 🐛 FIXED: Also swapped to 'alert.threat_text' here for the background task
    background_tasks.add_task(process_incident_with_ai, db_incident.id, alert.threat_text, db)

    return db_incident
    
