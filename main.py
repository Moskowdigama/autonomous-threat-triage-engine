import os
import json
import time
import traceback
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import google.generativeai as genai

from database import engine, get_db, SessionLocal, Base
import models

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SOC Incident Response Engine")

# Setup Gemini Engine
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY environment variable is not set!")

genai.configure(api_key=GEMINI_API_KEY)


class AlertSchema(BaseModel):
    threat_text: str


def run_ai_triage_pipeline(incident_id: int):
    db = SessionLocal()
    try:
        incident = (
            db.query(models.IncidentReport)
            .filter(models.IncidentReport.id == incident_id)
            .first()
        )
        if not incident:
            return

        model = genai.GenerativeModel("gemini-1.5-flash")
        

        prompt = f"""
        You are an Enterprise SOC Analyst. Analyze this raw threat telemetry and output strictly valid JSON with no markdown syntax wrapping:
        {{
          "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
          "category": "Vector classification (e.g. Agent Malfunction, Privilege Escalation, Exfiltration)",
          "mitre_technique": "MITRE ATT&CK ID (e.g. T1078, T1499)",
          "summary": "2-sentence executive summary explaining business impact and immediate threat."
        }}

        Telemetry Payload:
        {incident.threat_text}
        """

        # --- Safe AI Request with 429 Retry Loop ---
        max_retries = 3
        response = None

        for attempt in range(max_retries):
            try:
                response = model.generate_content(prompt)
                break  # Success! Exit retry loop
            except Exception as e:
                if "429" in str(e) and attempt < max_retries - 1:
                    print(
                        f"Rate limit hit (429). Retrying in 10s... (Attempt {attempt + 1}/{max_retries})",
                        flush=True,
                    )
                    time.sleep(10)
                else:
                    raise e

        if not response or not response.text:
            raise RuntimeError("Empty response received from Gemini API.")

        # Clean response text if markdown code fences exist
        clean_json = response.text.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean_json)

        # Update DB Record
        incident.severity = data.get("severity", "HIGH")
        incident.category = data.get("category", "Unknown Vector")
        incident.summary = f"[{data.get('mitre_technique', 'T1000')}] {data.get('summary', 'Analysis complete.')}"
        incident.status = "COMPLETED"
        incident.ai_analysis = response.text
        db.commit()

    except Exception as e:
        print(f"Pipeline Execution Error: {e}", flush=True)
        traceback.print_exc()
        if "incident" in locals() and incident:
            incident.status = "FAILED"
            db.commit()
    finally:
        db.close()  # Always close background DB session


# --- Endpoints ---
@app.get("/")
def root():
    return {"status": "online", "system": "Autonomous Threat Triage Engine"}


@app.post("/alerts/dispatch")
def dispatch_alert(
    payload: AlertSchema,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    new_alert = models.IncidentReport(
        threat_text=payload.threat_text,
        status="PENDING",
        severity="PENDING",
        category="PENDING",
    )
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)

    background_tasks.add_task(run_ai_triage_pipeline, new_alert.id)
    return {"id": new_alert.id, "status": "PENDING"}


@app.get("/alerts/{incident_id}")
def get_alert(incident_id: int, db: Session = Depends(get_db)):
    alert = (
        db.query(models.IncidentReport)
        .filter(models.IncidentReport.id == incident_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Incident record not found")
    return alert
      
