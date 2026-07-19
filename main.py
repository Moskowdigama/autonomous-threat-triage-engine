import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Import our custom secure data layers
import models
import schemas
from database import engine, Base, get_db

# 1. Automatically create database tables in Supabase if they don't exist yet
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SOAR Enterprise Threat Triage Engine")

# 2. Allow our future Frontend (Next.js) to securely talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # We will lock this down to our specific Vercel URL later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Simple health check endpoint to make sure the server is breathing
@app.get("/")
def health_check():
    return {"status": "online", "engine": "SOAR Triage Backend Active"}

# 4. The main Triage Endpoint
@app.post("/api/v1/triage", response_model=schemas.IncidentResponse)
def triage_threat(incident: schemas.IncidentCreate, db: Session = Depends(get_db)):
    raw_text = incident.threat_text.strip()
    
    if not raw_text:
        raise HTTPException(status_code=400, detail="Threat text cannot be empty")
        
    # --- INTERNAL TRIAGE LOGIC (Keyword Routing Guard) ---
    # Fixes the bug where "Agent" hijacked classification logic
    low_text = raw_text.lower()
    
    if "phishing" in low_text or "email" in low_text:
        subcategory = "Phishing Attempt"
        cvss_score = 4.2
        core_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
        framework_alignment = "MITRE ATT&CK T1566 (Phishing)"
        playbook_actions = "1. Isolate target mailbox. 2. Purge matching indicators from gateway. 3. Reset user session."
        
    elif "ransomware" in low_text or "encrypt" in low_text:
        subcategory = "Ransomware Deployment"
        cvss_score = 8.5
        core_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        framework_alignment = "MITRE ATT&CK T1486 (Data Encrypted for Impact)"
        playbook_actions = "1. Isolate host from network segment. 2. Revoke active Kerberos tickets. 3. Deploy EDR containment."
        
    else:
        # Default fallback triage if no strict keywords match
        subcategory = "General Anomaly / Unauthorized Activity"
        cvss_score = 5.0
        core_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        framework_alignment = "MITRE ATT&CK T1068 (Exploitation for Privilege Escalation)"
        playbook_actions = "1. Initiate continuous endpoint logging. 2. Route payload analysis to Tier-2 analyst queue."

    # 5. Commit the intelligence analysis directly to our cloud database
    db_report = models.IncidentReport(
        threat_text=raw_text,
        cvss_score=cvss_score,
        core_vector=core_vector,
        subcategory=subcategory,
        framework_alignment=framework_alignment,
        playbook_actions=playbook_actions
    )
    
    db.add(db_report)
    db.commit()
    db.refresh(db_report) # Pulls back the generated ID and timestamps from Supabase
    
    return db_report
      
