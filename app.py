import streamlit as st
import requests

# --- CONFIGURATION ---
# Points perfectly to your live backend engine alerts route
RENDER_ENGINE_URL = "https://autonomous-threat-triage-engine.onrender.com/alerts/"

# --- STREAMLIT PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AegisAgent AI: SOAR Platform",
    page_icon="🛡️",
    layout="centered"
)

# --- SESSION STATE INITIALIZATION ---
# Holds data across component refreshes
if "assessment_data" not in st.session_state:
    st.session_state.assessment_data = None

# --- CUSTOM CSS FOR HIGH-FIDELITY SOC DASHBOARD ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    h1, h2, h3 { color: #ffffff !important; font-family: 'Courier New', Courier, monospace; }
    .stTextArea textarea {
        background-color: #05080c !important;
        color: #00ff66 !important;
        font-family: 'Courier New', monospace !important;
        border: 1px solid #1e293b !important;
    }
    .triage-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 15px;
    }
    .cvss-score {
        color: #ef4444;
        font-size: 2.5rem;
        font-weight: bold;
        font-family: 'Courier New', monospace;
        margin: 0;
    }
    .vector-title {
        color: #3b82f6;
        font-size: 1.5rem;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# --- APPLICATION HEADER ---
st.markdown("# 🛡️ AegisAgent AI: SOAR Platform")
st.markdown("##### Next-Gen Autonomous Incident Response & Threat Orchestration Console")
st.markdown("---")

# Preset testing fixtures dictionary
incident_fixtures = {
    "Manual Entry Sandbox": "",
    "Prompt Injection Core Sample": "CRITICAL: User session payload contains an indirect prompt injection attempting to overwrite system instructions and bypass safety guardrails to extract internal environmental API keys.",
    "Model Context Protocol (MCP) Breach": "ALERT: Malicious MCP tool server returned an unmapped structural JSON payload during a schema validation check, causing an unhandled execution overflow error in the core agent system routing layer.",
    "Multi-Agent Cascade Loop Sample": "WARNING: Optimization sub-agents entered an infinite recursive negotiation loop during task allocation, leading to severe compute resource exhaustion and immediate agent thread denial of service.",
    "Supply Chain Risk": "SECURITY DETECTED: The pipeline pulled an unverified model dependency checkpoint from a compromised repository, indicating an active supply chain attack targeting our automated base image."
}

selected_fixture = st.selectbox("Select Threat Vector Presets", list(incident_fixtures.keys()))

if selected_fixture == "Manual Entry Sandbox":
    fallback_value = ""
else:
    fallback_value = incident_fixtures[selected_fixture]

user_input = st.text_area("Live Telemetry Stream Log Input", value=fallback_value, height=150)

# --- ACTION BUTTON TO TRIGGER ENGINE ---
if st.button("🚀 Dispatch Telemetry to Engine", type="primary", use_container_width=True):
    if user_input:
        with st.spinner("Streaming data to autonomous engine..."):
            try:
                # FIXED: Changed key from 'raw_text' to 'threat_text' to satisfy backend validation
                payload = {"threat_text": user_input}
                response = requests.post(RENDER_ENGINE_URL, json=payload)
                
                if response.status_code in [200, 201]:
                    st.session_state.assessment_data = response.json()
                    st.success("✅ Incident successfully logged in database!")
                else:
                    st.error(f"⚠️ Engine responded with Error {response.status_code}: {response.text}")
            except requests.exceptions.RequestException as e:
                st.error(f"🛑 Connection to Render Engine failed: {e}")
    else:
        st.warning("Please enter telemetry details before dispatching.")

# --- DYNAMIC INFERENCE & ANALYSIS DISPLAY ---
if st.session_state.assessment_data:
    data = st.session_state.assessment_data
    
    # Extract structural fields matching your FastAPI database models
    incident_id = data.get("id", "N/A")
    status = data.get("status", "PROCESSING")
    severity = data.get("severity", "PENDING")
    category = data.get("category", "PENDING")
    summary = data.get("summary", "Awaiting AI Analysis...")

    st.markdown("### REAL-TIME TRIAGE ASSESSMENT PROFILE")
    
    # Metric Display Box
    st.markdown(f"""
        <div class="triage-card">
            <p style='color: #9ca3af; font-size: 0.8rem; letter-spacing: 0.1em; margin: 0;'>INCIDENT ID: {incident_id} | STATUS: {status}</p>
            <p class="cvss-score">{severity}</p>
            <span style='background-color: #1e293b; color: #00ff66; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; font-family: monospace;'>DB PIPELINE RECEIPT</span>
        </div>
    """, unsafe_allow_html=True)
    
    # Vector Target Classification Box
    st.markdown(f"""
        <div class="triage-card">
            <p style='color: #9ca3af; font-size: 0.8rem; letter-spacing: 0.1em; margin: 0;'>CLASSIFIED CORE VECTOR</p>
            <p class="vector-title">{category}</p>
        </div>
    """, unsafe_allow_html=True)

    # Accordion Action Dropdown for Async Tracking
    with st.expander("🚨 Automated Orchestration Runbook Summary", expanded=True):
        st.markdown(f"**🤖 ENGINE ANALYSIS STATUS:** `{status}`")
        st.markdown("---")
        st.markdown(f"**Executive Summary:**\n{summary}")

    # Async Refresh Trigger
    st.markdown("---")
    if st.button("🔄 Check Latest Triage Status", use_container_width=True):
        if incident_id != "N/A":
            with st.spinner("Checking database for async updates..."):
                try:
                    # Tries to poll the individual item if GET /alerts/{id} is configured
                    get_url = f"{RENDER_ENGINE_URL}{incident_id}"
                    get_resp = requests.get(get_url)
                    if get_resp.status_code == 200:
                        st.session_state.assessment_data = get_resp.json()
                        st.rerun()
                    else:
                        st.info("ℹ cod1; Triage background job processing context. Check your main database logs for full async completions.")
                except Exception:
                    st.info("ℹ️ Triage background job processing context. Check your main database logs for full async completions.")

    # Data Report Exporter
    report_data = f"""==================================================
AEGISAGENT AI: AUTOMATED INCIDENT TRIAGE REPORT
==================================================
[INCIDENT ID]: {incident_id}
[STATUS]: {status}
[SEVERITY ASSESSMENT]: {severity}
[CLASSIFIED CORE VECTOR]: {category}

[RAW SYSTEM TELEMETRY EVENT LOG]:
--------------------------------------------------
{user_input}
--------------------------------------------------

[AI EXECUTIVE SUMMARY]:
{summary}
"""

    st.download_button(
        label="📥 Export Incident Triage Ticker",
        data=report_data,
        file_name=f"Aegis_SOAR_Alert_{incident_id}.txt",
        mime="text/plain"
    )
else:
    st.info("Awaiting structural incoming data stream... Enter telemetry details above to begin orchestrating incident triage response matrices.")
