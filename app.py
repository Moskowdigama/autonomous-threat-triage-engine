import streamlit as st
import requests
import json

# --- CONFIGURATION ---
# The endpoint where your FastAPI engine listens for data
RENDER_ENGINE_URL = "https://ge-engine.onrender.com/triage"

# --- STREAMLIT PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AegisAgent AI: SOAR Platform",
    page_icon="🛡️",
    layout="centered"
)

# --- SESSION STATE INITIALIZATION ---
# Prevents the UI from flickering or losing data when buttons are clicked
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
        font-size: 3rem;
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

# --- TWO-COLUMN WORKSPACE CONTROL ---
col_terminal, col_analytics = st.columns([1, 1])

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
if st.button("🚀 Run AI Threat Triage", type="primary", use_container_width=True):
    if user_input:
        with st.spinner("Connecting to Render Engine & Gemini AI..."):
            try:
                # Structure the payload for FastAPI
                payload = {"log_data": user_input}
                
                # Send POST request to your backend engine
                response = requests.post(RENDER_ENGINE_URL, json=payload)
                
                if response.status_code == 200:
                    # Save the AI's JSON response into Streamlit memory
                    st.session_state.assessment_data = response.json()
                else:
                    st.error(f"⚠️ Engine responded with Error {response.status_code}: {response.text}")
            except requests.exceptions.RequestException as e:
                st.error(f"🛑 Connection to Render Engine failed. Is the backend awake? Error: {e}")
    else:
        st.warning("Please enter a telemetry stream to analyze.")

# --- DYNAMIC INFERENCE & ANALYSIS ENGINE (POWERED BY RENDER API) ---
if st.session_state.assessment_data:
    # Pull data from memory
    data = st.session_state.assessment_data
    
    # Safely extract variables from the JSON payload
    cvss_score = data.get("cvss_score", "N/A")
    pred_cat = data.get("category", "Anomaly Detected")
    pred_sub = data.get("subcategory", "General Triage Vector")
    blast_sub = data.get("blast_sub_agent", "⚠️ UNVERIFIED")
    blast_api = data.get("blast_api", "⚠️ UNVERIFIED")
    blast_billing = data.get("blast_billing", "⚠️ UNVERIFIED")
    framework = data.get("framework", "Pending Analysis")
    vulnerability = data.get("vulnerability", "Pending Analysis")
    action = data.get("action", "Manual review required.")
    mitigation = data.get("mitigation", "Isolate system parameters.")
    hardening = data.get("hardening", "Patch identified vulnerabilities.")

    # --- UI LAYOUT RENDERING ---
    st.markdown("### REAL-TIME TRIAGE ASSESSMENT PROFILE")
    
    # CVSS Metric Box
    st.markdown(f"""
        <div class="triage-card">
            <p style='color: #9ca3af; font-size: 0.8rem; letter-spacing: 0.1em; margin: 0;'>ASSESSED THREAT VELOCITY</p>
            <p class="cvss-score">CVSS {cvss_score}</p>
            <span style='background-color: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold;'>CRITICAL THREAT VECTOR</span>
        </div>
    """, unsafe_allow_html=True)
    
    # Target Class Metrics Box
    st.markdown(f"""
        <div class="triage-card">
            <p style='color: #9ca3af; font-size: 0.8rem; letter-spacing: 0.1em; margin: 0;'>CLASSIFIED CORE VECTOR</p>
            <p class="vector-title">{pred_cat}</p>
            <p style='color: #ffffff; margin: 0;'>Subcategory Focus: <b>{pred_sub}</b></p>
        </div>
    """, unsafe_allow_html=True)

    # Blast Radius Visualizer
    st.markdown("### ⚡ MULTI-AGENT CASCADING BLAST RADIUS VISUALIZER")
    st.markdown(f"""
        <div style='background-color: #111827; border: 1px solid #1f2937; padding: 15px; border-radius: 8px;'>
            <p style='color: #ef4444; font-family: monospace; margin: 5px 0;'>🚨 Sub-Agent Array ({blast_sub})</p>
            <p style='color: #f59e0b; font-family: monospace; margin: 5px 0;'>⚠️ API Rate Gate ({blast_api})</p>
            <p style='color: #10b981; font-family: monospace; margin: 5px 0;'>🛡️ Billing Ledger ({blast_billing})</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Compliance Mapping Card
    st.markdown("### 📋 REGULATORY MATRIX & COMPLIANCE MAPPING")
    st.markdown(f"""
        <div class="triage-card">
            <p style='margin: 0;'><b>Framework Alignment:</b> <span style='color: #ec4899;'>{framework}</span></p>
            <p style='margin: 10px 0 0 0;'><b>Identified Vulnerability:</b> {vulnerability}</p>
        </div>
    """, unsafe_allow_html=True)

    # Automated Orchestration Action Playbook Accordion
    with st.expander("🚨 Execute Automated Isolation Playbook", expanded=True):
        st.markdown(f"**⚠️ IMMEDIATE ACTION:** {action}")
        st.markdown(f"**🛠️ MITIGATION:** {mitigation}")
        st.markdown(f"**🔒 HARDENING:** {hardening}")

    # Reporting Infrastructure Download Control
    report_data = f"""==================================================
AEGISAGENT AI: AUTOMATED INCIDENT TRIAGE REPORT
==================================================
[SECURITY CLASSIFICATION]: CRITICAL THREAT VECTOR
[RISK LEVEL COEFFICIENT]: CVSS {cvss_score}
[CLASSIFIED CORE VECTOR]: {pred_cat}
[TARGET SUBCATEGORY]: {pred_sub}
[COMPLIANCE FRAMEWORK]: {framework}
[VULNERABILITY MATRICES]: {vulnerability}

[RAW SYSTEM TELEMETRY EVENT LOG]:
--------------------------------------------------
{user_input}
--------------------------------------------------

[AUTOMATED MITIGATION RUNTIME PLAYBOOK ACTIONS]:
- ⚠️ IMMEDIATE ACTION: {action}
- 🛠️ MITIGATION: {mitigation}
- 🔒 HARDENING: {hardening}
"""

    st.download_button(
        label="📥 Export Certified Incident Triage Report",
        data=report_data,
        file_name=f"Aegis_SOAR_Triage_Report_{pred_sub.replace(' ', '_')}.txt",
        mime="text/plain"
    )
else:
    st.info("Awaiting structural incoming data stream... Enter telemetry details above to begin orchestrating incident triage response matrices.")
  
