import streamlit as st
import requests

FASTAPI_URL = "https://e-1.onrender.com"  # Your Render backend URL

st.set_page_config(page_title="AI SOC Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Autonomous SOC Incident Response Engine")
st.caption("Real-Time Threat Telemetry Ingestion & Gemini AI Triage")

# Ingestion Panel
with st.form("dispatch_form"):
    telemetry_input = st.text_area(
        "Raw Security Log / Telemetry Payload",
        value="Optimization sub-agents entered an infinite recursive negotiation loop, causing severe compute resource exhaustion.",
        height=100
    )
    submit = st.form_submit_button("🚀 Dispatch Telemetry to Engine", use_container_width=True)

if submit:
    try:
        res = requests.post(f"{FASTAPI_URL}/triage", json={"threat_text": telemetry_input})
        if res.status_code == 200:
            data = res.json()
            st.session_state["active_incident_id"] = data["id"]
            st.toast(f"Incident #{data['id']} logged! Processing...", icon="⚡")
        else:
            st.error(f"Failed to submit alert. Server status: {res.status_code}")
    except Exception as e:
        st.error(f"Backend Connection Error: {e}")

# Auto-Polling Fragment (Isolated to avoid global rerun flickering)
@st.fragment(run_every=1.0)
def render_live_incident_profile():
    incident_id = st.session_state.get("active_incident_id")
    if not incident_id:
        st.info("👈 Submit telemetry above to launch autonomous triage.")
        return

    try:
        res = requests.get(f"{FASTAPI_URL}/alerts/{incident_id}")
        if res.status_code != 200:
            st.error("Failed to query backend state.")
            return

        data = res.json()
        status = data.get("status", "PENDING")

        st.markdown("---")
        st.subheader(f"REAL-TIME ASSESSMENT PROFILE — INCIDENT #{data['id']}")

        if status == "PENDING":
            with st.status("🔄 AI Triage Engine active...", expanded=True):
                st.write("📥 Telemetry ingested into pipeline...")
                st.write("🤖 Gemini 2.5 Flash analyzing vector & MITRE mappings...")
                st.spinner("Executing background task...")
        
        elif status == "TRIAGED":
            st.success("✅ Triage & Analysis Complete")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Severity Level", data.get("severity", "UNKNOWN"))
            with col2:
                st.metric("Classified Vector", data.get("category", "N/A"))
            with col3:
                st.metric("Pipeline Status", "DB_TRIAGED")

            st.markdown("### 🚨 Automated Orchestration Summary")
            st.info(data.get("summary", "No summary available."))

        elif status == "FAILED":
            st.error("❌ Incident analysis failed during AI background processing.")

    except Exception as e:
        st.error(f"Error refreshing dashboard: {e}")

if "active_incident_id" in st.session_state:
    render_live_incident_profile()
    
