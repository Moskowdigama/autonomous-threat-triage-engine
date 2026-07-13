import streamlit as st
import numpy as np
import pandas as pd
import joblib

# 1. Establish widescreen layout boundaries and disable default sidebar padding
st.set_page_config(
    page_title="AegisAgent AI SOAR",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# 2. Inject CSS styling rules into a singular global stylesheet block
st.markdown("""
    <style>
        body { color: #ffffff; }
        .stTextArea textarea { 
            font-family: 'Courier New', Courier, monospace; 
            background-color: #0c0f14 !important; 
            color: #00ff66 !important; 
            border: 1px solid #30363d !important; 
        }
        .metric-box { 
            background-color: #0d1117; 
            border: 1px solid #30363d; 
            padding: 18px; 
            border-radius: 6px; 
            margin-bottom: 12px; 
        }
        .status-tag { 
            text-transform: uppercase; 
            font-size: 0.75rem; 
            letter-spacing: 2px; 
            color: #8b949e; 
            font-weight: bold; 
            margin-bottom: 6px; 
        }
        .blast-node { 
            padding: 10px; 
            border-radius: 4px; 
            text-align: center; 
            font-family: 'Courier New', Courier, monospace; 
            font-size: 0.85rem; 
            font-weight: bold; 
            margin: 6px 0; 
        }
        .node-red { background-color: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid #f85149; }
        .node-orange { background-color: rgba(219, 109, 40, 0.15); color: #db6d28; border: 1px solid #db6d28; }
        .node-green { background-color: rgba(35, 134, 54, 0.15); color: #238636; border: 1px solid #238636; }
        
        .badge { 
            padding: 4px 12px; 
            border-radius: 4px; 
            font-size: 0.85rem; 
            font-weight: bold; 
            display: inline-block; 
            margin-top: 5px;
        }
        .badge-red { background-color: #f85149; color: #ffffff; }
        .badge-orange { background-color: #db6d28; color: #ffffff; }
        .badge-green { background-color: #238636; color: #ffffff; }
    </style>
""", unsafe_allow_html=True)

# 3. Cache binary file loading to ensure instantaneous app re-runs
@st.cache_resource
def load_security_pipeline():
    tfidf_vectorizer = joblib.load('security_tfidf.pkl')
    cat_model = joblib.load('model_category.pkl')
    sub_model = joblib.load('model_subcategory.pkl')
    sev_model = joblib.load('model_severity.pkl')
    defaults_metadata = joblib.load('security_defaults.pkl')
    return tfidf_vectorizer, cat_model, sub_model, sev_model, defaults_metadata

try:
    tfidf, model_category, model_subcategory, model_severity, security_defaults = load_security_pipeline()
    soar_intel = security_defaults.get('soar_intel', {})
except Exception as e:
    st.error("🔒 Pipeline Execution Error: Unified intelligence files are missing or corrupted in the root directory.")
    st.stop()

# --- HEADER APP LOGO ---
st.title("🛡️ AegisAgent AI: SOAR Platform")
st.markdown("##### Next-Gen Autonomous Incident Response & Threat Orchestration Console")
st.markdown("---")

# --- TWO-COLUMN WORKSPACE CONTROL ---
col_terminal, col_analytics = st.columns([1.1, 0.9], gap="large")

with col_terminal:
    st.markdown("<p class='status-tag'>Incident Log Simulation Terminal</p>", unsafe_allow_html=True)
    
    # Preset testing fixtures map
    incident_fixtures = {
        "Manual Entry Sandbox": "",
        "Prompt Injection Core Sample": "Prompt Injection: User prompt contained hidden system instructions forcing execution agent to flush local environmental keys to external webhook.",
        "Model Context Protocol (MCP) Payload Sample": "Model Context Protocol (MCP) Breach: Malicious tool server returned corrupted payload causing buffer overflow execution on structural file parsers.",
        "Multi-Agent Cascade Loop Sample": "Multi-Agent Collision: Optimization sub-agents entered recursive request loop consuming cloud computing thresholds and creating complete service denial."
    }
    
    selected_fixture = st.selectbox("Select Threat Vector Presets", list(incident_fixtures.keys()))
    
    # Calculate textual state dynamically
    if selected_fixture == "Manual Entry Sandbox":
        fallback_value = "Type or paste raw autonomous agent telemetry text logs here..."
    else:
        fallback_value = incident_fixtures[selected_fixture]
        
    user_input = st.text_area("Live Telemetry Stream Log Input", value=fallback_value, height=180)

# --- THREAT ESTIMATION ENGINE ---
input_is_valid = user_input and user_input != "Type or paste raw autonomous agent telemetry text logs here..." and user_input.strip() != ""

if input_is_valid:
    # Feature transform via token matrix
    vectorized_stream = tfidf.transform([user_input])
    
    # Run multi-output inference pipelines
    pred_cat = str(model_category.predict(vectorized_stream)[0])
    pred_sub = str(model_subcategory.predict(vectorized_stream)[0])
    pred_sev = float(model_severity.predict(vectorized_stream)[0])
    
    # Normalize mapping keys to safely match our custom knowledge base dictionaries
    target_lookup_key = 'Prompt Injection'
    combined_prediction_string = (pred_cat + " " + pred_sub).upper()
    
    if 'MCP' in combined_prediction_string or 'PROTOCOL' in combined_prediction_string:
        target_lookup_key = 'MCP Security Incident'
    elif 'MULTI' in combined_prediction_string or 'COLLISION' in combined_prediction_string or 'AGENT' in combined_prediction_string:
        target_lookup_key = 'Multi-Agent Attack'
    elif 'CHAIN' in combined_prediction_string or 'SUPPLY' in combined_prediction_string:
        target_lookup_key = 'Supply Chain Risk'

    # Retrieve safe default templates if direct mapping misses
    compliance_record = soar_intel.get('compliance_mapping', {}).get(
        target_lookup_key, soar_intel.get('compliance_mapping', {}).get('Prompt Injection')
    )
    playbook_record = soar_intel.get('incident_playbooks', {}).get(
        target_lookup_key, soar_intel.get('incident_playbooks', {}).get('Prompt Injection')
    )

    # Calculate dynamic safety color styles
    if pred_sev >= 7.5:
        badge_class, risk_string = "badge-red", "CRITICAL THREAT VECTOR"
    elif pred_sev >= 4.0:
        badge_class, risk_string = "badge-orange", "HIGH RISK ANOMALY"
    else:
        badge_class, risk_string = "badge-green", "LOW OPERATIONAL CLEARANCE"

    # --- RIGHT PANEL METRICS RENDER ---
    with col_analytics:
        st.markdown("<p class='status-tag'>Real-Time Triage Assessment Profile</p>", unsafe_allow_html=True)
        
        st.markdown(f"""
            <div class="metric-box">
                <div class="status-tag">Assessed Threat Velocity</div>
                <div style="font-size: 2.2rem; font-weight: 800; color:#ff4b4b; line-height:1.1;">CVSS {pred_sev:.1f}</div>
                <span class="badge {badge_class}">{risk_string}</span>
            </div>
            
            <div class="metric-box">
                <div class="status-tag">Classified Core Vector</div>
                <div style="font-size: 1.2rem; font-weight: 700; color: #58a6ff;">{pred_cat}</div>
                <div style="color: #8b949e; font-size: 0.85rem; margin-top: 4px;">Subcategory Focus: <b>{pred_sub}</b></div>
            </div>
        """, unsafe_allow_html=True)

    # --- ADVANCED LOWER PANELS ARCHITECTURE ---
    st.markdown("---")
    col_radius, col_compliance = st.columns(2, gap="large")
    
    with col_radius:
        st.markdown("<p class='status-tag'>⚡ Multi-Agent Cascading Blast Radius Visualizer</p>", unsafe_allow_html=True)
        
        # Build self-contained HTML block to prevent Streamlit wrapper leaks
        nodes_html_buffer = "<div style='background-color:#0d1117; padding:12px; border:1px solid #30363d; border-radius:6px;'>"
        for node_entry in compliance_record['blast_nodes']:
            if "COMPROMISED" in node_entry.upper():
                nodes_html_buffer += f"<div class='blast-node node-red'>🚨 {node_entry}</div>"
            elif "SUSPECT" in node_entry.upper() or "LIMIT" in node_entry.upper():
                nodes_html_buffer += f"<div class='blast-node node-orange'>⚠️ {node_entry}</div>"
            else:
                nodes_html_buffer += f"<div class='blast-node node-green'>🛡️ {node_entry}</div>"
        nodes_html_buffer += "</div>"
        
        st.markdown(nodes_html_buffer, unsafe_allow_html=True)

    with col_compliance:
        st.markdown("<p class='status-tag'>📋 Regulatory Matrix & Compliance Mapping</p>", unsafe_allow_html=True)
        st.markdown(f"""
            <div class="metric-box" style="margin-bottom:14px;">
                <div style="font-size:0.9rem; margin-bottom:6px;"><b>Framework Alignment:</b> <code style="color:#ff79c6; background:none; padding:0;">{compliance_record['framework']}</code></div>
                <div style="font-size:0.9rem;"><b>Identified Vulnerability:</b> <span style="color:#e1e4e8;">{compliance_record['vulnerability']}</span></div>
            </div>
        """, unsafe_allow_html=True)
        
        with st.expander("🚨 Execute Automated Isolation Playbook", expanded=True):
            for step_instruction in playbook_record:
                st.markdown(f"**{step_instruction}**")
                
        # Structured Markdown data generator for reporting functionality
        compiled_report_string = f"""==================================================
AEGISAGENT AI: AUTOMATED INCIDENT TRIAGE REPORT
==================================================
[SECURITY CLASSIFICATION]: {risk_string}
[RISK LEVEL COEFFICIENT]: CVSS {pred_sev:.1f}
[CLASSIFIED CORE VECTOR]: {pred_cat}
[TARGET SUBCATEGORY]: {pred_sub}
[COMPLIANCE FRAMEWORK]: {compliance_record['framework']}
[VULNERABILITY MATRICES]: {compliance_record['vulnerability']}

[RAW SYSTEM TELEMETRY EVENT LOG]:
--------------------------------------------------
{user_input}
--------------------------------------------------

[AUTOMATED MITIGATION RUNTIME PLAYBOOK ACTIONS]:
""" + "\n".join([f"- {action_step}" for action_step in playbook_record])

        st.download_button(
            label="📥 Export Certified Incident Triage Report",
            data=compiled_report_string,
            file_name=f"Aegis_SOAR_Triage_Report_{pred_sub.replace(' ', '_')}.txt",
            mime="text/plain",
            use_container_width=True
        )
else:
    with col_analytics:
        st.info("💡 Feed raw infrastructure strings or system logs into the simulator terminal to initialize the threat response orchestration dashboard.")
  
