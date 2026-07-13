import streamlit as st

# --- STREAMLIT PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AegisAgent AI: SOAR Platform",
    page_icon="🛡️",
    layout="centered"
)

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
""", unsafe_html=True)

# --- APPLICATION HEADER ---
st.markdown("# 🛡️ AegisAgentAgent AI: SOAR Platform")
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

# Calculate textual state dynamically
if selected_fixture == "Manual Entry Sandbox":
    fallback_value = ""
else:
    fallback_value = incident_fixtures[selected_fixture]

user_input = st.text_area("Live Telemetry Stream Log Input", value=fallback_value, height=150)

# --- KNOWLEDGE BASE KERNEL MATRICES ---
knowledge_base = {
    "Prompt Injection": {
        "framework": "OWASP Top 10 LLM-01 / MITRE ATLAS AML-T0051",
        "vulnerability": "Indirect Prompt Injection / Privilege Escalation",
        "blast_sub_agent": "🔴 COMPROMISED",
        "blast_api": "⚠️ TIER LIMIT",
        "blast_billing": "🟢 SECURE",
        "action": "Force a system interrupt on running sub-agent workflow loops.",
        "mitigation": "Establish explicit max-depth limits for recursive tool routing.",
        "hardening": "Implement state verification steps before closing multi-agent consensus chains."
    },
    "MCP Security Incident": {
        "framework": "OWASP LLM02 / Dependency Pipeline Vulnerability",
        "vulnerability": "Untrusted Transport Layer Tool Execution / Arbitrary Code Execution",
        "blast_sub_agent": "🔴 COMPROMISED",
        "blast_api": "🔴 EXPLOITED",
        "blast_billing": "🟢 SECURE",
        "action": "Sever stdio connection handles to host custom tool servers.",
        "mitigation": "Validate outbound JSON-RPC schemas against structural schemas.",
        "hardening": "Enforce strict sandbox isolation containers for third-party host protocol bridges."
    },
    "Multi-Agent Attack": {
        "framework": "MITRE ATLAS AML.T0054 / Agentic Cascading Failure",
        "vulnerability": "Recursive Negotiation Loop / Resource Exhaustion",
        "blast_sub_agent": "🔴 COMPROMISED",
        "blast_api": "⚠️ TIER LIMIT",
        "blast_billing": "🟢 SECURE",
        "action": "Force a system interrupt on running sub-agent workflow loops.",
        "mitigation": "Establish explicit max-depth limits for recursive tool routing.",
        "hardening": "Implement state verification steps before closing multi-agent consensus chains."
    },
    "Supply Chain Risk": {
        "framework": "OWASP LLM08 / Dependency Pipeline Vulnerability",
        "vulnerability": "Poisoned Base Model Weights / Malicious Package Inversion",
        "blast_sub_agent": "⚠️ UNVERIFIED",
        "blast_api": "🟢 SECURE",
        "blast_billing": "🔴 SUSPENDED",
        "action": "Revoke standard execution tokens for active user session context.",
        "mitigation": "Route upstream raw texts through LLM-Guard or heuristic sanitizers.",
        "hardening": "Lock artifact dependency hashes and sign structural container images."
    }
}

# --- DYNAMIC INFERENCE & ANALYSIS ENGINE ---
if user_input:
    text_clean = user_input.upper()
    
    # 1. Intelligence Triage Mapping Logic
    if "INJECTION" in text_clean or "PROMPT" in text_clean:
        pred_cat = "AI Agent Core Threat"
        pred_sub = "Prompt Injection"
        cvss_score = 8.7
    elif "MCP" in text_clean or "PROTOCOL" in text_clean:
        pred_cat = "Model Context Protocol (MCP) Attack"
        pred_sub = "Tool Poisoning"
        cvss_score = 9.5
    elif "CHAIN" in text_clean or "DEPENDENCY" in text_clean or "REPOSITORY" in text_clean:
        pred_cat = "Adversarial Machine Learning"
        pred_sub = "Supply Chain Attack"
        cvss_score = 9.1
    elif "LOOP" in text_clean or "COLLISION" in text_clean or "RECURSIVE" in text_clean or "NEGOTIATION" in text_clean:
        pred_cat = "AI Agent Core Threat"
        pred_sub = "Denial of Service"
        cvss_score = 9.0
    else:
        pred_cat = "Anomaly Detected"
        pred_sub = "General Triage Vector"
        cvss_score = 5.0

    # 2. Prioritized Keyword Routing (Fixes the Cross-Wiring Bug)
    combined_prediction_string = (pred_cat + " " + pred_sub).upper()
    
    if 'INJECTION' in combined_prediction_string or 'PROMPT' in combined_prediction_string:
        target_lookup_key = 'Prompt Injection'
    elif 'MCP' in combined_prediction_string or 'PROTOCOL' in combined_prediction_string:
        target_lookup_key = 'MCP Security Incident'
    elif 'CHAIN' in combined_prediction_string or 'SUPPLY' in combined_prediction_string:
        target_lookup_key = 'Supply Chain Risk'
    elif 'MULTI' in combined_prediction_string or 'COLLISION' in combined_prediction_string:
        target_lookup_key = 'Multi-Agent Attack'
    elif 'AGENT' in combined_prediction_string:
        target_lookup_key = 'Multi-Agent Attack'
    else:
        target_lookup_key = 'Multi-Agent Attack'

    # Safe lookup extraction from internal knowledge base
    meta_record = knowledge_base.get(target_lookup_key, knowledge_base['Multi-Agent Attack'])

    # --- UI LAYOUT RENDERING ---
    st.markdown("### REAL-TIME TRIAGE ASSESSMENT PROFILE")
    
    # CVSS Metric Box
    st.markdown(f"""
        <div class="triage-card">
            <p style='color: #9ca3af; font-size: 0.8rem; letter-spacing: 0.1em; margin: 0;'>ASSESSED THREAT VELOCITY</p>
            <p class="cvss-score">CVSS {cvss_score}</p>
            <span style='background-color: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold;'>CRITICAL THREAT VECTOR</span>
        </div>
    """, unsafe_html=True)
    
    # Target Class Metrics Box
    st.markdown(f"""
        <div class="triage-card">
            <p style='color: #9ca3af; font-size: 0.8rem; letter-spacing: 0.1em; margin: 0;'>CLASSIFIED CORE VECTOR</p>
            <p class="vector-title">{pred_cat}</p>
            <p style='color: #ffffff; margin: 0;'>Subcategory Focus: <b>{pred_sub}</b></p>
        </div>
    """, unsafe_html=True)

    # Blast Radius Visualizer
    st.markdown("### ⚡ MULTI-AGENT CASCADING BLAST RADIUS VISUALIZER")
    st.markdown(f"""
        <div style='background-color: #111827; border: 1px solid #1f2937; padding: 15px; border-radius: 8px;'>
            <p style='color: #ef4444; font-family: monospace; margin: 5px 0;'>🚨 Sub-Agent Array ({meta_record['blast_sub_agent']})</p>
            <p style='color: #f59e0b; font-family: monospace; margin: 5px 0;'>⚠️ API Rate Gate ({meta_record['blast_api']})</p>
            <p style='color: #10b981; font-family: monospace; margin: 5px 0;'>🛡️ Billing Ledger ({meta_record['blast_billing']})</p>
        </div>
    """, unsafe_html=True)
    
    # Compliance Mapping Card
    st.markdown("### 📋 REGULATORY MATRIX & COMPLIANCE MAPPING")
    st.markdown(f"""
        <div class="triage-card">
            <p style='margin: 0;'><b>Framework Alignment:</b> <span style='color: #ec4899;'>{meta_record['framework']}</span></p>
            <p style='margin: 10px 0 0 0;'><b>Identified Vulnerability:</b> {meta_record['vulnerability']}</p>
        </div>
    """, unsafe_html=True)

    # Automated Orchestration Action Playbook Accordion
    with st.expander("🚨 Execute Automated Isolation Playbook", expanded=True):
        st.markdown(f"**⚠️ IMMEDIATE ACTION:** {meta_record['action']}")
        st.markdown(f"**🛠️ MITIGATION:** {meta_record['mitigation']}")
        st.markdown(f"**🔒 HARDENING:** {meta_record['hardening']}")

    # Reporting Infrastructure Download Control
    report_data = f"""==================================================
AEGISAGENT AI: AUTOMATED INCIDENT TRIAGE REPORT
==================================================
[SECURITY CLASSIFICATION]: CRITICAL THREAT VECTOR
[RISK LEVEL COEFFICIENT]: CVSS {cvss_score}
[CLASSIFIED CORE VECTOR]: {pred_cat}
[TARGET SUBCATEGORY]: {pred_sub}
[COMPLIANCE FRAMEWORK]: {meta_record['framework']}
[VULNERABILITY MATRICES]: {meta_record['vulnerability']}

[RAW SYSTEM TELEMETRY EVENT LOG]:
--------------------------------------------------
{user_input}
--------------------------------------------------

[AUTOMATED MITIGATION RUNTIME PLAYBOOK ACTIONS]:
- ⚠️ IMMEDIATE ACTION: {meta_record['action']}
- 🛠️ MITIGATION: {meta_record['mitigation']}
- 🔒 HARDENING: {meta_record['hardening']}
"""

    st.download_button(
        label="📥 Export Certified Incident Triage Report",
        data=report_data,
        file_name=f"Aegis_SOAR_Triage_Report_{pred_sub.replace(' ', '_')}.txt",
        mime="text/plain"
    )
else:
    st.info("Awaiting structural incoming data stream... Enter telemetry details above to begin orchestrating incident triage response matrices.")
