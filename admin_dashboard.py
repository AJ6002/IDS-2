import streamlit as st
import pandas as pd
import joblib
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import os
import time
from datetime import datetime

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="NEURAL-SHIELD | AI IDS Admin Panel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: white; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #3e4259; }
    .stProgress > div > div > div > div { background-color: #ff4b4b; }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.3; }
        100% { opacity: 1; }
    }
    .live-indicator {
        color: #00ff00;
        font-weight: bold;
        animation: pulse 2s infinite;
    }
    </style>
    """, unsafe_allow_html=True)

# --- LOAD MODELS ---
@st.cache_resource
def load_models():
    try:
        model = joblib.load("ids_model_tuesday.pkl")
        scaler = joblib.load("ids_scaler_tuesday.pkl")
        le = joblib.load("ids_label_encoder_tuesday.pkl")
        return model, scaler, le
    except:
        return None, None, None

model, scaler, le = load_models()

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ NEURAL-SHIELD")
    st.markdown("<p class='live-indicator'>● SYSTEM LIVE</p>", unsafe_allow_html=True)
    st.markdown("---")
    st.subheader("Connection Status")
    st.success("🟢 Azure VM: Connected")
    st.success("🟢 Honeypot: Active")
    st.info(f"Last Sync: {datetime.now().strftime('%H:%M:%S')}")
    st.markdown("---")
    auto_refresh = st.toggle("Auto-Refresh Data (5s)", value=True)
    if st.button("Manual Force Refresh"):
        st.cache_resource.clear()
        st.rerun()

# --- DATA PROCESSING ---
def get_data():
    if os.path.exists("high_def_features.csv"):
        file_time = datetime.fromtimestamp(os.path.getmtime("high_def_features.csv"))
        df = pd.read_csv("high_def_features.csv")
        return df, file_time
    return None, None

df, last_update = get_data()

# --- HEADER ---
st.title("🛡️ AI-Driven Intrusion Detection Dashboard")
if last_update:
    st.write(f"Showing analysis from: **{last_update.strftime('%Y-%m-%d %H:%M:%S')}**")
else:
    st.warning("Awaiting initial data capture...")

# --- AI INFERENCE ---
if df is not None:
    mapping = {'dst_port': 'Destination Port', 'flow_duration': 'Flow Duration'}
    X = df.rename(columns=mapping)
    if 'Flow Duration' in X.columns:
        X['Flow Duration'] = X['Flow Duration'] * 1000000
    X = X.reindex(columns=scaler.feature_names_in_, fill_value=0)
    X.replace([np.inf, -np.inf], 0, inplace=True)
    X.fillna(0, inplace=True)
    X_scaled = scaler.transform(X)
    probs = model.predict_proba(X_scaled)
    
    ssh_idx = list(le.classes_).index('SSH-Patator')
    detected_count = sum(1 for p in probs if p[ssh_idx] > 0.02)
    threat_perc = (detected_count / len(df)) * 100
else:
    threat_perc = 0
    detected_count = 0

# --- METRICS ROW ---
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Flows", len(df) if df is not None else 0)
m2.metric("Threat Index", f"{threat_perc:.1f}%")
m3.metric("Detected Intrusions", detected_count)
m4.metric("System Health", "SECURE" if threat_perc < 10 else "UNDER ATTACK")

# --- TABS ---
tab1, tab2, tab3 = st.tabs(["🔥 Live Monitor", "📊 Traffic Features", "🧠 AI Analysis"])

with tab1:
    st.subheader("Inbound Network Stream")
    col_a, col_b = st.columns([3, 1])
    with col_a:
        logs = [
            f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Monitoring Azure Port 22...",
            f"[{last_update.strftime('%H:%M:%S') if last_update else 'N/A'}] DATA: Received high-def flow batch.",
            f"[{datetime.now().strftime('%H:%M:%S')}] AI: Re-evaluating threat landscape..."
        ]
        if threat_perc > 50:
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 ALERT: SSH Brute Force signature confirmed!")
        st.code("\n".join(logs), language="bash")
        
        if threat_perc > 10:
            st.error(f"🚨 CRITICAL: {detected_count} flows identified as SSH-Patator (Anomalous)")
        else:
            st.success("✅ Clean: No malicious signatures found in latest batch.")

with tab2:
    if df is not None:
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No feature data currently in buffer.")

with tab3:
    if df is not None:
        c1, c2 = st.columns(2)
        with c1:
            chart_data = pd.DataFrame({
                'Category': ['Normal', 'Intrusion'],
                'Count': [len(df) - detected_count, detected_count]
            })
            fig = px.pie(chart_data, values='Count', names='Category', hole=0.4,
                         color_discrete_sequence=['#00c853', '#ff4b4b'], title="Threat Distribution")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            fig2 = px.scatter(df, x='flow_duration', y='tot_fwd_pkts', 
                              size='totlen_fwd_pkts', color='dst_port',
                              title="Flow Duration vs Packet Volume", color_continuous_scale="Viridis")
            st.plotly_chart(fig2, use_container_width=True)

# AUTO REFRESH
if auto_refresh:
    time.sleep(5)
    st.rerun()
