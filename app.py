import streamlit as st
import pandas as pd
import numpy as np
import joblib

# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title="Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# CUSTOM CSS
# =========================

st.markdown("""
<style>

/* Main Background */
.stApp {
    background: #030712;
    color: white;
}

/* Headings */
h1 {
    color: white !important;
    font-weight: 800 !important;
}

h2,h3 {
    color: #00ffaa !important;
}

/* Labels */
label {
    color: white !important;
    font-size: 18px !important;
    font-weight: 600 !important;
}

/* Selectbox */
.stSelectbox div[data-baseweb="select"] > div {
    background-color: white !important;
    color: black !important;
    font-size: 20px !important;
    font-weight: 600 !important;
    border-radius: 10px !important;
}

/* Dropdown selected text */
.stSelectbox div[data-baseweb="select"] span {
    color: black !important;
}

/* Number Input */
.stNumberInput input {
    background-color: white !important;
    color: black !important;
    font-size: 20px !important;
    font-weight: 600 !important;
}

/* Number Input +/- buttons */
.stNumberInput button {
    color: black !important;
}

/* Button */
.stButton > button {
    background-color: white !important;
    color: black !important;
    font-size: 22px !important;
    font-weight: 700 !important;
    border-radius: 12px !important;
    padding: 12px 30px !important;
    border: none !important;
    transition: 0.3s;
}

/* Hover Effect */
.stButton > button:hover {
    background-color: #00ffaa !important;
    color: black !important;
}

/* Result Card */
.result-box {
    background-color: #111827;
    border: 2px solid #00ffaa;
    border-radius: 15px;
    padding: 25px;
    margin-top: 20px;
}

/* Metrics */
.metric-container {
    background-color: #111827;
    border: 1px solid #00ffaa;
    border-radius: 10px;
    padding: 15px;
}

/* Hide Streamlit Branding */
#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

header {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)

# =========================
# LOAD MODEL
# =========================

model = joblib.load("xgboost_ids_model.pkl")

le_proto = joblib.load("le_proto.pkl")
le_service = joblib.load("le_service.pkl")
le_state = joblib.load("le_state.pkl")
le_target = joblib.load("le_target.pkl")

# =========================
# ATTACK DESCRIPTIONS
# =========================

attack_info = {
    "Analysis": ("Low", "Traffic used for analysis and information gathering."),
    "Backdoor": ("High", "Unauthorized access mechanism installed in a system."),
    "DoS": ("Critical", "Denial of Service attack attempting to exhaust resources."),
    "Exploits": ("Critical", "Attempt to exploit vulnerabilities in a target."),
    "Fuzzers": ("Medium", "Sending random inputs to discover weaknesses."),
    "Generic": ("High", "General attack traffic detected."),
    "Normal": ("Safe", "Normal network behavior."),
    "Reconnaissance": ("Medium", "Information gathering before an attack."),
    "Shellcode": ("Critical", "Malicious code used to gain control."),
    "Worms": ("Critical", "Self-replicating malware spreading through networks.")
}

# =========================
# MEDIAN VALUES
# =========================

default_features = {
    'dur': 0.014138,
    'proto': 111,
    'service': 0,
    'state': 3,
    'spkts': 6,
    'dpkts': 2,
    'sbytes': 534,
    'dbytes': 178,
    'rate': 2650.176667,
    'sttl': 254,
    'dttl': 29,
    'sload': 577003.21875,
    'dload': 2112.951416,
    'sloss': 1,
    'dloss': 0,
    'sinpkt': 0.5579285,
    'dinpkt': 0.01,
    'sjit': 17.6239185,
    'djit': 0,
    'swin': 255,
    'stcpb': 27888855,
    'dtcpb': 28569748.5,
    'dwin': 255,
    'tcprtt': 0.000551,
    'synack': 0.000441,
    'ackdat': 0.00008,
    'smean': 65,
    'dmean': 44,
    'trans_depth': 0,
    'response_body_len': 0,
    'ct_srv_src': 5,
    'ct_state_ttl': 1,
    'ct_dst_ltm': 2,
    'ct_src_dport_ltm': 1,
    'ct_dst_sport_ltm': 1,
    'ct_dst_src_ltm': 3,
    'is_ftp_login': 0,
    'ct_ftp_cmd': 0,
    'ct_flw_http_mthd': 0,
    'ct_src_ltm': 3,
    'ct_srv_dst': 5,
    'is_sm_ips_ports': 0
}

# =========================
# UI
# =========================

st.title("🛡️ Explainable Intrusion Detection System")
st.markdown("Predict cyber attack categories using XGBoost")

col1, col2 = st.columns(2)

with col1:
    proto = st.selectbox(
        "Protocol",
        list(le_proto.classes_),
        index=list(le_proto.classes_).index("tcp")
    )

    service = st.selectbox(
        "Service",
        list(le_service.classes_),
        index=list(le_service.classes_).index("http")
    )

    state = st.selectbox(
        "State",
        list(le_state.classes_),
        index=list(le_state.classes_).index("CON")
    )

with col2:
    sbytes = st.number_input(
        "Source Bytes",
        min_value=0.0,
        value=534.0
    )

    dbytes = st.number_input(
        "Destination Bytes",
        min_value=0.0,
        value=178.0
    )

st.subheader("⚡ Most Important Network Features")

col3, col4 = st.columns(2)

with col3:
    sttl = st.number_input(
        "Source TTL (sttl)",
        min_value=0.0,
        value=254.0
    )

with col4:
    dttl = st.number_input(
        "Destination TTL (dttl)",
        min_value=0.0,
        value=29.0
    )

# =========================
# PREDICT
# =========================

if st.button("🔍 Predict & Analyze"):

    features = default_features.copy()

    features["proto"] = int(
        le_proto.transform([proto])[0]
    )

    features["service"] = int(
        le_service.transform([service])[0]
    )

    features["state"] = int(
        le_state.transform([state])[0]
    )

    features["sbytes"] = sbytes
    features["dbytes"] = dbytes
    features["sttl"] = sttl
    features["dttl"] = dttl

    feature_order = [
        'dur','proto','service','state','spkts','dpkts',
        'sbytes','dbytes','rate','sttl','dttl','sload',
        'dload','sloss','dloss','sinpkt','dinpkt',
        'sjit','djit','swin','stcpb','dtcpb','dwin',
        'tcprtt','synack','ackdat','smean','dmean',
        'trans_depth','response_body_len','ct_srv_src',
        'ct_state_ttl','ct_dst_ltm','ct_src_dport_ltm',
        'ct_dst_sport_ltm','ct_dst_src_ltm',
        'is_ftp_login','ct_ftp_cmd',
        'ct_flw_http_mthd','ct_src_ltm',
        'ct_srv_dst','is_sm_ips_ports'
    ]

    input_df = pd.DataFrame(
        [[features[col] for col in feature_order]],
        columns=feature_order
    )

    prediction = model.predict(input_df)[0]

    probabilities = model.predict_proba(input_df)[0]

    confidence = np.max(probabilities) * 100

    attack_name = le_target.inverse_transform(
        [prediction]
    )[0]

    risk, description = attack_info[attack_name]

    st.success("Prediction Complete")

    st.markdown(
        f"""
        <div class="result-box">
        <h2>Attack Type: {attack_name}</h2>
        <h3>Confidence: {confidence:.2f}%</h3>
        <h3>Risk Level: {risk}</h3>
        <p>{description}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Top Influential Features")

    st.write("1. dttl")
    st.write("2. sttl")
    st.write("3. sbytes")
    st.write("4. service")
    st.write("5. ct_srv_dst")